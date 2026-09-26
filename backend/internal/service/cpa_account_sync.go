package service

import (
	"context"
	"net/http"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/cpapolicy"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

// CPAAccountSyncResult reports business accounts reconciled with exact CPA auth
// files. An unchanged existing account still counts as updated: the import UI
// uses that count to confirm that its auth file has a business account.
type CPAAccountSyncResult struct {
	Created    int `json:"created"`
	Updated    int `json:"updated"`
	Identities int `json:"identities"`
	AccountIDs []int64 `json:"account_ids"`
}

type cpaAccountSyncCandidate struct {
	credential CPACredentialSettings
	existing   *Account
}

// SyncCPAAccounts reconciles the requested auth files without changing an
// existing business account's status, schedulability, or group membership. A
// newly imported account is deliberately disabled, unschedulable and ungrouped
// until an administrator explicitly configures it.
func (s *OpenAIQuotaService) SyncCPAAccounts(ctx context.Context, authNames []string) (*CPAAccountSyncResult, error) {
	if s == nil || s.accountRepo == nil {
		return nil, infraerrors.New(http.StatusServiceUnavailable, "CPA_ACCOUNT_SYNC_UNAVAILABLE", "CPA account synchronization is unavailable")
	}
	if len(authNames) == 0 || len(authNames) > 100 {
		return nil, infraerrors.BadRequest("CPA_ACCOUNT_SYNC_NAMES_INVALID", "请选择 1 至 100 份 CPA 授权文件")
	}
	requested := make([]string, 0, len(authNames))
	seenNames := make(map[string]bool, len(authNames))
	for _, raw := range authNames {
		name := strings.TrimSpace(raw)
		if name == "" || strings.ContainsAny(name, "/\\") {
			return nil, infraerrors.BadRequest("CPA_ACCOUNT_SYNC_NAMES_INVALID", "CPA 授权文件名无效")
		}
		if !seenNames[name] {
			requested = append(requested, name)
			seenNames[name] = true
		}
	}

	cpaRuntimeMu.Lock()
	defer cpaRuntimeMu.Unlock()

	cfg, err := cpaRuntimeConfig()
	if err != nil {
		return nil, err
	}
	files, err := cpaAuthList(ctx, cfg)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]openAIQuotaBridgeAuthFile, len(files))
	for _, file := range files {
		if seenNames[file.Name] {
			if _, duplicate := byName[file.Name]; duplicate {
				return nil, infraerrors.New(http.StatusConflict, "CPA_ACCOUNT_SYNC_AUTH_AMBIGUOUS", "CPA 返回重复的授权文件名")
			}
			byName[file.Name] = file
		}
	}

	candidates := make([]cpaAccountSyncCandidate, 0, len(requested))
	seenIdentities := make(map[string]string, len(requested))
	for _, name := range requested {
		file, exists := byName[name]
		if !exists {
			return nil, infraerrors.NotFound("CPA_ACCOUNT_SYNC_AUTH_NOT_FOUND", "CPA 授权文件不存在")
		}
		provider := strings.TrimSpace(file.Provider)
		if provider == "" {
			provider = strings.TrimSpace(file.Type)
		}
		if !strings.EqualFold(provider, "codex") || strings.TrimSpace(file.ID) == "" {
			return nil, infraerrors.BadRequest("CPA_ACCOUNT_SYNC_AUTH_UNSUPPORTED", "只能同步具有稳定授权 ID 的 CPA Codex 账号")
		}
		file.Provider = "codex"
		metadata, err := cpaAuthMetadata(ctx, cfg, name)
		if err != nil {
			return nil, err
		}
		credential := cpaSettings(file, metadata)
		if previous, duplicate := seenIdentities[credential.Identity]; duplicate && previous != name {
			return nil, infraerrors.New(http.StatusConflict, "CPA_ACCOUNT_SYNC_IDENTITY_AMBIGUOUS", "多份 CPA 授权文件指向同一身份，请只选择其中一份")
		}
		seenIdentities[credential.Identity] = name
		candidates = append(candidates, cpaAccountSyncCandidate{credential: credential})
	}

	// Resolve every binding before writing. Exact auth ID wins over the
	// identity hash, while disagreement between those lookups is a conflict;
	// it must never attach a second business account to another identity.
	plannedAccounts := make(map[int64]string, len(candidates))
	needCreate := false
	for i := range candidates {
		credential := candidates[i].credential
		byAuthID, err := s.accountRepo.FindByExtraField(ctx, "cpa_auth_id", credential.AuthID)
		if err != nil {
			return nil, err
		}
		byIdentity, err := s.accountRepo.FindByExtraField(ctx, "cpa_identity", credential.Identity)
		if err != nil {
			return nil, err
		}
		byAuthName, err := s.accountRepo.FindByExtraField(ctx, OpenAIQuotaBridgeAuthNameExtraKey, credential.Name)
		if err != nil {
			return nil, err
		}
		if len(byAuthID) > 1 || len(byIdentity) > 1 || (len(byAuthID) == 1 && len(byIdentity) == 1 && byAuthID[0].ID != byIdentity[0].ID) {
			return nil, infraerrors.New(http.StatusConflict, "CPA_ACCOUNT_SYNC_IDENTITY_CONFLICT", "CPA 授权 ID 和业务身份绑定存在冲突，请先核对账号")
		}
		if len(byAuthName) > 1 {
			return nil, infraerrors.New(http.StatusConflict, "CPA_ACCOUNT_SYNC_AUTH_NAME_CONFLICT", "多条业务账号指向同一 CPA 授权文件，请先核对旧桥接和重复账号")
		}
		var account *Account
		if len(byAuthID) == 1 {
			account = &byAuthID[0]
		} else if len(byIdentity) == 1 {
			account = &byIdentity[0]
		}
		if len(byAuthName) == 1 && (account == nil || byAuthName[0].ID != account.ID) {
			// A legacy shared bridge may only carry the file name. Never
			// silently convert it into an identity-bound business account or
			// create another live route for the same authorization.
			return nil, infraerrors.New(http.StatusConflict, "CPA_ACCOUNT_SYNC_AUTH_NAME_CONFLICT", "CPA 授权文件已被另一条业务账号引用，请先核对旧桥接和重复账号")
		}
		if account == nil {
			needCreate = true
			continue
		}
		if account.Platform != PlatformOpenAI || account.Type != AccountTypeAPIKey || ValidateCPAAccount(account) != nil || account.GetOpenAIApiKey() == "" {
			return nil, infraerrors.New(http.StatusConflict, "CPA_ACCOUNT_SYNC_ACCOUNT_INVALID", "已有身份绑定的业务账号不是有效 CPA OpenAI 账号")
		}
		if previous, duplicate := plannedAccounts[account.ID]; duplicate && previous != credential.Name {
			return nil, infraerrors.New(http.StatusConflict, "CPA_ACCOUNT_SYNC_ACCOUNT_AMBIGUOUS", "多份授权文件指向同一个业务账号")
		}
		plannedAccounts[account.ID] = credential.Name
		candidates[i].existing = account
	}

	apiKey := ""
	if needCreate {
		var keys openAIQuotaBridgeAPIKeysResponse
		if err := callOpenAIQuotaBridgeManagement(ctx, cfg, http.MethodGet, "/v0/management/api-keys", nil, &keys); err != nil {
			return nil, err
		}
		for _, key := range keys.Keys {
			if apiKey = strings.TrimSpace(key); apiKey != "" {
				break
			}
		}
		if apiKey == "" {
			return nil, infraerrors.New(http.StatusServiceUnavailable, "CPA_ACCOUNT_SYNC_API_KEY_MISSING", "CPA 没有可用于业务账号的 API Key")
		}
	}

	result := &CPAAccountSyncResult{Identities: len(candidates), AccountIDs: make([]int64, 0, len(candidates))}
	for _, candidate := range candidates {
		credential := candidate.credential
		binding := map[string]any{
			"cpa_auth_id":                            credential.AuthID,
			"cpa_identity":                           credential.Identity,
			OpenAIQuotaBridgeAuthNameExtraKey:        credential.Name,
			OpenAIQuotaBridgeAuthEmailExtraKey:       credential.Email,
			OpenAIQuotaViaCompatibleUpstreamExtraKey: true,
		}
		if candidate.existing != nil {
			updates := make(map[string]any, len(binding))
			for key, value := range binding {
				if candidate.existing.Extra[key] != value {
					updates[key] = value
				}
			}
			if len(updates) > 0 {
				if err := s.accountRepo.UpdateExtra(ctx, candidate.existing.ID, updates); err != nil {
					return nil, err
				}
			}
			result.Updated++
			result.AccountIDs = append(result.AccountIDs, candidate.existing.ID)
			continue
		}
		name := strings.TrimSpace(credential.Email)
		if name == "" {
			name = credential.Name
		}
		account := &Account{
			Name: name, Platform: PlatformOpenAI, Type: AccountTypeAPIKey,
			Credentials: map[string]any{"base_url": cpapolicy.BaseURL, "api_key": apiKey},
			Extra:       binding, Concurrency: 1, Status: StatusDisabled,
			Schedulable: false, AutoPauseOnExpired: true,
		}
		if err := s.accountRepo.Create(ctx, account); err != nil {
			return nil, err
		}
		result.Created++
		result.AccountIDs = append(result.AccountIDs, account.ID)
	}
	return result, nil
}
