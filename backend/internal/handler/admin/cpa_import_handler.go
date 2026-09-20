package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/Wei-Shaw/sub2api/internal/pkg/cpapolicy"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

type cpaBridgeProvisioner interface {
	ListCPABridgeCandidates(context.Context) ([]service.CPABridgeCandidate, error)
	PrepareCPABridgeProvisioning(context.Context, string) (*service.CPABridgeProvisioning, error)
}

var cpaBridgeCreateMu sync.Mutex

// Keep existing business accounts intact; fail instead of choosing arbitrarily.
func (h *OpenAIOAuthHandler) currentCPABridge(ctx context.Context) (*service.Account, error) {
	accounts, err := h.adminService.ListAccountsForSchedulerScoreFilter(ctx, service.PlatformOpenAI, service.AccountTypeAPIKey, "", "", 0, "")
	if err != nil {
		return nil, err
	}
	var found *service.Account
	for i := range accounts {
		a := &accounts[i]
		if a.IsOpenAICompatibleQuotaBridge() && cpapolicy.ValidateBaseURL(a.GetCredential("base_url")) == nil {
			if found != nil {
				return nil, infraerrors.New(http.StatusConflict, "CPA_BRIDGE_AMBIGUOUS", "存在多个桥接，请先在账号管理中核对")
			}
			found = a
		}
	}
	return found, nil
}
func (h *OpenAIOAuthHandler) CPABridgeOptions(c *gin.Context) {
	if h.cpaBridgeService == nil || h.adminService == nil {
		response.Error(c, 503, "CPA bridge is unavailable")
		return
	}
	candidates, err := h.cpaBridgeService.ListCPABridgeCandidates(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	bridge, err := h.currentCPABridge(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	groups, err := h.adminService.GetAllGroupsByPlatform(c.Request.Context(), service.PlatformOpenAI)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	safeGroups := make([]gin.H, 0)
	for _, g := range groups {
		if g.Status == service.StatusActive {
			safeGroups = append(safeGroups, gin.H{"id": g.ID, "name": g.Name})
		}
	}
	var current any
	if bridge != nil {
		current = gin.H{"account_id": bridge.ID, "auth_name": bridge.GetExtraString(service.OpenAIQuotaBridgeAuthNameExtraKey), "email": bridge.GetExtraString(service.OpenAIQuotaBridgeAuthEmailExtraKey), "group_ids": bridge.GroupIDs}
	}
	response.Success(c, gin.H{"candidates": candidates, "bridge": current, "groups": safeGroups})
}

// Explicitly select the quota identity and live business groups. No old accounts
// or groups are restored; inference continues through the existing CPA pool.
func (h *OpenAIOAuthHandler) EnsureCPAQuotaBridge(c *gin.Context) {
	if h.cpaBridgeService == nil || h.adminService == nil {
		response.Error(c, 503, "CPA bridge is unavailable")
		return
	}
	var req struct {
		AuthName string  `json:"auth_name"`
		GroupIDs []int64 `json:"group_ids"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.AuthName) == "" || len(req.GroupIDs) == 0 || len(req.GroupIDs) > 100 {
		response.BadRequest(c, "请选择 CPA 账号和至少一个业务分组")
		return
	}
	cpaBridgeCreateMu.Lock()
	defer cpaBridgeCreateMu.Unlock()
	ctx := c.Request.Context()
	seen := map[int64]bool{}
	ids := make([]int64, 0, len(req.GroupIDs))
	for _, id := range req.GroupIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		g, err := h.adminService.GetGroup(ctx, id)
		if err != nil {
			response.ErrorFrom(c, err)
			return
		}
		if g.Platform != service.PlatformOpenAI || g.Status != service.StatusActive {
			response.BadRequest(c, "只能绑定启用的 OpenAI 分组")
			return
		}
		ids = append(ids, id)
	}
	bridge, err := h.currentCPABridge(ctx)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	provision, err := h.cpaBridgeService.PrepareCPABridgeProvisioning(ctx, req.AuthName)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	extra := map[string]any{service.OpenAIQuotaViaCompatibleUpstreamExtraKey: true, service.OpenAIQuotaBridgeAuthNameExtraKey: provision.AuthName, service.OpenAIQuotaBridgeAuthEmailExtraKey: provision.Email}
	created := bridge == nil
	if created {
		bridge, err = h.adminService.CreateAccount(ctx, &service.CreateAccountInput{Name: "CPA Bridge", Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey, Credentials: map[string]any{"api_key": provision.APIKey, "base_url": cpapolicy.BaseURL}, Extra: extra, Concurrency: 50, Priority: 1, GroupIDs: ids, SkipDefaultGroupBind: true})
	} else {
		merged := make(map[string]any, len(bridge.Extra)+3)
		for k, v := range bridge.Extra {
			merged[k] = v
		}
		for k, v := range extra {
			merged[k] = v
		}
		bridge, err = h.adminService.UpdateAccount(ctx, bridge.ID, &service.UpdateAccountInput{Extra: merged, GroupIDs: &ids})
	}
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"created": created, "account_id": bridge.ID, "auth_name": provision.AuthName, "email": provision.Email, "groups_configured": true})
}

// DirectAccountBackendRemoved is used by obsolete creation/sync/shadow routes.
// It is an explicit error rather than silently accepting ignored configuration.
func DirectAccountBackendRemoved(c *gin.Context) { response.ErrorFrom(c, cpapolicy.Required()) }

// ImportCPAAccounts is also the destination for legacy Codex/data imports.
// It never invokes Sub2 CreateAccount/UpdateAccount, including on partial errors.
func (h *OpenAIOAuthHandler) ImportCPAAccounts(c *gin.Context) {
	if h.cpaImportService == nil {
		response.Error(c, http.StatusServiceUnavailable, "CPA import is unavailable")
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 4<<20)
	var req struct {
		Runtime     *service.CPACredentialUpdate `json:"runtime,omitempty"`
		Content     string                       `json:"content"`
		Contents    []string                     `json:"contents"`
		Credentials map[string]any               `json:"credentials"`
		Data        json.RawMessage              `json:"data"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid CPA import payload")
		return
	}
	if req.Credentials != nil {
		encoded, _ := json.Marshal(req.Credentials)
		req.Contents = append(req.Contents, string(encoded))
	}
	if len(req.Data) > 0 {
		var data struct {
			Accounts []json.RawMessage `json:"accounts"`
		}
		if err := json.Unmarshal(req.Data, &data); err != nil {
			response.BadRequest(c, "Invalid account data")
			return
		}
		for _, account := range data.Accounts {
			req.Contents = append(req.Contents, string(account))
		}
	}
	entries, err := parseCodexSessionImportEntries(CodexSessionImportRequest{Content: req.Content, Contents: req.Contents})
	if err != nil {
		response.BadRequest(c, "授权文件 JSON 格式无效")
		return
	}
	if len(entries) == 0 || len(entries) > 100 {
		response.BadRequest(c, "每次请导入 1–100 个 CPA 账号")
		return
	}
	result := CodexSessionImportResult{Total: len(entries), Items: make([]CodexSessionImportItem, 0, len(entries))}
	for _, entry := range entries {
		if raw, ok := entry.Value.(map[string]any); ok {
			if creds, ok := raw["credentials"].(map[string]any); ok {
				entry.Value = creds
			}
		}
		var message string
		var accountID int64
		var name string
		if raw, ok := entry.Value.(map[string]any); ok && isProviderCPAFile(raw) {
			var imported *service.OpenAICPAImportResult
			var importErr error
			if req.Runtime != nil && h.cpaRuntimeService != nil {
				imported, importErr = h.cpaRuntimeService.ImportCPAAuthFileWithRuntime(c.Request.Context(), raw, req.Runtime)
			} else if req.Runtime != nil {
				importErr = cpapolicy.Required()
			} else {
				imported, importErr = h.cpaImportService.ImportCPAAuthFile(c.Request.Context(), raw)
			}
			if importErr != nil {
				message = infraerrors.Message(importErr)
			} else {
				name, accountID = imported.Email, imported.BridgeAccountID
			}
		} else {
			// CPA Codex files use expired; auth.json uses tokens + JWT claims.
			if raw, ok := entry.Value.(map[string]any); ok && raw["expires_at"] == nil && raw["expired"] != nil {
				raw["expires_at"] = raw["expired"]
			}
			item, normalizeErr := normalizeCodexImportEntry(entry)
			if normalizeErr != nil {
				message = "OpenAI 授权文件无效或已过期"
			} else {
				var imported *service.OpenAICPAImportResult
				var importErr error
				if req.Runtime != nil && h.cpaRuntimeService != nil {
					imported, importErr = h.cpaRuntimeService.ImportOAuthCredentialsToCPAWithRuntime(c.Request.Context(), item.Credentials, req.Runtime)
				} else if req.Runtime != nil {
					importErr = cpapolicy.Required()
				} else {
					imported, importErr = h.cpaImportService.ImportOAuthCredentialsToCPA(c.Request.Context(), item.Credentials)
				}
				if importErr != nil {
					message = infraerrors.Message(importErr)
				} else {
					name, accountID = imported.Email, imported.BridgeAccountID
				}
			}
		}
		if message != "" {
			result.Failed++
			result.Items = append(result.Items, CodexSessionImportItem{Index: entry.Index, Action: "failed", Message: message})
			result.Errors = append(result.Errors, CodexSessionImportMessage{Index: entry.Index, Message: message})
		} else {
			result.Created++
			result.Items = append(result.Items, CodexSessionImportItem{Index: entry.Index, Name: name, Action: "imported_cpa", AccountID: accountID})
		}
	}
	response.Success(c, result)
}

func isProviderCPAFile(raw map[string]any) bool {
	typeName, _ := raw["type"].(string)
	switch strings.ToLower(typeName) {
	case "claude", "gemini", "antigravity":
		return true
	default:
		return false
	}
}
