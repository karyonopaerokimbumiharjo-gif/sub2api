package service

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

// CPA auth files belong to individual business accounts only when an explicit
// identity binding exists. A shared CPA bridge must never toggle or delete an
// arbitrary member of its credential pool when its Sub2 account is edited.
func cpaAccountAuthBinding(account *Account) (authID, identity string) {
	if account == nil || account.Platform != PlatformOpenAI || account.Type != AccountTypeAPIKey {
		return "", ""
	}
	return strings.TrimSpace(account.GetExtraString("cpa_auth_id")), strings.TrimSpace(account.GetExtraString("cpa_identity"))
}

func findBoundCPAAccountAuth(ctx context.Context, cfg openAIQuotaBridgeConfig, authID, identity string) (*openAIQuotaBridgeAuthFile, error) {
	files, err := cpaAuthList(ctx, cfg)
	if err != nil {
		return nil, err
	}
	var match *openAIQuotaBridgeAuthFile
	for i := range files {
		auth := &files[i]
		if authID != "" && auth.ID != authID {
			continue
		}
		if identity != "" {
			metadata, err := cpaAuthMetadata(ctx, cfg, auth.Name)
			if err != nil {
				return nil, err
			}
			if cpaSettings(*auth, metadata).Identity != identity {
				continue
			}
		}
		if match != nil {
			return nil, infraerrors.New(http.StatusConflict, "CPA_AUTH_AMBIGUOUS", "多个 CPA 授权文件匹配同一业务账号，请先核对绑定")
		}
		match = auth
	}
	return match, nil
}

func setCPAAccountEnabled(ctx context.Context, account *Account, enabled bool) error {
	authID, identity := cpaAccountAuthBinding(account)
	if authID == "" && identity == "" {
		return nil
	}
	cpaRuntimeMu.Lock()
	defer cpaRuntimeMu.Unlock()
	cfg, err := cpaRuntimeConfig()
	if err != nil {
		return err
	}
	auth, err := findBoundCPAAccountAuth(ctx, cfg, authID, identity)
	if err != nil {
		return err
	}
	if auth == nil {
		return infraerrors.NotFound("CPA_AUTH_NOT_FOUND", "业务账号绑定的 CPA 授权文件不存在")
	}
	if auth.Disabled == !enabled {
		return nil
	}
	var response map[string]any
	if err := callOpenAIQuotaBridgeManagement(ctx, cfg, http.MethodPatch, "/v0/management/auth-files/status", map[string]any{
		"name": auth.Name, "auth_index": auth.AuthIndex, "disabled": !enabled,
	}, &response); err != nil {
		return err
	}
	current, err := findBoundCPAAccountAuth(ctx, cfg, authID, identity)
	if err != nil {
		return err
	}
	if current == nil || current.Disabled != !enabled {
		return infraerrors.New(http.StatusBadGateway, "CPA_AUTH_STATUS_VERIFY_FAILED", "CPA 授权状态更新未通过回读校验")
	}
	return nil
}

type cpaAccountReferenceLookup interface {
	FindByExtraField(ctx context.Context, key string, value any) ([]Account, error)
}

func deleteCPAAccountAuthorizations(ctx context.Context, account *Account, accounts cpaAccountReferenceLookup) error {
	authID, identity := cpaAccountAuthBinding(account)
	if authID == "" && identity == "" {
		return nil
	}
	if accounts == nil {
		return infraerrors.New(http.StatusServiceUnavailable, "CPA_ACCOUNT_LOOKUP_UNAVAILABLE", "无法核对 CPA 授权引用")
	}
	cpaRuntimeMu.Lock()
	defer cpaRuntimeMu.Unlock()
	cfg, err := cpaRuntimeConfig()
	if err != nil {
		return err
	}
	auth, err := findBoundCPAAccountAuth(ctx, cfg, authID, identity)
	if err != nil {
		return err
	}
	if auth == nil {
		return nil // Already removed from CPA; account deletion remains idempotent.
	}
	for _, binding := range []struct{ key, value string }{
		{"cpa_auth_id", auth.ID},
		{"cpa_identity", identity},
		{OpenAIQuotaBridgeAuthNameExtraKey, auth.Name},
	} {
		if binding.value == "" {
			continue
		}
		references, err := accounts.FindByExtraField(ctx, binding.key, binding.value)
		if err != nil {
			return err
		}
		for _, other := range references {
			if other.ID != account.ID {
				return infraerrors.New(http.StatusConflict, "CPA_AUTH_SHARED", "CPA 授权文件仍被其他业务账号使用，已保留授权文件")
			}
		}
	}
	var response map[string]any
	if err := callOpenAIQuotaBridgeManagement(ctx, cfg, http.MethodDelete, "/v0/management/auth-files?name="+url.QueryEscape(auth.Name), nil, &response); err != nil {
		return err
	}
	current, err := findBoundCPAAccountAuth(ctx, cfg, authID, identity)
	if err != nil {
		return err
	}
	if current != nil {
		return infraerrors.New(http.StatusBadGateway, "CPA_AUTH_DELETE_VERIFY_FAILED", "CPA 授权文件删除未通过回读校验")
	}
	return nil
}
