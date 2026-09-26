package service

import (
	"context"
	"net/http"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

// Reauthorization updates the existing Pi owner, never a second account or a
// shared alias's rotating credentials. CPA transport settings stay in CPA.
func (s *OpenAIQuotaService) preparePiReimport(ctx context.Context, account *Account, metadata map[string]any) (*Account, map[string]any, error) {
	if err := ValidateExecutionAccount(account); err != nil {
		return nil, nil, err
	}
	runtime, err := ResolveNativePiRuntimeAccount(ctx, s.accountRepo, account)
	if err != nil {
		return nil, nil, err
	}
	if err := ValidateExecutionAccount(runtime); err != nil {
		return nil, nil, err
	}
	source := shallowCopyMap(metadata)
	for _, field := range []string{"token", "tokens"} {
		if token, ok := metadata[field].(map[string]any); ok {
			for key, value := range token {
				if source[key] == nil || source[key] == "" {
					source[key] = value
				}
			}
		}
	}
	identity := strings.TrimSpace(openAICPACredentialString(source, "account_id"))
	if identity == "" {
		identity = strings.TrimSpace(openAICPACredentialString(source, "chatgpt_account_id"))
	}
	if identity == "" || identity != runtime.GetCredential("chatgpt_account_id") || identity != account.GetCredential("chatgpt_account_id") {
		return nil, nil, infraerrors.New(http.StatusConflict, "PI_REIMPORT_IDENTITY_CONFLICT", "授权身份与已有账号不一致，请核对后重新授权")
	}
	expiry := source["expires_at"]
	if expiry == nil || expiry == "" {
		expiry = source["expired"]
	}
	if expiry == nil || expiry == "" {
		expiry = source["expiry"]
	}
	expiresAt, err := normalizeOpenAICPAExpiration(expiry)
	if err != nil {
		return nil, nil, infraerrors.BadRequest("PI_REIMPORT_AUTH_INCOMPLETE", "授权缺少有效期，请重新授权后导入")
	}
	expires, _ := time.Parse(time.RFC3339, expiresAt)
	if !expires.After(time.Now().Add(30 * time.Second)) {
		return nil, nil, infraerrors.BadRequest("PI_REIMPORT_AUTH_EXPIRED", "授权已过期，请重新授权后导入")
	}
	patch := map[string]any{"expires_at": expiresAt, "chatgpt_account_id": identity}
	for _, key := range []string{"access_token", "refresh_token", "id_token", "email", "chatgpt_user_id", "organization_id", "plan_type", "client_id"} {
		if value := strings.TrimSpace(openAICPACredentialString(source, key)); value != "" {
			patch[key] = value
		}
	}
	if patch["access_token"] == nil || patch["refresh_token"] == nil {
		return nil, nil, infraerrors.BadRequest("PI_REIMPORT_AUTH_INCOMPLETE", "授权缺少有效凭证，请重新授权后导入")
	}
	return runtime, patch, nil
}

func (s *OpenAIQuotaService) persistPiReimport(ctx context.Context, runtime *Account, oauth map[string]any) error {
	cacheKey := OpenAITokenCacheKey(runtime)
	if s.tokenProvider != nil && s.tokenProvider.tokenCache != nil {
		cache := s.tokenProvider.tokenCache
		locked, err := cache.AcquireRefreshLock(ctx, cacheKey, 30*time.Second)
		if err != nil || !locked {
			return infraerrors.New(http.StatusConflict, "PI_REIMPORT_REFRESH_BUSY", "账号正在更新授权，请稍后重试导入")
		}
		defer func() { _ = cache.ReleaseRefreshLock(context.WithoutCancel(ctx), cacheKey) }()
	}
	current, err := s.accountRepo.GetByID(ctx, runtime.ID)
	if err != nil {
		return err
	}
	if current == nil || !current.UsesNativePiRuntime() || current.GetCredential("harness_kind") != PiNativeHarnessKind || current.GetCredential("chatgpt_account_id") != runtime.GetCredential("chatgpt_account_id") || current.GetCredential("pi_owner_user_id") != runtime.GetCredential("pi_owner_user_id") {
		return infraerrors.New(http.StatusConflict, "PI_REIMPORT_ACCOUNT_CHANGED", "账号状态已改变，请刷新后重试导入")
	}
	credentials := shallowCopyMap(current.Credentials)
	for key, value := range oauth {
		credentials[key] = value
	}
	if err := persistAccountCredentials(ctx, s.accountRepo, current, credentials); err != nil {
		return err
	}
	if s.tokenProvider != nil && s.tokenProvider.tokenCache != nil {
		if err := s.tokenProvider.tokenCache.DeleteAccessToken(ctx, cacheKey); err != nil {
			return infraerrors.New(http.StatusServiceUnavailable, "PI_REIMPORT_CACHE_UPDATE_FAILED", "授权缓存更新未完成，请重试导入")
		}
	}
	return nil
}
