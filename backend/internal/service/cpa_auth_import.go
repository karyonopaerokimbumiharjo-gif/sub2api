package service

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

// ImportCPAAuthFile accepts provider-native CPA OAuth files. No Sub2 account,
// provider route, proxy, or billing setting is imported from these files.
func (s *OpenAIQuotaService) ImportCPAAuthFile(ctx context.Context, raw map[string]any) (*OpenAICPAImportResult, error) {
	return s.ImportCPAAuthFileWithRuntime(ctx, raw, nil)
}
func (s *OpenAIQuotaService) ImportCPAAuthFileWithRuntime(ctx context.Context, raw map[string]any, runtime *CPACredentialUpdate) (*OpenAICPAImportResult, error) {
	provider := strings.ToLower(openAICPACredentialString(raw, "type"))
	if provider != "claude" && provider != "gemini" && provider != "antigravity" {
		return nil, infraerrors.BadRequest("CPA_AUTH_FORMAT_UNSUPPORTED", "此授权文件不受支持；请提供 OpenAI/Codex 或 CPA 原生 Claude、Gemini、Antigravity OAuth 文件")
	}
	email := openAICPACredentialString(raw, "email")
	refresh := openAICPACredentialString(raw, "refresh_token")
	if token, ok := raw["token"].(map[string]any); ok && refresh == "" {
		refresh = openAICPACredentialString(token, "refresh_token")
	}
	if email == "" || refresh == "" {
		return nil, infraerrors.BadRequest("CPA_AUTH_INCOMPLETE", "CPA 授权文件必须包含邮箱和可续期的 OAuth 凭证")
	}
	if expiry := openAICPACredentialString(raw, "expired"); expiry != "" {
		expiresAt, err := time.Parse(time.RFC3339, expiry)
		if err != nil || !expiresAt.After(time.Now().Add(30*time.Second)) {
			return nil, infraerrors.BadRequest("CPA_AUTH_EXPIRED", "CPA 授权文件已过期，请重新授权后导入")
		}
	}
	cpaRuntimeMu.Lock()
	defer cpaRuntimeMu.Unlock()
	config, err := loadOpenAIQuotaBridgeConfig()
	if err != nil {
		return nil, err
	}
	bridge, err := s.findOpenAIQuotaBridge(ctx, config.managementURL)
	if err != nil {
		return nil, err
	}
	accountID := openAICPACredentialString(raw, "account_id")
	digest := sha256.Sum256([]byte(provider + "\x00" + strings.ToLower(email) + "\x00" + accountID))
	name := fmt.Sprintf("%s-sub2-oauth-%x.json", provider, digest[:8])
	payload := map[string]any{"type": provider, "email": email, "disabled": false, "source": "sub2api"}
	for _, key := range []string{"access_token", "refresh_token", "id_token", "expired", "expiry", "token", "project_id", "account_id", "last_refresh", "client_id"} {
		if value, ok := raw[key]; ok {
			payload[key] = value
		}
	}
	if err := preserveCPAImportRuntime(ctx, config, name, payload); err != nil {
		return nil, err
	}
	if runtime != nil {
		input := *runtime
		input.Name = name
		fields, err := s.cpaRuntimeFields(ctx, input)
		if err != nil {
			return nil, err
		}
		for key, value := range fields {
			if key != "name" {
				payload[key] = value
			}
		}
		payload["disabled"] = input.Disabled
	}
	var upload openAICPAUploadResponse
	endpoint := "/v0/management/auth-files?name=" + url.QueryEscape(name)
	if err := callOpenAIQuotaBridgeManagement(ctx, config, http.MethodPost, endpoint, payload, &upload); err != nil {
		return nil, err
	}
	if upload.Status != "ok" {
		return nil, infraerrors.New(http.StatusBadGateway, "CPA_IMPORT_FAILED", "CPA 未确认导入成功")
	}
	var files openAIQuotaBridgeAuthFilesResponse
	if err := callOpenAIQuotaBridgeManagement(ctx, config, http.MethodGet, endpoint, nil, &files); err != nil {
		return nil, err
	}
	auth, err := matchingCPAAuth(files.Files, name)
	if err != nil {
		return nil, err
	}
	expectedDisabled, _ := payload["disabled"].(bool)
	if auth.Disabled != expectedDisabled || (!expectedDisabled && (auth.Unavailable || auth.Status != "active")) || !strings.EqualFold(auth.Email, email) {
		return nil, infraerrors.New(http.StatusBadGateway, "CPA_IMPORT_VERIFY_FAILED", "CPA 文件已上传，但账号未通过可用性校验，请重新授权后重试")
	}
	if runtime != nil {
		if err := verifyCPAImportedRuntime(ctx, config, name, payload); err != nil {
			return nil, err
		}
	}
	var bridgeID int64
	if bridge != nil {
		bridgeID = bridge.ID
	}
	return &OpenAICPAImportResult{AuthName: name, Email: email, BridgeAccountID: bridgeID}, nil
}
