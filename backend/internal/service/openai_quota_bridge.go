package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/cpapolicy"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

const (
	openAIQuotaBridgeManagementURLKey           = "OPENAI_QUOTA_BRIDGE_MANAGEMENT_URL"
	openAIQuotaBridgeManagementPasswordFileKey  = "OPENAI_QUOTA_BRIDGE_MANAGEMENT_PASSWORD_FILE"
	openAIQuotaBridgeMaxManagementResponseBytes = 2 << 20
)

var openAIQuotaBridgeHTTPClient = func() *http.Client {
	transport := &http.Transport{ForceAttemptHTTP2: true}
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = base.Clone()
	}
	// CPA is reached through the private Docker network. Never let an ambient
	// HTTP_PROXY receive the management credential.
	transport.Proxy = nil
	return &http.Client{
		Transport:     transport,
		Timeout:       openaiQuotaUpstreamTimeout,
		CheckRedirect: cpapolicy.NoRedirect,
	}
}()

type openAIQuotaBridgeConfig struct {
	managementURL string
	secret        string
}

type openAIQuotaBridgeAuthFilesResponse struct {
	Files []openAIQuotaBridgeAuthFile `json:"files"`
}

type openAIQuotaBridgeAPIKeysResponse struct {
	Keys []string `json:"api-keys"`
}

// CPABridgeProvisioning contains only non-secret binding metadata and the
// API key needed internally to create the local bridge account.
type CPABridgeProvisioning struct {
	AuthName string
	Email    string
	APIKey   string `json:"-"`
}

type openAIQuotaBridgeAuthFile struct {
	ID          string `json:"id"`
	AuthIndex   string `json:"auth_index"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Provider    string `json:"provider"`
	Email       string `json:"email"`
	Status      string `json:"status"`
	Disabled    bool   `json:"disabled"`
	Unavailable bool   `json:"unavailable"`
	IDToken     struct {
		ChatGPTAccountID string `json:"chatgpt_account_id"`
	} `json:"id_token"`
}

type openAIQuotaBridgeIdentity struct {
	authIndex        string
	chatGPTAccountID string
}

type openAIQuotaBridgeAPICallRequest struct {
	AuthIndex string            `json:"auth_index"`
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Header    map[string]string `json:"header,omitempty"`
	Data      string            `json:"data,omitempty"`
}

type openAIQuotaBridgeAPICallResponse struct {
	StatusCode int                 `json:"status_code"`
	Header     map[string][]string `json:"header"`
	Body       string              `json:"body"`
}

// OpenAICPAImportResult is the non-secret result returned after an OpenAI OAuth
// credential has been persisted in the private CPA auth store. Tokens are never
// echoed back to the handler or browser.
type OpenAICPAImportResult struct {
	AuthName          string `json:"auth_name"`
	Email             string `json:"email"`
	BridgeAccountID   int64  `json:"bridge_account_id"`
	ReplacedBoundAuth bool   `json:"replaced_bound_auth"`
}

type openAICPAUploadResponse struct {
	Status string `json:"status"`
}

// CPA versions may ignore the name query and return the whole pool. Always
// select the exact file locally, including quota reads after a second import.
func matchingCPAAuth(files []openAIQuotaBridgeAuthFile, name string) (openAIQuotaBridgeAuthFile, error) {
	var match openAIQuotaBridgeAuthFile
	count := 0
	for _, file := range files {
		if file.Name == name || file.ID == name {
			match, count = file, count+1
		}
	}
	if count != 1 {
		return match, infraerrors.New(http.StatusBadGateway, "OPENAI_CPA_AUTH_NOT_UNIQUE", "CPA did not return exactly one matching auth file")
	}
	return match, nil
}

// ImportOAuthCredentialsToCPA adds a validated OpenAI OAuth credential to the
// configured CPA pool, including before a business bridge has been created.
// It never creates/restores a schedulable Sub2 account or changes billing.
func (s *OpenAIQuotaService) ImportOAuthCredentialsToCPA(ctx context.Context, credentials map[string]any) (*OpenAICPAImportResult, error) {
	return s.ImportOAuthCredentialsToCPAWithRuntime(ctx, credentials, nil)
}

func (s *OpenAIQuotaService) ImportOAuthCredentialsToCPAWithRuntime(ctx context.Context, credentials map[string]any, runtime *CPACredentialUpdate) (*OpenAICPAImportResult, error) {
	cpaRuntimeMu.Lock()
	defer cpaRuntimeMu.Unlock()
	if s == nil || s.accountRepo == nil {
		return nil, infraerrors.New(http.StatusServiceUnavailable, "OPENAI_CPA_IMPORT_UNAVAILABLE", "CPA import service is unavailable")
	}

	config, err := loadOpenAIQuotaBridgeConfig()
	if err != nil {
		return nil, err
	}
	bridge, err := s.findOpenAIQuotaBridge(ctx, config.managementURL)
	if err != nil {
		return nil, err
	}

	accessToken := openAICPACredentialString(credentials, "access_token")
	refreshToken := openAICPACredentialString(credentials, "refresh_token")
	idToken := openAICPACredentialString(credentials, "id_token")
	email := strings.TrimSpace(openAICPACredentialString(credentials, "email"))
	accountID := strings.TrimSpace(openAICPACredentialString(credentials, "chatgpt_account_id"))
	if accessToken == "" || refreshToken == "" || idToken == "" || email == "" || accountID == "" {
		return nil, infraerrors.New(http.StatusBadRequest, "OPENAI_CPA_IMPORT_INCOMPLETE", "OpenAI OAuth credentials are incomplete")
	}
	expired, err := normalizeOpenAICPAExpiration(credentials["expires_at"])
	if err != nil {
		return nil, infraerrors.Newf(http.StatusBadRequest, "OPENAI_CPA_IMPORT_INVALID_EXPIRY", "OpenAI OAuth expiration is invalid: %v", err)
	}
	expiresAt, _ := time.Parse(time.RFC3339, expired)
	if !expiresAt.After(time.Now().Add(30 * time.Second)) {
		return nil, infraerrors.BadRequest("OPENAI_CPA_IMPORT_EXPIRED", "OAuth 授权已过期或即将过期，请重新授权后导入")
	}
	// Validate the incoming credential through CPA before replacing a live file.
	// A syntactically valid JWT may still be revoked; a failed preflight must
	// leave the currently working pool untouched.
	preflight, err := callOpenAIQuotaBridge(ctx, config, openAIQuotaBridgeIdentity{}, http.MethodGet, chatGPTUsageURL, buildCodexCommonHeaders(accessToken, accountID, false), "")
	if err != nil {
		return nil, err
	}
	if preflight.StatusCode != http.StatusOK {
		return nil, infraerrors.New(http.StatusBadRequest, "OPENAI_CPA_IMPORT_CREDENTIAL_REJECTED", "CPA 未能验证此 OAuth 授权；现有账号池未修改，请重新授权后重试")
	}

	var boundName, boundEmail string
	var bridgeID int64
	if bridge != nil {
		bridgeID = bridge.ID
		boundName = strings.TrimSpace(bridge.GetExtraString(OpenAIQuotaBridgeAuthNameExtraKey))
		boundEmail = strings.TrimSpace(bridge.GetExtraString(OpenAIQuotaBridgeAuthEmailExtraKey))
	}
	authName := openAICPAAuthFileName(email, accountID)
	replacedBoundAuth := boundName != "" && strings.EqualFold(email, boundEmail)
	if replacedBoundAuth {
		var current openAIQuotaBridgeAuthFilesResponse
		if err := callOpenAIQuotaBridgeManagement(ctx, config, http.MethodGet, "/v0/management/auth-files?name="+url.QueryEscape(boundName), nil, &current); err != nil {
			return nil, err
		}
		bound, err := matchingCPAAuth(current.Files, boundName)
		if err != nil {
			return nil, err
		}
		// One email may have multiple workspaces. Never overwrite another
		// workspace's live credential merely because its email matches.
		replacedBoundAuth = strings.TrimSpace(bound.IDToken.ChatGPTAccountID) == accountID
		if replacedBoundAuth {
			authName = boundName
		}
	}

	payload := map[string]any{
		"type":          "codex",
		"auth_kind":     "oauth",
		"source":        "sub2api",
		"email":         email,
		"account_id":    accountID,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"id_token":      idToken,
		"expired":       expired,
		"last_refresh":  time.Now().UTC().Format(time.RFC3339),
		"disabled":      false,
		"weight":        1,
	}
	if planType := openAICPACredentialString(credentials, "plan_type"); planType != "" {
		payload["plan_type"] = planType
	}
	if err := preserveCPAImportRuntime(ctx, config, authName, payload); err != nil {
		return nil, err
	}

	if runtime != nil {
		input := *runtime
		input.Name = authName
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
	endpoint := "/v0/management/auth-files?name=" + url.QueryEscape(authName)
	if err := callOpenAIQuotaBridgeManagement(ctx, config, http.MethodPost, endpoint, payload, &upload); err != nil {
		return nil, err
	}
	if !strings.EqualFold(strings.TrimSpace(upload.Status), "ok") {
		return nil, infraerrors.New(http.StatusBadGateway, "OPENAI_CPA_IMPORT_FAILED", "CPA did not confirm the OAuth import")
	}

	var authFiles openAIQuotaBridgeAuthFilesResponse
	if err := callOpenAIQuotaBridgeManagement(ctx, config, http.MethodGet, "/v0/management/auth-files?name="+url.QueryEscape(authName), nil, &authFiles); err != nil {
		return nil, err
	}
	imported, err := matchingCPAAuth(authFiles.Files, authName)
	if err != nil {
		return nil, err
	}
	expectedDisabled, _ := payload["disabled"].(bool)
	if imported.Disabled != expectedDisabled || (!expectedDisabled && (imported.Unavailable || !strings.EqualFold(imported.Status, "active"))) || !strings.EqualFold(strings.TrimSpace(imported.Email), email) ||
		strings.TrimSpace(imported.IDToken.ChatGPTAccountID) != accountID {
		return nil, infraerrors.New(http.StatusBadGateway, "OPENAI_CPA_IMPORT_VERIFY_FAILED", "CPA imported OAuth identity did not pass verification")
	}

	if runtime != nil {
		if err := verifyCPAImportedRuntime(ctx, config, authName, payload); err != nil {
			return nil, err
		}
	}
	return &OpenAICPAImportResult{
		AuthName:          authName,
		Email:             email,
		BridgeAccountID:   bridgeID,
		ReplacedBoundAuth: replacedBoundAuth,
	}, nil
}

// CPABridgeCandidate is safe for admin UI display. No credential material is returned.
type CPABridgeCandidate struct {
	Name      string `json:"name"`
	Email     string `json:"email"`
	Provider  string `json:"provider"`
	Status    string `json:"status"`
	CanBridge bool   `json:"can_bridge"`
	Reason    string `json:"reason"`
}

func cpaBridgeCandidate(file openAIQuotaBridgeAuthFile) CPABridgeCandidate {
	provider := strings.TrimSpace(file.Provider)
	if provider == "" {
		provider = strings.TrimSpace(file.Type)
	}
	c := CPABridgeCandidate{Name: file.Name, Email: file.Email, Provider: provider, Status: file.Status}
	switch {
	case !strings.EqualFold(provider, "codex"):
		c.Reason = "目前仅支持 Codex 授权桥接"
	case file.Disabled:
		c.Reason = "已停用，请先在 CPA 凭证设置中启用"
	case file.Unavailable || !strings.EqualFold(strings.TrimSpace(file.Status), "active"):
		c.Reason = "授权或网络异常，请先检查 CPA 凭证"
	case strings.TrimSpace(file.Name) == "" || strings.TrimSpace(file.Email) == "" || strings.TrimSpace(file.AuthIndex) == "" || strings.TrimSpace(file.IDToken.ChatGPTAccountID) == "":
		c.Reason = "授权身份信息不完整，请重新导入"
	default:
		c.CanBridge = true
	}
	return c
}

func (s *OpenAIQuotaService) ListCPABridgeCandidates(ctx context.Context) ([]CPABridgeCandidate, error) {
	config, err := loadOpenAIQuotaBridgeConfig()
	if err != nil {
		return nil, err
	}
	files, err := cpaAuthList(ctx, config)
	if err != nil {
		return nil, err
	}
	result := make([]CPABridgeCandidate, 0, len(files))
	for _, file := range files {
		result = append(result, cpaBridgeCandidate(file))
	}
	return result, nil
}

// Provision only the explicitly selected auth, never a different pool member.
func (s *OpenAIQuotaService) PrepareCPABridgeProvisioning(ctx context.Context, authName string) (*CPABridgeProvisioning, error) {
	if strings.TrimSpace(authName) == "" {
		return nil, infraerrors.BadRequest("CPA_AUTH_REQUIRED", "请先选择要桥接的 CPA 账号")
	}
	config, err := loadOpenAIQuotaBridgeConfig()
	if err != nil {
		return nil, err
	}
	files, err := cpaAuthList(ctx, config)
	if err != nil {
		return nil, err
	}
	file, err := matchingCPAAuth(files, authName)
	if err != nil {
		return nil, err
	}
	candidate := cpaBridgeCandidate(file)
	if !candidate.CanBridge {
		return nil, infraerrors.New(http.StatusConflict, "CPA_AUTH_NOT_READY", candidate.Reason)
	}
	var keys openAIQuotaBridgeAPIKeysResponse
	if err := callOpenAIQuotaBridgeManagement(ctx, config, http.MethodGet, "/v0/management/api-keys", nil, &keys); err != nil {
		return nil, err
	}
	for _, key := range keys.Keys {
		if key = strings.TrimSpace(key); key != "" {
			return &CPABridgeProvisioning{AuthName: file.Name, Email: file.Email, APIKey: key}, nil
		}
	}
	return nil, infraerrors.New(http.StatusServiceUnavailable, "OPENAI_CPA_BRIDGE_API_KEY_MISSING", "CPA API Key 未配置")
}

func (s *OpenAIQuotaService) findOpenAIQuotaBridge(ctx context.Context, managementURL string) (*Account, error) {
	// The business bridge is optional for pool imports. Return nil when none
	// exists; never restore deleted accounts. Still reject ambiguous bindings
	// and repository/config errors rather than replacing an arbitrary auth file.
	// Import is a management operation: a failed or paused bridge must still be
	// discoverable for reauthorization. ListByPlatform only returns active
	// accounts. Keep runtime scheduling checks in the business and audit paths.
	accounts, err := s.accountRepo.ListAllWithFilters(ctx, PlatformOpenAI, AccountTypeAPIKey, "", "", 0, "")
	if err != nil {
		return nil, infraerrors.Newf(http.StatusInternalServerError, "OPENAI_CPA_BRIDGE_LOOKUP_FAILED", "failed to load CPA bridge account: %v", err)
	}
	managementOrigin, err := openAIQuotaBridgeOrigin(managementURL)
	if err != nil {
		return nil, infraerrors.New(http.StatusInternalServerError, "OPENAI_CPA_BRIDGE_NOT_CONFIGURED", "CPA management endpoint is invalid")
	}
	var bridge *Account
	for i := range accounts {
		candidate := &accounts[i]
		if !candidate.IsOpenAICompatibleQuotaBridge() {
			continue
		}
		origin, originErr := openAIQuotaBridgeOrigin(candidate.GetCredential("base_url"))
		if originErr != nil || !strings.EqualFold(origin, managementOrigin) {
			continue
		}
		if bridge != nil {
			return nil, infraerrors.New(http.StatusConflict, "OPENAI_CPA_BRIDGE_AMBIGUOUS", "more than one CPA bridge account matches the configured management endpoint")
		}
		bridge = candidate
	}
	return bridge, nil
}

func openAICPACredentialString(credentials map[string]any, key string) string {
	if credentials == nil {
		return ""
	}
	value, _ := credentials[key].(string)
	return strings.TrimSpace(value)
}

func normalizeOpenAICPAExpiration(raw any) (string, error) {
	switch value := raw.(type) {
	case string:
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
		if err != nil {
			return "", err
		}
		return parsed.UTC().Format(time.RFC3339), nil
	case float64:
		seconds := int64(value)
		if seconds > 10_000_000_000 {
			seconds /= 1000
		}
		if seconds <= 0 {
			return "", fmt.Errorf("must be positive")
		}
		return time.Unix(seconds, 0).UTC().Format(time.RFC3339), nil
	case int64:
		seconds := value
		if seconds > 10_000_000_000 {
			seconds /= 1000
		}
		if seconds <= 0 {
			return "", fmt.Errorf("must be positive")
		}
		return time.Unix(seconds, 0).UTC().Format(time.RFC3339), nil
	case int:
		return normalizeOpenAICPAExpiration(int64(value))
	case json.Number:
		seconds, err := value.Int64()
		if err != nil {
			return "", err
		}
		return normalizeOpenAICPAExpiration(seconds)
	default:
		return "", fmt.Errorf("missing expiration")
	}
}

func openAICPAAuthFileName(email, accountID string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email)) + "\x00" + strings.TrimSpace(accountID)))
	return fmt.Sprintf("codex-sub2-oauth-%x.json", sum[:8])
}

func (s *OpenAIQuotaService) queryUsageViaOpenAIQuotaBridge(ctx context.Context, account *Account) (*OpenAIQuotaUsage, error) {
	config, identity, err := s.prepareOpenAIQuotaBridge(ctx, account)
	if err != nil {
		return nil, err
	}

	callCtx, cancel := context.WithTimeout(ctx, openaiQuotaUpstreamTimeout)
	defer cancel()

	response, err := callOpenAIQuotaBridge(
		callCtx,
		config,
		identity,
		http.MethodGet,
		chatGPTUsageURL,
		buildCodexCommonHeaders("$TOKEN$", identity.chatGPTAccountID, false),
		"",
	)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		body := truncate(response.Body, 240)
		slog.Warn("openai_quota_bridge_query_failed", "account_id", account.ID, "status", response.StatusCode, "body", body)
		return nil, infraerrors.Newf(mapUpstreamStatus(response.StatusCode), "OPENAI_QUOTA_UPSTREAM_ERROR", "upstream returned %d: %s", response.StatusCode, body)
	}

	var payload OpenAIQuotaUsage
	if err := json.Unmarshal([]byte(response.Body), &payload); err != nil {
		return nil, infraerrors.Newf(http.StatusBadGateway, "OPENAI_QUOTA_UPSTREAM_INVALID_RESPONSE", "failed to decode upstream quota response: %v", err)
	}
	payload.FetchedAt = time.Now().Unix()
	mergeOpenAIQuotaResetCreditDetails(&payload, queryOpenAIQuotaBridgeResetCreditDetails(callCtx, config, identity, account.ID))
	return &payload, nil
}

func (s *OpenAIQuotaService) resetCreditViaOpenAIQuotaBridge(ctx context.Context, account *Account) (*OpenAIQuotaResetResult, error) {
	config, identity, err := s.prepareOpenAIQuotaBridge(ctx, account)
	if err != nil {
		return nil, err
	}
	redeemRequestID, err := generateRedeemRequestID()
	if err != nil {
		return nil, infraerrors.Newf(http.StatusInternalServerError, "OPENAI_QUOTA_REDEEM_ID_FAILED", "failed to generate redeem id: %v", err)
	}
	body, err := json.Marshal(map[string]string{"redeem_request_id": redeemRequestID})
	if err != nil {
		return nil, infraerrors.Newf(http.StatusInternalServerError, "OPENAI_QUOTA_RESET_REQUEST_FAILED", "failed to encode reset request: %v", err)
	}
	headers := buildCodexCommonHeaders("$TOKEN$", identity.chatGPTAccountID, false)
	headers["content-type"] = "application/json"

	callCtx, cancel := context.WithTimeout(ctx, openaiQuotaUpstreamTimeout)
	defer cancel()
	response, err := callOpenAIQuotaBridge(callCtx, config, identity, http.MethodPost, chatGPTRateLimitResetURL, headers, string(body))
	if err != nil {
		return nil, err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		body := truncate(response.Body, 240)
		slog.Warn("openai_quota_bridge_reset_failed", "account_id", account.ID, "status", response.StatusCode, "body", body)
		return nil, infraerrors.Newf(mapUpstreamStatus(response.StatusCode), "OPENAI_QUOTA_RESET_UPSTREAM_ERROR", "upstream returned %d: %s", response.StatusCode, body)
	}

	var payload OpenAIQuotaResetResult
	if err := json.Unmarshal([]byte(response.Body), &payload); err != nil {
		return nil, infraerrors.Newf(http.StatusBadGateway, "OPENAI_QUOTA_RESET_INVALID_RESPONSE", "failed to decode upstream reset response: %v", err)
	}
	slog.Info("openai_quota_bridge_reset_success", "account_id", account.ID, "code", payload.Code, "windows_reset", payload.WindowsReset)
	return &payload, nil
}

func (s *OpenAIQuotaService) prepareOpenAIQuotaBridge(ctx context.Context, account *Account) (openAIQuotaBridgeConfig, openAIQuotaBridgeIdentity, error) {
	var zeroConfig openAIQuotaBridgeConfig
	var zeroIdentity openAIQuotaBridgeIdentity
	if account == nil || !account.IsOpenAICompatibleQuotaBridge() {
		return zeroConfig, zeroIdentity, infraerrors.New(http.StatusBadRequest, "OPENAI_QUOTA_INVALID_TYPE", "account is not a compatible quota bridge")
	}

	config, err := loadOpenAIQuotaBridgeConfig()
	if err != nil {
		return zeroConfig, zeroIdentity, err
	}
	accountOrigin, err := openAIQuotaBridgeOrigin(account.GetCredential("base_url"))
	if err != nil {
		return zeroConfig, zeroIdentity, infraerrors.Newf(http.StatusBadRequest, "OPENAI_QUOTA_BRIDGE_INVALID_BASE_URL", "invalid quota bridge base URL: %v", err)
	}
	managementOrigin, err := openAIQuotaBridgeOrigin(config.managementURL)
	if err != nil || !strings.EqualFold(accountOrigin, managementOrigin) {
		return zeroConfig, zeroIdentity, infraerrors.New(http.StatusBadRequest, "OPENAI_QUOTA_BRIDGE_BASE_URL_MISMATCH", "quota bridge account does not match the configured CPA management endpoint")
	}

	authName := strings.TrimSpace(account.GetExtraString(OpenAIQuotaBridgeAuthNameExtraKey))
	expectedEmail := strings.TrimSpace(account.GetExtraString(OpenAIQuotaBridgeAuthEmailExtraKey))
	if authName == "" || expectedEmail == "" {
		return zeroConfig, zeroIdentity, infraerrors.New(http.StatusBadRequest, "OPENAI_QUOTA_BRIDGE_AUTH_BINDING_MISSING", "quota bridge auth file name and email must both be configured")
	}

	var authFiles openAIQuotaBridgeAuthFilesResponse
	endpoint := "/v0/management/auth-files?name=" + url.QueryEscape(authName)
	if err := callOpenAIQuotaBridgeManagement(ctx, config, http.MethodGet, endpoint, nil, &authFiles); err != nil {
		return zeroConfig, zeroIdentity, err
	}
	auth, err := matchingCPAAuth(authFiles.Files, authName)
	if err != nil {
		return zeroConfig, zeroIdentity, err
	}
	if auth.Name != authName && auth.ID != authName {
		return zeroConfig, zeroIdentity, infraerrors.New(http.StatusBadGateway, "OPENAI_QUOTA_BRIDGE_AUTH_MISMATCH", "CPA returned a different auth identity")
	}
	provider := strings.TrimSpace(auth.Provider)
	if provider == "" {
		provider = strings.TrimSpace(auth.Type)
	}
	if !strings.EqualFold(provider, "codex") || auth.Disabled || auth.Unavailable || strings.EqualFold(strings.TrimSpace(auth.Status), "disabled") {
		return zeroConfig, zeroIdentity, infraerrors.New(http.StatusBadGateway, "OPENAI_QUOTA_BRIDGE_AUTH_UNAVAILABLE", "the bound CPA Codex auth is disabled or unavailable")
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Email), expectedEmail) {
		return zeroConfig, zeroIdentity, infraerrors.New(http.StatusBadGateway, "OPENAI_QUOTA_BRIDGE_EMAIL_MISMATCH", "the bound CPA auth email does not match the configured account")
	}
	identity := openAIQuotaBridgeIdentity{
		authIndex:        strings.TrimSpace(auth.AuthIndex),
		chatGPTAccountID: strings.TrimSpace(auth.IDToken.ChatGPTAccountID),
	}
	if identity.authIndex == "" || identity.chatGPTAccountID == "" {
		return zeroConfig, zeroIdentity, infraerrors.New(http.StatusBadGateway, "OPENAI_QUOTA_BRIDGE_AUTH_INCOMPLETE", "the bound CPA auth is missing auth_index or chatgpt_account_id")
	}
	return config, identity, nil
}

func loadOpenAIQuotaBridgeConfig() (openAIQuotaBridgeConfig, error) {
	var zero openAIQuotaBridgeConfig
	managementURL, err := normalizeOpenAIQuotaBridgeManagementURL(os.Getenv(openAIQuotaBridgeManagementURLKey))
	if err != nil {
		return zero, infraerrors.Newf(http.StatusInternalServerError, "OPENAI_QUOTA_BRIDGE_NOT_CONFIGURED", "quota bridge management URL is not configured: %v", err)
	}
	secret, err := readOpenAIQuotaBridgeManagementSecret(os.Getenv(openAIQuotaBridgeManagementPasswordFileKey))
	if err != nil {
		return zero, infraerrors.Newf(http.StatusInternalServerError, "OPENAI_QUOTA_BRIDGE_NOT_CONFIGURED", "quota bridge management credential is unavailable: %v", err)
	}
	return openAIQuotaBridgeConfig{managementURL: managementURL, secret: secret}, nil
}

func queryOpenAIQuotaBridgeResetCreditDetails(ctx context.Context, config openAIQuotaBridgeConfig, identity openAIQuotaBridgeIdentity, accountID int64) *openAIRateLimitResetCreditDetails {
	response, err := callOpenAIQuotaBridge(
		ctx,
		config,
		identity,
		http.MethodGet,
		chatGPTRateLimitCreditsURL,
		buildCodexCommonHeaders("$TOKEN$", identity.chatGPTAccountID, false),
		"",
	)
	if err != nil {
		slog.Warn("openai_quota_bridge_reset_credit_details_failed", "account_id", accountID, "error", err)
		return nil
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		slog.Warn("openai_quota_bridge_reset_credit_details_failed", "account_id", accountID, "status", response.StatusCode)
		return nil
	}
	details, err := parseOpenAIRateLimitResetCreditDetails([]byte(response.Body))
	if err != nil {
		slog.Warn("openai_quota_bridge_reset_credit_details_parse_failed", "account_id", accountID, "error", err)
		if details.AvailableCount == nil {
			return nil
		}
	}
	if details.AvailableCount == nil && !details.CreditListPresent {
		return nil
	}
	return &details
}

func mergeOpenAIQuotaResetCreditDetails(payload *OpenAIQuotaUsage, details *openAIRateLimitResetCreditDetails) {
	if payload == nil || details == nil {
		return
	}
	if payload.RateLimitResetCredits == nil {
		payload.RateLimitResetCredits = &OpenAIRateLimitResetCredits{}
	}
	if details.CreditListPresent {
		payload.RateLimitResetCredits.Credits = details.Credits
	}
	switch {
	case details.AvailableCount != nil:
		payload.RateLimitResetCredits.AvailableCount = *details.AvailableCount
	case details.CreditListPresent:
		payload.RateLimitResetCredits.AvailableCount = details.AvailableCreditCount
	}
}

func callOpenAIQuotaBridge(ctx context.Context, config openAIQuotaBridgeConfig, identity openAIQuotaBridgeIdentity, method, upstreamURL string, headers map[string]string, data string) (*openAIQuotaBridgeAPICallResponse, error) {
	payload := openAIQuotaBridgeAPICallRequest{
		AuthIndex: identity.authIndex,
		Method:    method,
		URL:       upstreamURL,
		Header:    headers,
		Data:      data,
	}
	var response openAIQuotaBridgeAPICallResponse
	if err := callOpenAIQuotaBridgeManagement(ctx, config, http.MethodPost, "/v0/management/api-call", payload, &response); err != nil {
		return nil, err
	}
	if response.StatusCode <= 0 {
		return nil, infraerrors.New(http.StatusBadGateway, "OPENAI_QUOTA_BRIDGE_INVALID_RESPONSE", "CPA management API returned an invalid upstream status")
	}
	return &response, nil
}

func callOpenAIQuotaBridgeManagement(ctx context.Context, config openAIQuotaBridgeConfig, method, endpoint string, body any, out any) error {
	var requestBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return infraerrors.Newf(http.StatusInternalServerError, "OPENAI_QUOTA_BRIDGE_REQUEST_FAILED", "failed to encode CPA management request: %v", err)
		}
		requestBody = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(config.managementURL, "/")+endpoint, requestBody)
	if err != nil {
		return infraerrors.Newf(http.StatusInternalServerError, "OPENAI_QUOTA_BRIDGE_REQUEST_FAILED", "failed to build CPA management request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+config.secret)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := openAIQuotaBridgeHTTPClient.Do(request)
	if err != nil {
		return infraerrors.Newf(http.StatusBadGateway, "OPENAI_QUOTA_BRIDGE_REQUEST_FAILED", "CPA management request failed: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	limited := io.LimitReader(response.Body, openAIQuotaBridgeMaxManagementResponseBytes+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return infraerrors.Newf(http.StatusBadGateway, "OPENAI_QUOTA_BRIDGE_RESPONSE_FAILED", "failed to read CPA management response: %v", err)
	}
	if len(responseBody) > openAIQuotaBridgeMaxManagementResponseBytes {
		return infraerrors.New(http.StatusBadGateway, "OPENAI_QUOTA_BRIDGE_RESPONSE_TOO_LARGE", "CPA management response exceeded the quota bridge limit")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return infraerrors.Newf(http.StatusBadGateway, "OPENAI_QUOTA_BRIDGE_MANAGEMENT_ERROR", "CPA management API returned %d", response.StatusCode)
	}
	if err := json.Unmarshal(responseBody, out); err != nil {
		return infraerrors.Newf(http.StatusBadGateway, "OPENAI_QUOTA_BRIDGE_INVALID_RESPONSE", "failed to decode CPA management response: %v", err)
	}
	return nil
}

func normalizeOpenAIQuotaBridgeManagementURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("environment variable %s is empty", openAIQuotaBridgeManagementURLKey)
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil {
		return "", fmt.Errorf("must be an absolute http(s) URL without user info")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", fmt.Errorf("must not contain a path, query, or fragment")
	}
	parsed.Path = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func openAIQuotaBridgeOrigin(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil {
		return "", fmt.Errorf("must be an absolute http(s) URL without user info")
	}
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host), nil
}

func readOpenAIQuotaBridgeManagementSecret(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("environment variable %s is empty", openAIQuotaBridgeManagementPasswordFileKey)
	}
	// The path is set by the administrator-owned management-password-file
	// environment variable. No HTTP request field can select this file.
	file, err := os.Open(path) // #nosec G703 -- Explicit operator-selected credential file.
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 4096 {
		return "", fmt.Errorf("management credential file is invalid")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("management credential file permissions are too broad")
	}
	contents, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return "", err
	}
	if len(contents) > 4096 {
		return "", fmt.Errorf("management credential file is too large")
	}
	secret := strings.TrimSpace(string(contents))
	if secret == "" {
		return "", fmt.Errorf("management credential file is empty")
	}
	return secret, nil
}
