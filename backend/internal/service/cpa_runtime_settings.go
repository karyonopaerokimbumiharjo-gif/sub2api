package service

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

// Runtime edits are deliberately allowlisted. OAuth tokens and proxy passwords
// never enter a browser response or an arbitrary management API passthrough.
type CPACredentialSettings struct {
	Name              string  `json:"name"`
	BusinessAccountID int64   `json:"business_account_id,omitempty"`
	BusinessStatus    string  `json:"business_status,omitempty"`
	Schedulable       bool    `json:"schedulable"`
	GroupIDs          []int64 `json:"group_ids,omitempty"`
	AuthID            string  `json:"auth_id"`
	Identity          string  `json:"identity"`
	Unavailable       bool    `json:"unavailable"`
	Email             string  `json:"email"`
	Provider          string  `json:"provider"`
	Status            string  `json:"status"`
	Disabled          bool    `json:"disabled"`
	ProxyID           *int64  `json:"proxy_id"`
	ProxyConfigured   bool    `json:"proxy_configured"`
	Priority          int     `json:"priority"`
	Weight            int     `json:"weight"`
	RequestRetry      int     `json:"request_retry"`
}

type CPACredentialUpdate struct {
	Name         string `json:"name"`
	Disabled     bool   `json:"disabled"`
	ProxyID      *int64 `json:"proxy_id"`
	Priority     int    `json:"priority"`
	Weight       int    `json:"weight"`
	RequestRetry int    `json:"request_retry"`
}

var cpaRuntimeMu sync.Mutex

func cpaRuntimeConfig() (openAIQuotaBridgeConfig, error) { return loadOpenAIQuotaBridgeConfig() }

func cpaAuthMetadata(ctx context.Context, cfg openAIQuotaBridgeConfig, name string) (map[string]any, error) {
	var data map[string]any
	err := callOpenAIQuotaBridgeManagement(ctx, cfg, http.MethodGet, "/v0/management/auth-files/download?name="+url.QueryEscape(name), nil, &data)
	return data, err
}

// LoadCPAOAuthCredentials reads the already-authorized Codex file from CPA for
// a bound business account. It is used only for an explicit CPA ↔ Pi backend
// switch; it never returns the material through an API response. Keeping this
// path in the service also makes the identity/email binding checks identical to
// quota reads and prevents selecting an arbitrary pool member.
func (s *OpenAIQuotaService) LoadCPAOAuthCredentials(ctx context.Context, account *Account) (map[string]any, error) {
	if account == nil || !account.IsOpenAICompatibleQuotaBridge() {
		return nil, infraerrors.BadRequest("OPENAI_CPA_ACCOUNT_REQUIRED", "只能切换已绑定的 CPA OpenAI 账号")
	}
	config, identity, err := s.prepareOpenAIQuotaBridge(ctx, account)
	if err != nil {
		return nil, err
	}
	metadata, err := cpaAuthMetadata(ctx, config, strings.TrimSpace(account.GetExtraString(OpenAIQuotaBridgeAuthNameExtraKey)))
	if err != nil {
		return nil, err
	}
	credentials := make(map[string]any, len(metadata)+8)
	for key, value := range metadata {
		credentials[key] = value
	}
	// CPA releases have used both flat fields and a nested token object. Accept
	// both shapes while preserving the source map only inside the service.
	token, tokenOK := metadata["token"].(map[string]any)
	if !tokenOK {
		token, tokenOK = metadata["tokens"].(map[string]any)
	}
	if tokenOK {
		for _, key := range []string{"access_token", "refresh_token", "id_token", "expires_at", "expired", "account_id", "email", "client_id"} {
			if _, exists := credentials[key]; !exists {
				if value, exists := token[key]; exists {
					credentials[key] = value
				}
			}
		}
	}
	if _, ok := credentials["chatgpt_account_id"]; !ok || strings.TrimSpace(openAICPACredentialString(credentials, "chatgpt_account_id")) == "" {
		credentials["chatgpt_account_id"] = identity.chatGPTAccountID
	}
	if _, ok := credentials["email"]; !ok || strings.TrimSpace(openAICPACredentialString(credentials, "email")) == "" {
		credentials["email"] = account.GetExtraString(OpenAIQuotaBridgeAuthEmailExtraKey)
	}
	if _, ok := credentials["expires_at"]; !ok {
		if expired := openAICPACredentialString(credentials, "expired"); expired != "" {
			credentials["expires_at"] = expired
		} else if expiry := openAICPACredentialString(credentials, "expiry"); expiry != "" {
			credentials["expires_at"] = expiry
		}
	}
	for _, key := range []string{"access_token", "refresh_token", "chatgpt_account_id", "email", "expires_at"} {
		if strings.TrimSpace(openAICPACredentialString(credentials, key)) == "" {
			return nil, infraerrors.New(http.StatusBadRequest, "OPENAI_CPA_AUTH_INCOMPLETE", "CPA 授权文件缺少可切换所需的 OAuth 凭据，请先在 CPA 中重新验证")
		}
	}
	return credentials, nil
}

func cpaNumber(m map[string]any, key string, fallback int) int {
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case json.Number:
		n, e := v.Int64()
		if e == nil {
			return int(n)
		}
	case string:
		n, e := strconv.Atoi(strings.TrimSpace(v))
		if e == nil {
			return n
		}
	}
	return fallback
}

func cpaSettings(auth openAIQuotaBridgeAuthFile, m map[string]any) CPACredentialSettings {
	result := CPACredentialSettings{Name: auth.Name, Email: auth.Email, Provider: auth.Provider, Status: auth.Status, Disabled: auth.Disabled, Priority: cpaNumber(m, "priority", 0), Weight: cpaNumber(m, "weight", 1), RequestRetry: cpaNumber(m, "request_retry", 0)}
	identity := strings.TrimSpace(auth.IDToken.ChatGPTAccountID)
	if identity == "" {
		identity, _ = m["account_id"].(string)
	}
	if identity == "" {
		identity = strings.ToLower(strings.TrimSpace(auth.Email))
	}
	if identity == "" {
		identity = auth.Name
	}
	digest := sha256.Sum256([]byte(auth.Provider + "\x00" + identity))
	result.Identity = fmt.Sprintf("%x", digest[:16])
	result.Unavailable = auth.Unavailable
	result.AuthID = auth.ID
	if id := cpaNumber(m, "sub2_proxy_id", 0); id > 0 {
		n := int64(id)
		result.ProxyID = &n
	}
	proxy, _ := m["proxy_url"].(string)
	result.ProxyConfigured = strings.TrimSpace(proxy) != ""
	return result
}

func cpaAuthList(ctx context.Context, cfg openAIQuotaBridgeConfig) ([]openAIQuotaBridgeAuthFile, error) {
	var response openAIQuotaBridgeAuthFilesResponse
    err := callOpenAIQuotaBridgeManagement(ctx, cfg, http.MethodGet, "/v0/management/auth-files", nil, &response)
    // Plugin credentials are in-memory shadows of the same OAuth file, not
    // additional user accounts and must never be imported or deleted separately.
    files := make([]openAIQuotaBridgeAuthFile, 0, len(response.Files))
    for _, f := range response.Files {
        if f.Provider == "oai-basispoints" || f.Type == "oai-basispoints" { continue }
        files = append(files, f)
    }
    return files, err
}

func findCPAAuth(ctx context.Context, cfg openAIQuotaBridgeConfig, name string) (openAIQuotaBridgeAuthFile, error) {
	files, err := cpaAuthList(ctx, cfg)
	if err != nil {
		return openAIQuotaBridgeAuthFile{}, err
	}
	for _, a := range files {
		if a.Name == name {
			return a, nil
		}
	}
	return openAIQuotaBridgeAuthFile{}, infraerrors.NotFound("CPA_AUTH_NOT_FOUND", "CPA credential was not found")
}

func (s *OpenAIQuotaService) ListCPACredentials(ctx context.Context) ([]CPACredentialSettings, error) {
	cfg, err := cpaRuntimeConfig()
	if err != nil {
		return nil, err
	}
	files, err := cpaAuthList(ctx, cfg)
	if err != nil {
		return nil, err
	}
	result := make([]CPACredentialSettings, 0, len(files))
	for _, a := range files {
		m, err := cpaAuthMetadata(ctx, cfg, a.Name)
		if err != nil {
			return nil, err
		}
		result = append(result, cpaSettings(a, m))
	}
	return result, nil
}

func validateCPARuntime(input CPACredentialUpdate) error {
	if strings.TrimSpace(input.Name) == "" || strings.ContainsAny(input.Name, "/\\") || input.Priority < -10000 || input.Priority > 10000 || input.Weight < 1 || input.Weight > 1000000 || input.RequestRetry < 0 || input.RequestRetry > 10 {
		return infraerrors.BadRequest("CPA_SETTINGS_INVALID", "凭证名、优先级、权重或重试次数无效")
	}
	if input.ProxyID != nil && *input.ProxyID < 0 {
		return infraerrors.BadRequest("CPA_PROXY_INVALID", "代理 ID 无效")
	}
	return nil
}

func (s *OpenAIQuotaService) cpaRuntimeFields(ctx context.Context, input CPACredentialUpdate) (map[string]any, error) {
	if err := validateCPARuntime(input); err != nil {
		return nil, err
	}
	proxyURL := ""
	var proxyID any = nil
	if input.ProxyID != nil && *input.ProxyID > 0 {
		if s == nil || s.proxyRepo == nil {
			return nil, infraerrors.BadRequest("CPA_PROXY_UNAVAILABLE", "代理服务不可用")
		}
		proxy, err := s.proxyRepo.GetByID(ctx, *input.ProxyID)
		if err != nil {
			return nil, err
		}
		if proxy == nil || !proxy.IsActive() || proxy.IsExpired(time.Now()) {
			return nil, infraerrors.BadRequest("CPA_PROXY_UNAVAILABLE", "所选代理已停用或到期")
		}
		// Expiry and fallback workers are not CPA transports. Do not silently
		// promise automatic fallback/expiry enforcement that CPA does not provide.
		if proxy.ExpiresAt != nil || proxy.FallbackMode == FallbackModeProxy || proxy.FallbackMode == FallbackModeDirect {
			return nil, infraerrors.BadRequest("CPA_PROXY_LIFECYCLE_UNSUPPORTED", "CPA 代理暂不支持自动到期或自动回退，请使用无到期、无回退的代理")
		}
		proxyURL = proxy.URL()
		proxyID = proxy.ID
	}
	return map[string]any{"name": input.Name, "proxy_url": proxyURL, "sub2_proxy_id": proxyID, "priority": input.Priority, "weight": input.Weight, "request_retry": input.RequestRetry}, nil
}

func patchCPARuntime(ctx context.Context, cfg openAIQuotaBridgeConfig, fields map[string]any) error {
	var out map[string]any
	return callOpenAIQuotaBridgeManagement(ctx, cfg, http.MethodPatch, "/v0/management/auth-files/fields", fields, &out)
}

func (s *OpenAIQuotaService) UpdateCPACredential(ctx context.Context, input CPACredentialUpdate) (*CPACredentialSettings, error) {
	cpaRuntimeMu.Lock()
	defer cpaRuntimeMu.Unlock()
	cfg, err := cpaRuntimeConfig()
	if err != nil {
		return nil, err
	}
	auth, err := findCPAAuth(ctx, cfg, input.Name)
	if err != nil {
		return nil, err
	}
	old, err := cpaAuthMetadata(ctx, cfg, input.Name)
	if err != nil {
		return nil, err
	}
	fields, err := s.cpaRuntimeFields(ctx, input)
	if err != nil {
		return nil, err
	}
	// Preserve unmanaged egress when editing unrelated settings.
	if input.ProxyID == nil {
		fields["proxy_url"] = old["proxy_url"]
		fields["sub2_proxy_id"] = old["sub2_proxy_id"]
	}
	if err = patchCPARuntime(ctx, cfg, fields); err != nil {
		return nil, err
	}
	if input.Disabled != auth.Disabled {
		var out map[string]any
		err = callOpenAIQuotaBridgeManagement(ctx, cfg, http.MethodPatch, "/v0/management/auth-files/status", map[string]any{"name": input.Name, "auth_index": auth.AuthIndex, "disabled": input.Disabled}, &out)
		if err != nil {
			rollback := map[string]any{"name": input.Name}
			for _, k := range []string{"proxy_url", "sub2_proxy_id", "priority", "weight", "request_retry"} {
				rollback[k] = old[k]
			}
			if rollback["request_retry"] == nil {
				rollback["request_retry"] = 0
			}
			restore, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			if rollbackErr := patchCPARuntime(restore, cfg, rollback); rollbackErr != nil {
				return nil, infraerrors.New(http.StatusBadGateway, "CPA_SETTINGS_PARTIAL", "CPA 更新未完成，回退失败，请刷新后核对")
			}
			return nil, err
		}
	}
	current, err := findCPAAuth(ctx, cfg, input.Name)
	if err != nil {
		return nil, err
	}
	metadata, err := cpaAuthMetadata(ctx, cfg, input.Name)
	if err != nil {
		return nil, err
	}
	result := cpaSettings(current, metadata)
	actualProxy, _ := metadata["proxy_url"].(string)
	expectedProxy, _ := fields["proxy_url"].(string)
	actualID, expectedID := int64(0), int64(0)
	if result.ProxyID != nil {
		actualID = *result.ProxyID
	}
	if input.ProxyID != nil {
		expectedID = *input.ProxyID
	} else {
		expectedID = int64(cpaNumber(old, "sub2_proxy_id", 0))
	}
	if result.Disabled != input.Disabled || result.Priority != input.Priority || result.Weight != input.Weight || result.RequestRetry != input.RequestRetry || actualProxy != expectedProxy || actualID != expectedID {
		return nil, infraerrors.New(http.StatusBadGateway, "CPA_SETTINGS_VERIFY_FAILED", "CPA 配置回读不一致，请刷新后核对")
	}
	return &result, nil
}

// cpaProxyBindings is used by proxy edits/deletes too, so a saved proxy cannot
// silently diverge from an already configured CPA egress proxy.
func cpaProxyBindings(ctx context.Context, id int64) (openAIQuotaBridgeConfig, []string, error) {
	if os.Getenv(openAIQuotaBridgeManagementURLKey) == "" {
		return openAIQuotaBridgeConfig{}, nil, nil
	}
	cfg, err := cpaRuntimeConfig()
	if err != nil {
		return cfg, nil, err
	}
	files, err := cpaAuthList(ctx, cfg)
	if err != nil {
		return cfg, nil, err
	}
	var names []string
	for _, a := range files {
		m, e := cpaAuthMetadata(ctx, cfg, a.Name)
		if e != nil {
			return cfg, nil, e
		}
		if int64(cpaNumber(m, "sub2_proxy_id", 0)) == id {
			names = append(names, a.Name)
		}
	}
	return cfg, names, nil
}

func syncCPAProxy(ctx context.Context, proxy *Proxy) (func() error, error) {
	cfg, names, err := cpaProxyBindings(ctx, proxy.ID)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return func() error { return nil }, nil
	}
	if !proxy.IsActive() || proxy.ExpiresAt != nil || proxy.FallbackMode == FallbackModeProxy || proxy.FallbackMode == FallbackModeDirect {
		return nil, infraerrors.BadRequest("CPA_PROXY_IN_USE", "该代理已绑定 CPA 凭证；请先在 CPA 凭证设置中更换代理，再停用或设置到期/回退")
	}
	old := map[string]any{}
	revert := func() error {
		restore, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		var failed bool
		for name, value := range old {
			if e := patchCPARuntime(restore, cfg, map[string]any{"name": name, "proxy_url": value}); e != nil {
				failed = true
			}
		}
		if failed {
			return infraerrors.New(http.StatusBadGateway, "CPA_PROXY_ROLLBACK_FAILED", "CPA 代理回退失败，请核对凭证设置")
		}
		return nil
	}
	for _, name := range names {
		m, e := cpaAuthMetadata(ctx, cfg, name)
		if e != nil {
			if restoreErr := revert(); restoreErr != nil {
				return nil, restoreErr
			}
			return nil, e
		}
		old[name] = m["proxy_url"]
		if e = patchCPARuntime(ctx, cfg, map[string]any{"name": name, "proxy_url": proxy.URL()}); e != nil {
			if restoreErr := revert(); restoreErr != nil {
				return nil, restoreErr
			}
			return nil, e
		}
		verified, e := cpaAuthMetadata(ctx, cfg, name)
		actual, _ := verified["proxy_url"].(string)
		if e != nil || actual != proxy.URL() {
			if restoreErr := revert(); restoreErr != nil {
				return nil, restoreErr
			}
			return nil, infraerrors.New(http.StatusBadGateway, "CPA_PROXY_VERIFY_FAILED", "CPA 代理回读校验失败，已尝试回退")
		}
	}
	return revert, nil
}

// Reauthorization preserves runtime edits for both the bound credential and
// additional pool members. Only the credential material is replaced.
func preserveCPAImportRuntime(ctx context.Context, cfg openAIQuotaBridgeConfig, name string, payload map[string]any) error {
	var response openAIQuotaBridgeAuthFilesResponse
	if err := callOpenAIQuotaBridgeManagement(ctx, cfg, http.MethodGet, "/v0/management/auth-files?name="+url.QueryEscape(name), nil, &response); err != nil {
		return err
	}
	for _, auth := range response.Files {
		if auth.Name != name {
			continue
		}
		old, err := cpaAuthMetadata(ctx, cfg, name)
		if err != nil {
			return err
		}
		for _, key := range []string{"proxy_url", "sub2_proxy_id", "priority", "weight", "request_retry", "disabled"} {
			if value, ok := old[key]; ok {
				payload[key] = value
			}
		}
		payload["disabled"] = auth.Disabled
		break
	}
	return nil
}
func verifyCPAImportedRuntime(ctx context.Context, cfg openAIQuotaBridgeConfig, name string, payload map[string]any) error {
	metadata, err := cpaAuthMetadata(ctx, cfg, name)
	if err != nil {
		return err
	}
	actual, _ := metadata["proxy_url"].(string)
	expected, _ := payload["proxy_url"].(string)
	if actual != expected {
		return infraerrors.New(http.StatusBadGateway, "CPA_IMPORT_RUNTIME_VERIFY_FAILED", "CPA 导入完成，但代理配置回读不一致，请核对")
	}
	for _, key := range []string{"sub2_proxy_id", "priority", "weight", "request_retry"} {
		if cpaNumber(metadata, key, 0) != cpaNumber(payload, key, 0) {
			return infraerrors.New(http.StatusBadGateway, "CPA_IMPORT_RUNTIME_VERIFY_FAILED", "CPA 导入完成，但调度配置回读不一致，请核对")
		}
	}
	return nil
}

// CPAExecutionAPIKey is server-side provisioning data and must never enter a DTO.
func (s *OpenAIQuotaService) CPAExecutionAPIKey(ctx context.Context) (string,error) {
 cfg,err:=cpaRuntimeConfig();if err!=nil{return "",err}
 var keys openAIQuotaBridgeAPIKeysResponse
 if err=callOpenAIQuotaBridgeManagement(ctx,cfg,http.MethodGet,"/v0/management/api-keys",nil,&keys);err!=nil{return "",err}
 for _,key:=range keys.Keys{if strings.TrimSpace(key)!=""{return strings.TrimSpace(key),nil}}
 return "",infraerrors.BadRequest("CPA_EXECUTION_KEY_MISSING","执行后端未配置 API Key")
}
