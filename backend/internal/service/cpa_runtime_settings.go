package service

import (
	"context"
	"encoding/json"
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
	Name            string `json:"name"`
	Email           string `json:"email"`
	Provider        string `json:"provider"`
	Status          string `json:"status"`
	Disabled        bool   `json:"disabled"`
	ProxyID         *int64 `json:"proxy_id"`
	ProxyConfigured bool   `json:"proxy_configured"`
	Priority        int    `json:"priority"`
	Weight          int    `json:"weight"`
	RequestRetry    int    `json:"request_retry"`
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
	return response.Files, err
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
