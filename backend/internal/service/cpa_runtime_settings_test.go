package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type cpaRuntimeProxyRepo struct {
	ProxyRepository
	proxy *Proxy
}

func (r *cpaRuntimeProxyRepo) GetByID(context.Context, int64) (*Proxy, error) {
	p := *r.proxy
	return &p, nil
}

// This fake models CPA's arbitrary metadata patch (null deletes a field), not
// just the Sub2 response. It catches token leakage and failed partial updates.
func TestCPARuntimeRoundTripAndRollback(t *testing.T) {
	metadata := map[string]any{"access_token": "never-return-this-token", "proxy_url": "http://old-proxy:8080", "priority": float64(2), "weight": float64(1), "request_retry": float64(0)}
	disabled, failStatus := false, false
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer test-secret", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v0/management/auth-files":
			_ = json.NewEncoder(w).Encode(map[string]any{"files": []any{map[string]any{"name": "bound.json", "provider": "codex", "auth_index": "index", "email": "test@example.com", "disabled": disabled, "status": "active"}}})
		case "/v0/management/auth-files/download":
			_ = json.NewEncoder(w).Encode(metadata)
		case "/v0/management/auth-files/fields":
			writes++
			var patch map[string]any
			require.NoError(t, json.NewDecoder(r.Body).Decode(&patch))
			require.Equal(t, "bound.json", patch["name"])
			for k, v := range patch {
				if k == "name" {
					continue
				}
				if v == nil {
					delete(metadata, k)
				} else {
					metadata[k] = v
				}
			}
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/v0/management/auth-files/status":
			if failStatus {
				http.Error(w, `{"error":"unavailable"}`, http.StatusServiceUnavailable)
				return
			}
			var patch struct {
				Disabled bool `json:"disabled"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&patch))
			disabled = patch.Disabled
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	secret := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(secret, []byte("test-secret"), 0600))
	t.Setenv(openAIQuotaBridgeManagementURLKey, server.URL)
	t.Setenv(openAIQuotaBridgeManagementPasswordFileKey, secret)
	repo := &cpaRuntimeProxyRepo{proxy: &Proxy{ID: 9, Protocol: "http", Host: "new-proxy", Port: 8080, Username: "proxy-user", Password: "proxy-secret", Status: StatusActive, FallbackMode: FallbackModeNone}}
	s := &OpenAIQuotaService{proxyRepo: repo}
	ctx := context.Background()
	list, err := s.ListCPACredentials(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	encoded, err := json.Marshal(list)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "never-return")
	require.NotContains(t, string(encoded), "old-proxy")
	id := int64(9)
	input := CPACredentialUpdate{Name: "bound.json", ProxyID: &id, Priority: 7, Weight: 3, RequestRetry: 2, Disabled: true}
	result, err := s.UpdateCPACredential(ctx, input)
	require.NoError(t, err)
	require.True(t, result.Disabled)
	require.Equal(t, &id, result.ProxyID)
	require.Equal(t, repo.proxy.URL(), metadata["proxy_url"])
	require.Equal(t, "never-return-this-token", metadata["access_token"])
	encoded, err = json.Marshal(result)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "proxy-secret")
	input.Disabled = false
	input.Priority = 99
	failStatus = true
	_, err = s.UpdateCPACredential(ctx, input)
	require.Error(t, err)
	require.Equal(t, float64(7), metadata["priority"])
	require.True(t, disabled)
	failStatus = false
	input.ProxyID = nil
	input.Priority = 4
	result, err = s.UpdateCPACredential(ctx, input)
	require.NoError(t, err)
	require.Nil(t, result.ProxyID)
	require.False(t, result.ProxyConfigured)
	require.False(t, result.Disabled)
	before := writes
	expires := time.Now().Add(time.Hour)
	repo.proxy.ExpiresAt = &expires
	input.ProxyID = &id
	_, err = s.UpdateCPACredential(ctx, input)
	require.ErrorContains(t, err, "到期")
	require.Equal(t, before, writes)
	input.Name = "../secret"
	_, err = s.UpdateCPACredential(ctx, input)
	require.Error(t, err)
	require.Equal(t, before, writes)
	// A proxy already bound to CPA must not be silently disabled or deleted.
	metadata["sub2_proxy_id"] = float64(9)
	_, names, err := cpaProxyBindings(ctx, 9)
	require.NoError(t, err)
	require.Equal(t, []string{"bound.json"}, names)
	_, err = syncCPAProxy(ctx, repo.proxy)
	require.ErrorContains(t, err, "已绑定")
	repo.proxy.ExpiresAt = nil
	repo.proxy.Host = "changed-proxy"
	revert, err := syncCPAProxy(ctx, repo.proxy)
	require.NoError(t, err)
	require.Equal(t, repo.proxy.URL(), metadata["proxy_url"])
	require.NoError(t, revert())
	require.Empty(t, metadata["proxy_url"])

	admin := &adminServiceImpl{}
	proxies := []ProxyWithAccountCount{{Proxy: Proxy{ID: 9}}, {Proxy: Proxy{ID: 10}}}
	admin.attachCPACredentialBindings(ctx, proxies)
	require.Equal(t, int64(1), *proxies[0].CPACredentialCount)
	require.Equal(t, []string{"test@example.com"}, proxies[0].CPACredentialNames)
	require.Equal(t, int64(0), *proxies[1].CPACredentialCount)
	require.Empty(t, proxies[1].CPACredentialNames)
}

func TestCPAImportAppliesRuntimeAndReauthorizationPreservesIt(t *testing.T) {
	var metadata map[string]any
	var name string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			name = r.URL.Query().Get("name")
			require.NoError(t, json.NewDecoder(r.Body).Decode(&metadata))
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		if r.URL.Path == "/v0/management/auth-files/download" {
			_ = json.NewEncoder(w).Encode(metadata)
			return
		}
		files := []any{}
		if metadata != nil {
			files = append(files, map[string]any{"name": name, "email": metadata["email"], "provider": "claude", "status": "active", "disabled": metadata["disabled"]})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"files": files})
	}))
	defer server.Close()
	secret := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(secret, []byte("test-secret"), 0600))
	t.Setenv(openAIQuotaBridgeManagementURLKey, server.URL)
	t.Setenv(openAIQuotaBridgeManagementPasswordFileKey, secret)
	bridge := newOpenAIQuotaBridgeTestAccount(30, server.URL, "bound.json", "bound@example.com")
	s := &OpenAIQuotaService{accountRepo: &stubQuotaAccountRepo{accounts: map[int64]*Account{30: bridge}}}
	raw := map[string]any{"type": "claude", "email": "import@example.com", "refresh_token": "first-token"}
	runtime := &CPACredentialUpdate{Disabled: true, Priority: 7, Weight: 3, RequestRetry: 2}
	result, err := s.ImportCPAAuthFileWithRuntime(context.Background(), raw, runtime)
	require.NoError(t, err)
	require.Equal(t, int64(30), result.BridgeAccountID)
	require.Equal(t, true, metadata["disabled"])
	require.Equal(t, float64(7), metadata["priority"])
	require.Equal(t, float64(2), metadata["request_retry"])
	raw["refresh_token"] = "renewed-token"
	_, err = s.ImportCPAAuthFile(context.Background(), raw)
	require.NoError(t, err)
	require.Equal(t, "renewed-token", metadata["refresh_token"])
	require.Equal(t, true, metadata["disabled"])
	require.Equal(t, float64(3), metadata["weight"])
}
