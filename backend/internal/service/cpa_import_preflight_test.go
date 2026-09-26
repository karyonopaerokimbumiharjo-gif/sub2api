package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCPAImportPreflightRetriesTransientReadOnlyFailure(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		require.Equal(t, "/v0/management/api-call", r.URL.Path)
		if attempts == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status_code": 200, "body": "{}"})
	}))
	defer server.Close()
	err := preflightCPAImport(context.Background(), openAIQuotaBridgeConfig{managementURL: server.URL, secret: "synthetic"}, "synthetic", "synthetic-account", "")
	require.NoError(t, err)
	require.Equal(t, 2, attempts)
}

func TestCPAImportPreflightUsesSelectedProxyAndNeverUploadsRejectedCredential(t *testing.T) {
	var observed map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v0/management/api-call", r.URL.Path, "a rejected preflight must not upload credentials")
		require.NoError(t, json.NewDecoder(r.Body).Decode(&observed))
		_ = json.NewEncoder(w).Encode(map[string]any{"status_code": http.StatusUnauthorized, "body": "{}"})
	}))
	defer server.Close()
	secret := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(secret, []byte("test-secret"), 0o600))
	t.Setenv(openAIQuotaBridgeManagementURLKey, server.URL)
	t.Setenv(openAIQuotaBridgeManagementPasswordFileKey, secret)
	proxy := &Proxy{ID: 9, Protocol: "http", Host: "selected-proxy", Port: 8080, Status: StatusActive, FallbackMode: FallbackModeNone}
	service := &OpenAIQuotaService{accountRepo: &stubQuotaAccountRepo{accounts: map[int64]*Account{}}, proxyRepo: &cpaRuntimeProxyRepo{proxy: proxy}}
	id := int64(9)
	_, err := service.ImportOAuthCredentialsToCPAWithRuntime(context.Background(), map[string]any{"email": "test@example.invalid", "access_token": "synthetic-access", "refresh_token": "synthetic-refresh", "chatgpt_account_id": "synthetic-account", "expires_at": "2100-01-01T00:00:00Z"}, &CPACredentialUpdate{ProxyID: &id, Weight: 1})
	require.ErrorContains(t, err, "OPENAI_CPA_IMPORT_CREDENTIAL_REJECTED")
	require.Equal(t, "http://selected-proxy:8080", observed["proxy_url"])
}
