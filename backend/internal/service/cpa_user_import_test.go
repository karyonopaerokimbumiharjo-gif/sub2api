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

func TestCPAUserImportDoesNotRestoreUnselectedProxy(t *testing.T) {
	selected := int64(11)
	for _, tc := range []struct {
		name                 string
		existing, userImport bool
		runtime              *CPACredentialUpdate
		wantProxy            string
		wantID               int64
	}{
		{"new omitted runtime", false, true, nil, "", 0},
		{"reimport omitted runtime", true, true, nil, "", 0},
		{"reimport null proxy", true, true, &CPACredentialUpdate{Weight: 1}, "", 0},
		{"reimport selected proxy", true, true, &CPACredentialUpdate{Weight: 1, ProxyID: &selected}, "http://selected-proxy:8080", 11},
		{"internal refresh preserves override", true, false, nil, "http://historical-proxy:8080", 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const email, accountID = "fixture@example.invalid", "fixture-account"
			name := openAICPAAuthFileName(email, accountID)
			var metadata map[string]any
			if tc.existing {
				metadata = map[string]any{"proxy_url": "http://historical-proxy:8080", "sub2_proxy_id": 9, "priority": 7, "weight": 2, "request_retry": 1, "account_id": accountID}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/v0/management/api-call":
					_, _ = w.Write([]byte(`{"status_code":200,"body":"{}"}`))
				case "/v0/management/auth-files/download":
					_ = json.NewEncoder(w).Encode(metadata)
				case "/v0/management/auth-files":
					if r.Method == http.MethodPost {
						require.Equal(t, name, r.URL.Query().Get("name"))
						require.NoError(t, json.NewDecoder(r.Body).Decode(&metadata))
						_, _ = w.Write([]byte(`{"status":"ok"}`))
						return
					}
					files := []any{}
					if metadata != nil {
						files = append(files, map[string]any{"name": name, "id": "fixture-auth", "provider": "codex", "email": email, "status": "active", "disabled": false, "id_token": map[string]any{"chatgpt_account_id": accountID}})
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"files": files})
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			secret := filepath.Join(t.TempDir(), "secret")
			require.NoError(t, os.WriteFile(secret, []byte("fixture-secret"), 0600))
			t.Setenv(openAIQuotaBridgeManagementURLKey, server.URL)
			t.Setenv(openAIQuotaBridgeManagementPasswordFileKey, secret)
			svc := &OpenAIQuotaService{accountRepo: &stubQuotaAccountRepo{accounts: map[int64]*Account{}}, proxyRepo: &cpaRuntimeProxyRepo{proxy: &Proxy{ID: 11, Protocol: "http", Host: "selected-proxy", Port: 8080, Status: StatusActive, FallbackMode: FallbackModeNone}}}
			ctx := context.Background()
			if tc.userImport {
				ctx = WithCPAUserImport(ctx)
			}
			_, err := svc.ImportOAuthCredentialsToCPAWithRuntime(ctx, map[string]any{"access_token": "fixture-access", "refresh_token": "fixture-refresh", "email": email, "chatgpt_account_id": accountID, "expires_at": "2100-01-01T00:00:00Z"}, tc.runtime)
			require.NoError(t, err)
			require.Equal(t, tc.wantProxy, metadata["proxy_url"])
			require.Equal(t, tc.wantID, int64(cpaNumber(metadata, "sub2_proxy_id", 0)))
			require.Equal(t, "fixture-refresh", metadata["refresh_token"])
			if tc.runtime == nil && tc.existing {
				require.Equal(t, float64(7), metadata["priority"], "proxy default must not reset unrelated runtime settings")
			}
		})
	}
}
