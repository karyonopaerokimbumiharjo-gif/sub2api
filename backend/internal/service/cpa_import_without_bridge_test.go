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

// A deleted business bridge is deliberately absent from the repository. Pool
// management must not recreate it or require it before accepting credentials.
func TestCPAImportWithoutBusinessBridge(t *testing.T) {
	for _, provider := range []string{"codex", "claude", "gemini", "antigravity"} {
		t.Run(provider, func(t *testing.T) {
			var uploaded map[string]any
			var name string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "Bearer synthetic-management-secret", r.Header.Get("Authorization"))
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/v0/management/api-call":
					_, _ = w.Write([]byte(`{"status_code":200,"body":"{}"}`))
				case "/v0/management/auth-files":
					if r.Method == http.MethodPost {
						name = r.URL.Query().Get("name")
						require.NoError(t, json.NewDecoder(r.Body).Decode(&uploaded))
						_, _ = w.Write([]byte(`{"status":"ok"}`))
						return
					}
					files := []any{}
					if uploaded != nil {
						files = append(files, map[string]any{"name": name, "provider": provider, "email": "import@example.invalid", "status": "active", "disabled": false, "id_token": map[string]any{"chatgpt_account_id": "synthetic-account"}})
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"files": files})
				case "/v0/management/auth-files/download":
					_ = json.NewEncoder(w).Encode(uploaded)
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			secret := filepath.Join(t.TempDir(), "secret")
			require.NoError(t, os.WriteFile(secret, []byte("synthetic-management-secret"), 0o600))
			t.Setenv(openAIQuotaBridgeManagementURLKey, server.URL)
			t.Setenv(openAIQuotaBridgeManagementPasswordFileKey, secret)
			repo := &stubQuotaAccountRepo{accounts: map[int64]*Account{}}
			s := &OpenAIQuotaService{accountRepo: repo}
			credentials := map[string]any{"type": provider, "email": "import@example.invalid", "access_token": "synthetic-access", "refresh_token": "synthetic-refresh", "id_token": "synthetic-id", "chatgpt_account_id": "synthetic-account", "expires_at": "2100-01-01T00:00:00Z"}
			runtime := &CPACredentialUpdate{Weight: 1}
			var result *OpenAICPAImportResult
			var err error
			if provider == "codex" {
				result, err = s.ImportOAuthCredentialsToCPAWithRuntime(context.Background(), credentials, runtime)
			} else {
				result, err = s.ImportCPAAuthFileWithRuntime(context.Background(), credentials, runtime)
			}
			require.NoError(t, err)
			require.Zero(t, result.BridgeAccountID)
			require.False(t, result.ReplacedBoundAuth)
			require.NotEmpty(t, result.AuthName)
			require.Equal(t, "synthetic-refresh", uploaded["refresh_token"])
			require.Empty(t, repo.accounts)
			require.Zero(t, repo.extraUpdateCalls)
		})
	}
}

func TestCPAImportWithoutBridgeStillRejectsInvalidCredentials(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "/v0/management/api-call", r.URL.Path, "must not upload rejected credentials")
				_ = json.NewEncoder(w).Encode(map[string]any{"status_code": status, "body": "{}"})
			}))
			defer server.Close()
			secret := filepath.Join(t.TempDir(), "secret")
			require.NoError(t, os.WriteFile(secret, []byte("synthetic-secret"), 0o600))
			t.Setenv(openAIQuotaBridgeManagementURLKey, server.URL)
			t.Setenv(openAIQuotaBridgeManagementPasswordFileKey, secret)
			s := &OpenAIQuotaService{accountRepo: &stubQuotaAccountRepo{accounts: map[int64]*Account{}}}
			_, err := s.ImportOAuthCredentialsToCPA(context.Background(), map[string]any{"email": "import@example.invalid", "access_token": "synthetic-access", "refresh_token": "synthetic-refresh", "id_token": "synthetic-id", "chatgpt_account_id": "synthetic-account", "expires_at": "2100-01-01T00:00:00Z"})
			require.ErrorContains(t, err, "OPENAI_CPA_IMPORT_CREDENTIAL_REJECTED")
		})
	}
}
