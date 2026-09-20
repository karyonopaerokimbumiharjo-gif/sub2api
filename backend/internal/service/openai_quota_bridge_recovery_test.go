package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/cpapolicy"
	"github.com/stretchr/testify/require"
)

// Match the real repository's active-only ListByPlatform semantics. Import
// must not use this runtime lookup, while audit must continue to use it.
type cpaRecoveryAccountRepo struct {
	*stubQuotaAccountRepo
}

func (r *cpaRecoveryAccountRepo) ListByPlatform(_ context.Context, platform string) ([]Account, error) {
	var accounts []Account
	for _, account := range r.accounts {
		if account != nil && account.Platform == platform && account.Status == StatusActive {
			accounts = append(accounts, *account)
		}
	}
	return accounts, nil
}

func TestImportOAuthCredentialsToCPAWithUnavailableBridgePreservesScheduling(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status string
	}{
		{name: "authentication_error", status: StatusError},
		{name: "disabled", status: StatusDisabled},
		{name: "manually_paused", status: StatusActive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const authName = "bound.json"
			var uploads int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "Bearer test-management-secret", r.Header.Get("Authorization"))
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/v0/management/api-call":
					_, _ = w.Write([]byte(`{"status_code":200,"body":"{}"}`))
				case "/v0/management/auth-files":
					require.Equal(t, authName, r.URL.Query().Get("name"))
					if r.Method == http.MethodPost {
						var payload map[string]any
						require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
						require.Equal(t, "new-access-token", payload["access_token"])
						uploads++
						_, _ = w.Write([]byte(`{"status":"ok"}`))
						return
					}
					_, _ = w.Write([]byte(`{"files":[{"name":"bound.json","provider":"codex","email":"bound@example.com","status":"active","disabled":false,"unavailable":false,"id_token":{"chatgpt_account_id":"bound-id"}}]}`))
				case "/v0/management/auth-files/download":
					_, _ = w.Write([]byte(`{"disabled":false}`))
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			secretFile := filepath.Join(t.TempDir(), "management-password")
			require.NoError(t, os.WriteFile(secretFile, []byte("test-management-secret"), 0o600))
			t.Setenv(openAIQuotaBridgeManagementURLKey, server.URL)
			t.Setenv(openAIQuotaBridgeManagementPasswordFileKey, secretFile)

			bridge := newOpenAIQuotaBridgeTestAccount(30, server.URL, authName, "bound@example.com")
			bridge.Status = tc.status
			bridge.Schedulable = false
			bridge.ErrorMessage = "previous authentication failure"
			repo := &cpaRecoveryAccountRepo{&stubQuotaAccountRepo{accounts: map[int64]*Account{30: bridge}}}
			quotaService := &OpenAIQuotaService{accountRepo: repo}
			result, err := quotaService.ImportOAuthCredentialsToCPA(context.Background(), map[string]any{
				"access_token": "new-access-token", "refresh_token": "new-refresh-token", "id_token": "new-id-token",
				"email": "bound@example.com", "chatgpt_account_id": "bound-id", "expires_at": float64(4_102_444_800),
			})
			require.NoError(t, err)
			require.Equal(t, int64(30), result.BridgeAccountID)
			require.True(t, result.ReplacedBoundAuth)
			require.Equal(t, 1, uploads)
			require.Equal(t, tc.status, bridge.Status)
			require.False(t, bridge.Schedulable)
			require.Equal(t, "previous authentication failure", bridge.ErrorMessage)

			// Use the valid private CPA origin for scheduling assertions, so they
			// cannot pass merely because the httptest origin is rejected.
			bridge.Credentials["base_url"] = cpapolicy.BaseURL
			t.Setenv(openAIQuotaBridgeManagementURLKey, cpapolicy.BaseURL)
			require.False(t, bridge.IsSchedulable())
			gateway := &GatewayService{accountRepo: repo}
			selected, auditErr := gateway.FindCPABridgeForAudit(context.Background(), cpapolicy.BaseURL)
			require.ErrorIs(t, auditErr, ErrNoAvailableAccounts)
			require.Nil(t, selected)

			healthy := *bridge
			healthy.Status = StatusActive
			healthy.Schedulable = true
			repo.accounts[30] = &healthy
			selected, auditErr = gateway.FindCPABridgeForAudit(context.Background(), cpapolicy.BaseURL)
			require.NoError(t, auditErr)
			require.Equal(t, int64(30), selected.ID)
		})
	}
}

func TestFindOpenAIQuotaBridgeIncludesUnavailableBridgeInUniquenessCheck(t *testing.T) {
	const baseURL = "http://cpa:8317"
	active := newOpenAIQuotaBridgeTestAccount(30, baseURL, "active.json", "active@example.com")
	failed := newOpenAIQuotaBridgeTestAccount(31, baseURL, "failed.json", "failed@example.com")
	failed.Status = StatusError
	failed.Schedulable = false
	service := &OpenAIQuotaService{accountRepo: &cpaRecoveryAccountRepo{&stubQuotaAccountRepo{
		accounts: map[int64]*Account{30: active, 31: failed},
	}}}
	bridge, err := service.findOpenAIQuotaBridge(context.Background(), baseURL)
	// Reauthorization must not silently pick the active bridge while another
	// configured bridge with the same origin is hidden in the error state.
	require.ErrorContains(t, err, "more than one CPA bridge account")
	require.Nil(t, bridge)
}
