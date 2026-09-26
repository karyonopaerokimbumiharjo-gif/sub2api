package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func identityTestToken(t *testing.T, user, workspace, email string) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"sub": user, "email": email, "https://api.openai.com/auth": map[string]any{"chatgpt_account_id": workspace, "chatgpt_user_id": user}})
	require.NoError(t, err)
	return "e30." + base64.RawURLEncoding.EncodeToString(raw) + ".fixture"
}

func TestOAuthIdentitySeparatesTeamMembers(t *testing.T) {
	one := map[string]any{"chatgpt_account_id": "team", "access_token": identityTestToken(t, "member-one", "team", "one@example.com")}
	two := map[string]any{"chatgpt_account_id": "team", "access_token": identityTestToken(t, "member-two", "team", "two@example.com")}
	require.False(t, SameOpenAIOAuthIdentity(one, two))
	require.NotEqual(t, OpenAIOAuthPrincipal(one), OpenAIOAuthPrincipal(two))
	refreshed := map[string]any{"chatgpt_account_id": "team", "access_token": identityTestToken(t, "member-one", "team", "renamed@example.com")}
	require.True(t, SameOpenAIOAuthIdentity(one, refreshed))
	// A copied display field cannot override the principal inside the token.
	two["chatgpt_user_id"] = "member-one"
	require.False(t, SameOpenAIOAuthIdentity(one, two))
}

func TestSyncCPAAccountsKeepsDifferentTeamLoginsAsSeparateAccounts(t *testing.T) {
	files := []openAIQuotaBridgeAuthFile{
		{ID: "auth-one", Name: "one.json", Provider: "codex", Email: "one@example.com"},
		{ID: "auth-two", Name: "two.json", Provider: "codex", Email: "two@example.com"},
	}
	metadata := map[string]map[string]any{}
	for i, file := range files {
		metadata[file.Name] = map[string]any{"account_id": "shared-team", "email": file.Email, "access_token": identityTestToken(t, []string{"member-one", "member-two"}[i], "shared-team", file.Email), "refresh_token": "fixture-refresh", "expired": "2100-01-01T00:00:00Z"}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v0/management/auth-files":
			_ = json.NewEncoder(w).Encode(map[string]any{"files": files})
		case "/v0/management/auth-files/download":
			_ = json.NewEncoder(w).Encode(metadata[r.URL.Query().Get("name")])
		case "/v0/management/api-keys":
			_, _ = w.Write([]byte(`{"api-keys":["test-cpa-key"]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	secret := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(secret, []byte("fixture-management"), 0o600))
	t.Setenv(openAIQuotaBridgeManagementURLKey, server.URL)
	t.Setenv(openAIQuotaBridgeManagementPasswordFileKey, secret)
	repo := &cpaAccountSyncRepo{accounts: map[int64]*Account{}}
	svc := &OpenAIQuotaService{accountRepo: repo}
	one, err := svc.SyncCPAAccounts(context.Background(), []string{"one.json"})
	require.NoError(t, err)
	repo.accounts[one.AccountIDs[0]].Concurrency = 7
	// Reproduce the production state: the first team member already uses Pi.
	owner := repo.accounts[one.AccountIDs[0]]
	owner.Type = AccountTypeOAuth
	owner.Credentials = shallowCopyMap(metadata["one.json"])
	owner.Credentials["chatgpt_account_id"] = "shared-team"
	owner.Credentials["harness_kind"] = PiNativeHarnessKind
	owner.Credentials["pi_owner_user_id"] = "1"
	// Existing installations used the workspace-only identity key.
	repo.accounts[one.AccountIDs[0]].Extra["cpa_identity"] = cpaSettings(files[0], metadata[files[0].Name]).LegacyIdentity
	delete(repo.accounts[one.AccountIDs[0]].Extra, "cpa_principal")
	delete(repo.accounts[one.AccountIDs[0]].Extra, "cpa_workspace_id")
	two, err := svc.SyncCPAAccounts(WithCPAImportAccountDefaults(context.Background(), CPAImportAccountDefaults{Concurrency: 4, Priority: 2}), []string{"two.json"})
	require.NoError(t, err)
	require.NotEqual(t, one.AccountIDs, two.AccountIDs)
	require.Len(t, repo.accounts, 2)
	require.Equal(t, 4, repo.accounts[two.AccountIDs[0]].Concurrency)
	require.Equal(t, 2, repo.accounts[two.AccountIDs[0]].Priority)
	require.NotEqual(t, repo.accounts[101].GetExtraString("cpa_identity"), repo.accounts[102].GetExtraString("cpa_identity"))
	again, err := svc.SyncCPAAccounts(context.Background(), []string{"one.json", "two.json"})
	require.NoError(t, err)
	require.Zero(t, again.Created)
	require.Len(t, repo.accounts, 2)
	require.Equal(t, 7, repo.accounts[101].Concurrency)
	require.True(t, repo.accounts[101].UsesNativePiRuntime())
}

func TestPiReimportRejectsAnotherMemberOfSameTeam(t *testing.T) {
	account := &Account{ID: 51, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Credentials: map[string]any{"harness_kind": "pi", "pi_owner_user_id": "1", "chatgpt_account_id": "team", "access_token": identityTestToken(t, "first", "team", "first@example.com"), "refresh_token": "first-refresh"}}
	svc := &OpenAIQuotaService{}
	_, _, err := svc.preparePiReimport(context.Background(), account, map[string]any{"account_id": "team", "email": "second@example.com", "access_token": identityTestToken(t, "second", "team", "second@example.com"), "refresh_token": "second-refresh", "expired": "2100-01-01T00:00:00Z"})
	require.ErrorContains(t, err, "另一位用户")
	require.Equal(t, "first-refresh", account.GetCredential("refresh_token"))
}
