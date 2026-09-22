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

type cpaAccountSyncRepo struct {
	AccountRepository
	accounts map[int64]*Account
	created  int
	updated  int
}

func (r *cpaAccountSyncRepo) FindByExtraField(_ context.Context, key string, value any) ([]Account, error) {
	var found []Account
	for _, account := range r.accounts {
		if account.Extra[key] == value {
			found = append(found, *account)
		}
	}
	return found, nil
}

func (r *cpaAccountSyncRepo) Create(_ context.Context, account *Account) error {
	r.created++
	account.ID = int64(r.created + 100)
	r.accounts[account.ID] = account
	return nil
}

func (r *cpaAccountSyncRepo) UpdateExtra(_ context.Context, id int64, updates map[string]any) error {
	r.updated++
	for key, value := range updates {
		r.accounts[id].Extra[key] = value
	}
	return nil
}

func cpaAccountSyncTestServer(t *testing.T, authID, accountID *string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v0/management/auth-files":
			_ = json.NewEncoder(w).Encode(map[string]any{"files": []any{map[string]any{
				"id": *authID, "name": "one.json", "provider": "codex", "email": "one@example.com",
				"id_token": map[string]any{"chatgpt_account_id": *accountID},
			}}})
		case "/v0/management/auth-files/download":
			require.Equal(t, "one.json", r.URL.Query().Get("name"))
			_, _ = w.Write([]byte(`{"account_id":"` + *accountID + `"}`))
		case "/v0/management/api-keys":
			_, _ = w.Write([]byte(`{"api-keys":["test-cpa-key"]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	secret := filepath.Join(t.TempDir(), "cpa-management-secret")
	require.NoError(t, os.WriteFile(secret, []byte("test-secret"), 0o600))
	t.Setenv(openAIQuotaBridgeManagementURLKey, server.URL)
	t.Setenv(openAIQuotaBridgeManagementPasswordFileKey, secret)
	return server
}

func TestSyncCPAAccountsCreatesDisabledAccountAndReusesExactBinding(t *testing.T) {
	authID, accountID := "auth-1", "workspace-1"
	server := cpaAccountSyncTestServer(t, &authID, &accountID)
	defer server.Close()
	repo := &cpaAccountSyncRepo{accounts: map[int64]*Account{}}
	svc := &OpenAIQuotaService{accountRepo: repo}

	first, err := svc.SyncCPAAccounts(context.Background(), []string{"one.json"})
	require.NoError(t, err)
	require.Equal(t, &CPAAccountSyncResult{Created: 1, Identities: 1}, first)
	require.Len(t, repo.accounts, 1)
	account := repo.accounts[101]
	require.Equal(t, StatusDisabled, account.Status)
	require.False(t, account.Schedulable)
	require.Empty(t, account.GroupIDs)
	require.Equal(t, cpapolicy.BaseURL, account.GetCredential("base_url"))
	require.Equal(t, "test-cpa-key", account.GetOpenAIApiKey())
	require.Equal(t, "auth-1", account.GetExtraString("cpa_auth_id"))
	require.True(t, account.IsOpenAICompatibleQuotaBridge())

	second, err := svc.SyncCPAAccounts(context.Background(), []string{"one.json", "one.json"})
	require.NoError(t, err)
	require.Equal(t, &CPAAccountSyncResult{Updated: 1, Identities: 1}, second)
	require.Equal(t, 1, repo.created)
	require.Equal(t, 0, repo.updated, "identical binding needs no database write")

	account.Status, account.Schedulable, account.GroupIDs = StatusActive, true, []int64{7, 9}
	accountID = "workspace-2" // Same exact auth ID wins despite an improved identity claim.
	third, err := svc.SyncCPAAccounts(context.Background(), []string{"one.json"})
	require.NoError(t, err)
	require.Equal(t, &CPAAccountSyncResult{Updated: 1, Identities: 1}, third)
	require.Equal(t, 1, repo.created)
	require.Equal(t, 1, repo.updated)
	require.Equal(t, StatusActive, account.Status)
	require.True(t, account.Schedulable)
	require.Equal(t, []int64{7, 9}, account.GroupIDs)
}

func TestSyncCPAAccountsRebindsSameIdentityWithoutChangingAccountSettings(t *testing.T) {
	authID, accountID := "auth-1", "workspace-1"
	server := cpaAccountSyncTestServer(t, &authID, &accountID)
	defer server.Close()
	repo := &cpaAccountSyncRepo{accounts: map[int64]*Account{}}
	svc := &OpenAIQuotaService{accountRepo: repo}
	_, err := svc.SyncCPAAccounts(context.Background(), []string{"one.json"})
	require.NoError(t, err)
	account := repo.accounts[101]
	account.GroupIDs = []int64{42}
	account.Schedulable = true
	authID = "auth-2" // CPA replaced the file but retained the workspace.
	result, err := svc.SyncCPAAccounts(context.Background(), []string{"one.json"})
	require.NoError(t, err)
	require.Equal(t, &CPAAccountSyncResult{Updated: 1, Identities: 1}, result)
	require.Equal(t, "auth-2", account.GetExtraString("cpa_auth_id"))
	require.Equal(t, StatusDisabled, account.Status)
	require.True(t, account.Schedulable)
	require.Equal(t, []int64{42}, account.GroupIDs)
	require.Equal(t, 1, repo.created)
}

func TestSyncCPAAccountsRejectsAuthIDIdentityConflictBeforeWriting(t *testing.T) {
	authID, accountID := "auth-1", "workspace-1"
	server := cpaAccountSyncTestServer(t, &authID, &accountID)
	defer server.Close()
	repo := &cpaAccountSyncRepo{accounts: map[int64]*Account{}}
	svc := &OpenAIQuotaService{accountRepo: repo}
	_, err := svc.SyncCPAAccounts(context.Background(), []string{"one.json"})
	require.NoError(t, err)
	identity := repo.accounts[101].GetExtraString("cpa_identity")
	accountID = "workspace-2"
	_, err = svc.SyncCPAAccounts(context.Background(), []string{"one.json"})
	require.NoError(t, err)
	// The old identity is now claimed by a different row while the same auth ID
	// still belongs to account 101. Neither business account may be changed.
	accountID = "workspace-1"
	repo.accounts[102] = &Account{ID: 102, Platform: PlatformOpenAI, Type: AccountTypeAPIKey,
		Credentials: map[string]any{"base_url": cpapolicy.BaseURL, "api_key": "other-key"},
		Extra:       map[string]any{"cpa_identity": identity}}
	writes := repo.updated
	_, err = svc.SyncCPAAccounts(context.Background(), []string{"one.json"})
	require.ErrorContains(t, err, "绑定存在冲突")
	require.Equal(t, writes, repo.updated)
	require.Equal(t, 1, repo.created)
}

func TestSyncCPAAccountsRejectsLegacySharedBridgeAndDuplicateAuthID(t *testing.T) {
	authID, accountID := "auth-1", "workspace-1"
	server := cpaAccountSyncTestServer(t, &authID, &accountID)
	defer server.Close()
	for _, existing := range []map[int64]*Account{
		{30: {ID: 30, Extra: map[string]any{OpenAIQuotaBridgeAuthNameExtraKey: "one.json"}}},
		{
			40: {ID: 40, Extra: map[string]any{"cpa_auth_id": "auth-1"}},
			43: {ID: 43, Extra: map[string]any{"cpa_auth_id": "auth-1"}},
		},
	} {
		repo := &cpaAccountSyncRepo{accounts: existing}
		svc := &OpenAIQuotaService{accountRepo: repo}
		_, err := svc.SyncCPAAccounts(context.Background(), []string{"one.json"})
		require.ErrorContains(t, err, "核对", "ambiguous legacy bindings must not be guessed")
		require.Zero(t, repo.created)
		require.Zero(t, repo.updated)
	}
}
