package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type cpaReimportTokenCache struct {
	OpenAITokenCache
	locked  bool
	deleted []string
}

func (c *cpaReimportTokenCache) AcquireRefreshLock(context.Context, string, time.Duration) (bool, error) {
	return c.locked, nil
}
func (c *cpaReimportTokenCache) ReleaseRefreshLock(context.Context, string) error { return nil }
func (c *cpaReimportTokenCache) DeleteAccessToken(_ context.Context, key string) error {
	c.deleted = append(c.deleted, key)
	return nil
}

func TestSyncCPAAccountsReimportsExistingPiWithoutChangingBackend(t *testing.T) {
	authID, accountID := "auth-pi", "workspace-pi"
	server := cpaAccountSyncTestServer(t, &authID, &accountID)
	defer server.Close()
	account := &Account{
		ID: 50, Platform: PlatformOpenAI, Type: AccountTypeOAuth,
		Credentials: map[string]any{
			"harness_kind": PiNativeHarnessKind, "pi_owner_user_id": "1", "pi_transport": "sse",
			"chatgpt_account_id": accountID, "access_token": "old-access", "refresh_token": "old-refresh",
			"cpa_bridge_api_key": "saved-bridge", "model_mapping": map[string]any{"client": "upstream"},
		},
		Extra:       map[string]any{"cpa_auth_id": authID, OpenAIQuotaBridgeAuthNameExtraKey: "one.json"},
		Concurrency: 7, Priority: 3, Status: StatusActive, Schedulable: true, GroupIDs: []int64{42},
	}
	repo := &cpaAccountSyncRepo{accounts: map[int64]*Account{50: account}}
	cache := &cpaReimportTokenCache{locked: true}
	svc := &OpenAIQuotaService{accountRepo: repo, tokenProvider: &OpenAITokenProvider{tokenCache: cache}}
	for attempt := 0; attempt < 2; attempt++ {
		result, err := svc.SyncCPAAccounts(context.Background(), []string{"one.json"})
		require.NoError(t, err)
		require.Equal(t, []int64{50}, result.AccountIDs)
		require.Zero(t, result.Created)
		require.Equal(t, 1, result.Updated)
	}
	require.Len(t, repo.accounts, 1)
	require.Equal(t, "updated-access", account.GetCredential("access_token"))
	require.Equal(t, "updated-refresh", account.GetCredential("refresh_token"))
	require.Equal(t, "2100-01-01T00:00:00Z", account.GetCredential("expires_at"))
	require.True(t, account.UsesNativePiRuntime())
	require.Equal(t, "1", account.GetCredential("pi_owner_user_id"))
	require.Equal(t, "saved-bridge", account.GetCredential("cpa_bridge_api_key"))
	require.NotContains(t, account.Credentials, "proxy_url")
	require.NotContains(t, account.Credentials, "base_url")
	require.Equal(t, 7, account.Concurrency)
	require.Equal(t, 3, account.Priority)
	require.Equal(t, StatusActive, account.Status)
	require.True(t, account.Schedulable)
	require.Equal(t, []int64{42}, account.GroupIDs)
	require.Equal(t, []string{OpenAITokenCacheKey(account), OpenAITokenCacheKey(account)}, cache.deleted)
}

func TestSyncCPAAccountsPiAliasUpdatesOnlyRuntimeOwner(t *testing.T) {
	authID, accountID := "auth-alias", "workspace-pi"
	server := cpaAccountSyncTestServer(t, &authID, &accountID)
	defer server.Close()
	owner := &Account{ID: 50, Platform: PlatformOpenAI, Type: AccountTypeOAuth,
		Credentials: map[string]any{"harness_kind": PiNativeHarnessKind, "pi_owner_user_id": "1", "chatgpt_account_id": accountID,
			"access_token": "old-access", "refresh_token": "old-refresh"}, Extra: map[string]any{}}
	alias := &Account{ID: 51, Platform: PlatformOpenAI, Type: AccountTypeOAuth,
		Credentials: map[string]any{"harness_kind": PiSharedHarnessKind, "pi_owner_user_id": "1", "chatgpt_account_id": accountID, PiRuntimeAccountIDCredential: "50"},
		Extra:       map[string]any{"cpa_auth_id": authID}}
	repo := &cpaAccountSyncRepo{accounts: map[int64]*Account{50: owner, 51: alias}}
	cache := &cpaReimportTokenCache{locked: false}
	svc := &OpenAIQuotaService{accountRepo: repo, tokenProvider: &OpenAITokenProvider{tokenCache: cache}}
	_, err := svc.SyncCPAAccounts(context.Background(), []string{"one.json"})
	require.ErrorContains(t, err, "账号正在更新授权")
	require.Equal(t, "old-access", owner.GetCredential("access_token"))
	require.Zero(t, repo.updated)
	cache.locked = true
	result, err := svc.SyncCPAAccounts(context.Background(), []string{"one.json"})
	require.NoError(t, err)
	require.Equal(t, []int64{51}, result.AccountIDs)
	require.Equal(t, "updated-access", owner.GetCredential("access_token"))
	require.NotContains(t, alias.Credentials, "access_token")
	require.NotContains(t, alias.Credentials, "refresh_token")
	require.Equal(t, PiSharedHarnessKind, alias.GetCredential("harness_kind"))
	require.Equal(t, []string{OpenAITokenCacheKey(owner)}, cache.deleted)
}

func TestSyncCPAAccountsDoesNotReplacePiWithAnotherIdentity(t *testing.T) {
	authID, accountID := "auth-pi", "different-workspace"
	server := cpaAccountSyncTestServer(t, &authID, &accountID)
	defer server.Close()
	account := &Account{ID: 50, Platform: PlatformOpenAI, Type: AccountTypeOAuth,
		Credentials: map[string]any{"harness_kind": PiNativeHarnessKind, "pi_owner_user_id": "1",
			"chatgpt_account_id": "original-workspace", "access_token": "old-access", "refresh_token": "old-refresh"},
		Extra: map[string]any{"cpa_auth_id": authID},
	}
	repo := &cpaAccountSyncRepo{accounts: map[int64]*Account{50: account}}
	_, err := (&OpenAIQuotaService{accountRepo: repo}).SyncCPAAccounts(context.Background(), []string{"one.json"})
	require.Error(t, err)
	require.Equal(t, "old-access", account.GetCredential("access_token"))
	require.Zero(t, repo.updated)
	require.Zero(t, repo.created)
}
