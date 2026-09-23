package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

type piAliasRepoStub struct{ accounts map[int64]*Account }

func (r *piAliasRepoStub) GetByID(_ context.Context, id int64) (*Account, error) { return r.accounts[id], nil }

func TestResolveNativePiRuntimeAccountUsesOwnerForSharedAlias(t *testing.T) {
	owner := &Account{ID: 46, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Credentials: map[string]any{
		"harness_kind": "pi", "pi_owner_user_id": "1", "chatgpt_account_id": "acct-1",
		"access_token": "access", "refresh_token": "refresh",
	}}
	alias := &Account{ID: 44, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Credentials: map[string]any{
		"harness_kind": "pi_shared", "pi_owner_user_id": "1", "pi_runtime_account_id": "46", "chatgpt_account_id": "acct-1",
	}}
	resolved, err := ResolveNativePiRuntimeAccount(context.Background(), &piAliasRepoStub{accounts: map[int64]*Account{46: owner}}, alias)
	require.NoError(t, err)
	require.Same(t, owner, resolved)
	require.NoError(t, ValidateExecutionAccount(alias))
}

func TestResolveNativePiRuntimeAccountRejectsIdentityMismatch(t *testing.T) {
	owner := &Account{ID: 46, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Credentials: map[string]any{
		"harness_kind": "pi", "pi_owner_user_id": "1", "chatgpt_account_id": "acct-owner",
		"access_token": "access", "refresh_token": "refresh",
	}}
	alias := &Account{ID: 44, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Credentials: map[string]any{
		"harness_kind": "pi_shared", "pi_owner_user_id": "1", "pi_runtime_account_id": "46", "chatgpt_account_id": "acct-other",
	}}
	_, err := ResolveNativePiRuntimeAccount(context.Background(), &piAliasRepoStub{accounts: map[int64]*Account{46: owner}}, alias)
	require.Error(t, err)
}
