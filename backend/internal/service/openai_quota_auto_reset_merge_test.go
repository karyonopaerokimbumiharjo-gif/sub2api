package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpenAIAutoResetMerge_LegacyWorkerHasExclusiveOwnership(t *testing.T) {
	account := &Account{ID: 99, Platform: PlatformOpenAI, Type: AccountTypeOAuth,
		Status: StatusActive, Schedulable: true,
		Extra: map[string]any{
			OpenAIAutoResetCreditEnabledExtraKey: true,
			openAIQuotaAutoResetEnabledKey:       true,
			"codex_5h_used_percent":              100.0,
		},
	}
	require.False(t, ResolveOpenAIAutoResetCreditConfig(account).Enabled)
	// Deliberately omit the quota dependency: evaluation must exit before any
	// query or credit consumption while the existing worker owns this account.
	svc := &OpenAIQuotaAutoResetService{accountRepo: &autoResetTestAccountRepo{account: account}}
	require.NoError(t, svc.evaluateAccount(context.Background(), account.ID))
	account.Extra[openAIQuotaAutoResetEnabledKey] = false
	require.True(t, ResolveOpenAIAutoResetCreditConfig(account).Enabled)
}
