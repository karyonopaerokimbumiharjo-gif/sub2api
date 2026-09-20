package service

import (
	"context"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/stretchr/testify/require"
)

type internalPoolAccountRepo struct {
	AccountRepository
	accounts []Account
}

func TestGatewayInternalAccountSelectionUsesGroupedPoolAndExclusions(t *testing.T) {
	older := time.Now().Add(-time.Hour)
	newer := time.Now()
	repo := &internalPoolAccountRepo{accounts: []Account{
		{ID: 21, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Status: StatusActive, Schedulable: true, Priority: 1,
			LastUsedAt: &newer, AccountGroups: []AccountGroup{{GroupID: 5}}, Credentials: map[string]any{
				"model_mapping": map[string]any{"gpt-5.3-codex-spark": "gpt-5.3-codex-spark"},
			}},
		{ID: 22, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Status: StatusActive, Schedulable: true, Priority: 1,
			LastUsedAt: &older, AccountGroups: []AccountGroup{{GroupID: 6}}, Credentials: map[string]any{
				"model_mapping": map[string]any{"gpt-5.3-codex-spark": "gpt-5.3-codex-spark"},
			}},
	}}
	svc := &GatewayService{accountRepo: repo, cfg: &config.Config{RunMode: config.RunModeStandard}}

	selected, err := svc.SelectInternalAccountForModelWithExclusions(
		context.Background(), PlatformOpenAI, "gpt-5.3-codex-spark", map[int64]struct{}{22: {}},
	)
	require.NoError(t, err)
	require.Equal(t, int64(21), selected.ID)
}

func (r *internalPoolAccountRepo) ListSchedulableByPlatform(_ context.Context, platform string) ([]Account, error) {
	result := make([]Account, 0, len(r.accounts))
	for _, account := range r.accounts {
		if account.Platform == platform && account.IsSchedulable() {
			result = append(result, account)
		}
	}
	return result, nil
}

func (r *internalPoolAccountRepo) ListSchedulableUngroupedByPlatform(_ context.Context, platform string) ([]Account, error) {
	result := make([]Account, 0, len(r.accounts))
	for _, account := range r.accounts {
		if account.Platform == platform && account.IsSchedulable() && len(account.AccountGroups) == 0 {
			result = append(result, account)
		}
	}
	return result, nil
}

func TestGatewayInternalAccountPoolBypassesOnlyGroupMembership(t *testing.T) {
	repo := &internalPoolAccountRepo{accounts: []Account{
		{ID: 22, Platform: PlatformAntigravity, Status: StatusActive, Schedulable: true,
			AccountGroups: []AccountGroup{{GroupID: 5}}},
	}}
	svc := &GatewayService{
		accountRepo: repo,
		cfg:         &config.Config{RunMode: config.RunModeStandard},
	}

	forcedCtx := context.WithValue(context.Background(), ctxkey.ForcePlatform, PlatformAntigravity)
	ordinary, _, err := svc.listSchedulableAccounts(forcedCtx, nil, PlatformAntigravity, true)
	require.NoError(t, err)
	require.Empty(t, ordinary, "ordinary requests must keep group isolation")

	internalCtx := context.WithValue(forcedCtx, ctxkey.InternalAccountPool, true)
	svc.schedulerSnapshot = &SchedulerSnapshotService{}
	internal, _, err := svc.listSchedulableAccounts(internalCtx, nil, PlatformAntigravity, true)
	require.NoError(t, err)
	require.Len(t, internal, 1)
	require.Equal(t, int64(22), internal[0].ID)
}

func TestGatewayInternalAccountPoolRequiresForcedPlatform(t *testing.T) {
	repo := &internalPoolAccountRepo{accounts: []Account{
		{ID: 22, Platform: PlatformAntigravity, Status: StatusActive, Schedulable: true,
			AccountGroups: []AccountGroup{{GroupID: 5}}},
	}}
	svc := &GatewayService{
		accountRepo: repo,
		cfg:         &config.Config{RunMode: config.RunModeStandard},
	}

	ctx := context.WithValue(context.Background(), ctxkey.InternalAccountPool, true)
	selected, _, err := svc.listSchedulableAccounts(ctx, nil, PlatformAntigravity, false)
	require.NoError(t, err)
	require.Empty(t, selected, "internal pool must not bypass isolation without a forced platform")
}
