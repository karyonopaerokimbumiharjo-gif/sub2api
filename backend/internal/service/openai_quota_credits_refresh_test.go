package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCodexCreditsRefreshRunsWithoutAutoResetAndNeverConsumes(t *testing.T) {
	now := time.Now()
	account := creditSchedulingAccount(t, now.Add(-3*time.Minute), `{"rate_limit":{"allowed":true},"credits":{"balance":"12.5"}}`)
	repo := &stubQuotaAccountRepo{accounts: map[int64]*Account{account.ID: account}}
	calls := 0
	svc := &OpenAIQuotaService{accountRepo: repo,
		autoResetQueryUsage: func(ctx context.Context, id int64) (*OpenAIQuotaUsage, error) {
			calls++
			require.Equal(t, account.ID, id)
			deadline, ok := ctx.Deadline()
			require.True(t, ok)
			require.LessOrEqual(t, time.Until(deadline), openaiQuotaUpstreamTimeout)
			balance := "12.4"
			return &OpenAIQuotaUsage{FetchedAt: now.Unix(), Credits: &OpenAICredits{Balance: &balance}, RateLimit: &OpenAIRateLimit{Allowed: true}}, nil
		},
		autoResetResetCredit: func(context.Context, int64) (*OpenAIQuotaResetResult, error) {
			t.Fatal("read-only credit refresh must not consume a reset")
			return nil, nil
		},
	}
	require.False(t, ResolveOpenAIAutoResetCreditConfig(account).Enabled)
	svc.runCreditsRefreshCycle(context.Background(), now)
	require.Equal(t, 1, calls)
	snapshot := readCodexCreditsSnapshot(repo.extraUpdates[account.ID])
	require.NotNil(t, snapshot)
	require.Equal(t, "12.4", *snapshot.Credits.Balance)
	require.NotContains(t, repo.extraUpdates[account.ID], openaiQuotaResetCreditsKey)
	require.Equal(t, StatusActive, account.Status)
	require.True(t, account.Schedulable)
	svc.runCreditsRefreshCycle(context.Background(), now.Add(time.Minute))
	require.Equal(t, 1, calls, "repeated scans are throttled")

	svc.autoResetQueryUsage = func(context.Context, int64) (*OpenAIQuotaUsage, error) {
		calls++
		return nil, errors.New("upstream unavailable")
	}
	before := repo.extraUpdates[account.ID]
	svc.runCreditsRefreshCycle(context.Background(), now.Add(2*time.Minute))
	require.Equal(t, 2, calls)
	require.Equal(t, before, repo.extraUpdates[account.ID], "failure preserves the previous snapshot")
	require.False(t, openAICreditsAllowExhaustedWindow(account, now.Add(3*time.Minute)), "failed refresh cannot extend freshness")
}

func TestCodexCreditsRefreshEligibility(t *testing.T) {
	now := time.Now()
	for _, change := range []func(*Account){
		func(a *Account) { a.Schedulable = false },
		func(a *Account) { a.Status = StatusDisabled },
		func(a *Account) { a.Status = StatusError },
		func(a *Account) { reset := now.Add(time.Hour); a.RateLimitResetAt = &reset },
		func(a *Account) { parent := int64(20); a.ParentAccountID = &parent },
	} {
		account := creditSchedulingAccount(t, now.Add(-3*time.Minute), `{"credits":{"balance":"2"}}`)
		change(account)
		require.False(t, shouldRefreshCodexCredits(account, now))
	}
	fresh := creditSchedulingAccount(t, now, `{"credits":{"balance":"2"}}`)
	require.False(t, shouldRefreshCodexCredits(fresh, now))
	unknown := creditSchedulingAccount(t, now.Add(-3*time.Minute), `{}`)
	require.True(t, shouldRefreshCodexCredits(unknown, now), "exhausted accounts need a first balance read")
	unknown.Extra["codex_5h_used_percent"] = 20.0
	unknown.Extra["codex_7d_used_percent"] = 20.0
	require.False(t, shouldRefreshCodexCredits(unknown, now), "do not poll ordinary accounts without a credit snapshot")
}
