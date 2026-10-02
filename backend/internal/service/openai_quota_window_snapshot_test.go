package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type quotaUsageQueryStub struct {
	usage *OpenAIQuotaUsage
	err   error
	ids   []int64
}

func (s *quotaUsageQueryStub) QueryUsage(_ context.Context, id int64) (*OpenAIQuotaUsage, error) {
	s.ids = append(s.ids, id)
	return s.usage, s.err
}

func TestQuotaBodySnapshotClearsMissingAndMapsRealDurations(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	limit := &OpenAIRateLimit{PrimaryWindow: &OpenAIRateLimitWindow{UsedPercent: 66, LimitWindowSeconds: 604800, ResetAt: now.Add(time.Hour).Unix()}}
	updates := buildCodexQuotaWindowExtraUpdates(limit, now)
	require.Nil(t, updates["codex_5h_used_percent"])
	require.Equal(t, 66.0, updates["codex_7d_used_percent"])
	require.Equal(t, 3600, updates["codex_7d_reset_after_seconds"])
	usage := &UsageInfo{FiveHour: &UsageProgress{Utilization: 42}}
	applyExtraToUsage(usage, updates, now)
	require.Nil(t, usage.FiveHour)
	require.Equal(t, 66.0, usage.SevenDay.Utilization)
	limit.SecondaryWindow = &OpenAIRateLimitWindow{UsedPercent: 3, LimitWindowSeconds: 18000, ResetAfterSeconds: 600}
	updates = buildCodexQuotaWindowExtraUpdates(limit, now)
	require.Equal(t, 3.0, updates["codex_5h_used_percent"])
	limit.SecondaryWindow.LimitWindowSeconds = 86400
	require.Nil(t, buildCodexQuotaWindowExtraUpdates(limit, now)["codex_5h_used_percent"])
	limit.PrimaryWindow.ResetAt = 0
	limit.PrimaryWindow.ResetAfterSeconds = 0
	updates = buildCodexQuotaWindowExtraUpdates(limit, now)
	applyExtraToUsage(usage, updates, now)
	require.Equal(t, 66.0, usage.SevenDay.Utilization)
	require.Nil(t, usage.SevenDay.ResetsAt)
}

func TestCompatibleUsageQueryUsesBoundQuotaServiceAndReplacesOldSnapshot(t *testing.T) {
	now := time.Now()
	account := newOpenAIQuotaBridgeTestAccount(30, "http://unreachable.invalid", "auth.json", "owner@example.test")
	account.Extra["codex_5h_used_percent"] = 0.0
	account.Extra["codex_7d_used_percent"] = 11.0
	account.Extra["codex_usage_updated_at"] = now.Add(-5 * 24 * time.Hour).Format(time.RFC3339)
	query := &quotaUsageQueryStub{usage: &OpenAIQuotaUsage{RateLimit: &OpenAIRateLimit{PrimaryWindow: &OpenAIRateLimitWindow{UsedPercent: 66, LimitWindowSeconds: 604800, ResetAfterSeconds: 7200}}}}
	svc := &AccountUsageService{openAIQuotaService: query}
	usage, err := svc.getOpenAIUsage(context.Background(), account, true)
	require.NoError(t, err)
	require.Equal(t, []int64{30}, query.ids)
	require.Empty(t, usage.Error)
	require.Nil(t, usage.FiveHour)
	require.Equal(t, 66.0, usage.SevenDay.Utilization)
	require.NotNil(t, usage.QuotaUpdatedAt)
	require.WithinDuration(t, now, *usage.QuotaUpdatedAt, time.Second)
	require.False(t, shouldRefreshOpenAICodexSnapshot(account, usage, time.Now()))
}

func TestCompatibleQuotaFailureKeepsOldTimestampAndReportsError(t *testing.T) {
	now := time.Now()
	old := now.Add(-2 * time.Hour).Truncate(time.Second)
	account := newOpenAIQuotaBridgeTestAccount(30, "http://unreachable.invalid", "auth.json", "owner@example.test")
	account.Extra["codex_7d_used_percent"] = 11.0
	account.Extra["codex_usage_updated_at"] = old.Format(time.RFC3339)
	for _, query := range []*quotaUsageQueryStub{{err: errors.New("token must never be echoed")}, {usage: &OpenAIQuotaUsage{}}} {
		svc := &AccountUsageService{openAIQuotaService: query}
		usage, err := svc.getOpenAIUsage(context.Background(), account, true)
		require.NoError(t, err)
		require.Equal(t, "quota_refresh_failed", usage.ErrorCode)
		require.NotContains(t, usage.Error, "token")
		require.Equal(t, 11.0, usage.SevenDay.Utilization)
		require.WithinDuration(t, old, *usage.QuotaUpdatedAt, time.Second)
	}
}

type quotaErrorClearRecorder struct {
	AccountRepository
	clears int
}

func (r *quotaErrorClearRecorder) ClearError(context.Context, int64) error {
	r.clears++
	return nil
}

func (r *quotaErrorClearRecorder) UpdateExtra(context.Context, int64, map[string]any) error {
	return nil
}

func TestCompatibleQuotaFailureDoesNotClearAccountAuthError(t *testing.T) {
	account := newOpenAIQuotaBridgeTestAccount(30, "http://unreachable.invalid", "auth.json", "owner@example.test")
	account.Status = StatusError
	account.ErrorMessage = "unauthenticated"
	repo := &quotaErrorClearRecorder{}
	svc := &AccountUsageService{accountRepo: repo, openAIQuotaService: &quotaUsageQueryStub{err: errors.New("quota unavailable")}}
	usage, err := svc.getUsageForAccount(context.Background(), account, true)
	require.NoError(t, err)
	require.Equal(t, "quota_refresh_failed", usage.ErrorCode)
	require.Equal(t, StatusError, account.Status)
	require.Zero(t, repo.clears)
}

func TestOpenAIQuotaReadSuccessPreservesAccountAuthError(t *testing.T) {
	now := time.Now()
	for _, account := range []*Account{
		creditSchedulingAccount(t, now, `{}`),
		newOpenAIQuotaBridgeTestAccount(30, "http://quota-test.invalid", "auth.json", "owner@example.test"),
	} {
		t.Run(account.Type, func(t *testing.T) {
			const authError = "Token refresh failed (non-retryable): refresh_token_invalidated"
			account.Status = StatusError
			account.ErrorMessage = authError
			balance := "25.00"
			query := &quotaUsageQueryStub{usage: &OpenAIQuotaUsage{
				FetchedAt: now.Unix(),
				Credits:   &OpenAICredits{HasCredits: true, Balance: &balance},
				RateLimit: &OpenAIRateLimit{Allowed: true, PrimaryWindow: &OpenAIRateLimitWindow{
					UsedPercent: 12, LimitWindowSeconds: 18000, ResetAt: now.Add(time.Hour).Unix(),
				}},
			}}
			repo := &quotaErrorClearRecorder{}
			svc := &AccountUsageService{accountRepo: repo, openAIQuotaService: query}
			usage, err := svc.getUsageForAccount(context.Background(), account, true)
			require.NoError(t, err)
			require.Empty(t, usage.Error)
			require.Equal(t, []int64{account.ID}, query.ids, "the bound quota read really succeeded")
			require.NotNil(t, readCodexCreditsSnapshot(account.Extra), "balance refresh still works")
			require.Equal(t, StatusError, account.Status)
			require.Equal(t, authError, account.ErrorMessage)
			require.Zero(t, repo.clears, "a valid access token does not establish refresh-token recovery")
		})
	}
}
