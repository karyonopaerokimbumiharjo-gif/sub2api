package service

import (
	"context"
	"log/slog"
	"time"
)

const openAICreditsRefreshInterval = 2 * time.Minute

// Runs serially in the existing quota worker. Read-only refreshes maintain
// credit eligibility while API clients run without an open admin dashboard.
// This path never consumes reset cards or changes account/cooldown state.
func (s *OpenAIQuotaService) runCreditsRefreshCycle(ctx context.Context, now time.Time) {
	accounts, err := s.accountRepo.ListByPlatform(ctx, PlatformOpenAI)
	if err != nil {
		slog.Warn("openai_credits_refresh_scan_failed", "error", err)
		return
	}
	if s.creditsRefreshAttempts == nil {
		s.creditsRefreshAttempts = make(map[int64]time.Time)
	}
	present := make(map[int64]bool, len(accounts))
	for i := range accounts {
		if ctx.Err() != nil {
			return
		}
		account := &accounts[i]
		present[account.ID] = true
		if !shouldRefreshCodexCredits(account, now) {
			continue
		}
		if attempted, ok := s.creditsRefreshAttempts[account.ID]; ok && now.Sub(attempted) < openAICreditsRefreshInterval {
			continue
		}
		s.creditsRefreshAttempts[account.ID] = now
		callCtx, cancel := context.WithTimeout(ctx, openaiQuotaUpstreamTimeout)
		usage, err := s.queryUsageForAutoReset(callCtx, account.ID)
		if err == nil && usage != nil {
			updates := buildCodexQuotaWindowExtraUpdates(usage.RateLimit, time.Unix(usage.FetchedAt, 0))
			updates[openaiQuotaCreditsKey] = codexCreditsSnapshotFromUsage(usage)
			err = s.accountRepo.UpdateExtra(callCtx, account.ID, updates)
		}
		cancel()
		if err != nil {
			// Do not include upstream bodies, account credentials, or tokens.
			slog.Warn("openai_credits_refresh_failed", "account_id", account.ID)
		}
	}
	for id := range s.creditsRefreshAttempts {
		if !present[id] {
			delete(s.creditsRefreshAttempts, id)
		}
	}
}

func shouldRefreshCodexCredits(account *Account, now time.Time) bool {
	if account == nil || !account.IsSchedulable() || account.IsShadow() ||
		(!account.IsOAuth() && !account.IsOpenAICompatibleQuotaBridge()) {
		return false
	}
	snapshot := readCodexCreditsSnapshot(account.Extra)
	if snapshot != nil && snapshot.FetchedAt > 0 && now.Sub(time.Unix(snapshot.FetchedAt, 0)) < openAICreditsRefreshInterval {
		return false
	}
	if snapshot != nil && (snapshot.Credits != nil || snapshot.SpendControl != nil) {
		return true
	}
	for _, window := range []string{"5h", "7d"} {
		if utilization, ok := resolveOpenAIQuotaUtilization(account.Extra, window, now); ok && utilization >= 1 {
			return true
		}
	}
	return false
}
