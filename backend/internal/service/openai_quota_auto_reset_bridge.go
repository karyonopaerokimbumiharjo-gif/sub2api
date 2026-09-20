package service

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

const (
	openAIQuotaAutoResetEnabledKey       = "openai_quota_auto_reset_enabled"
	openAIQuotaAutoResetLastAttemptAtKey = "openai_quota_auto_reset_last_attempt_at"
	openAIQuotaAutoResetLastWindowKey    = "openai_quota_auto_reset_last_window"
	openAIQuotaAutoResetLastResetAtKey   = "openai_quota_auto_reset_last_reset_at"
	openAIQuotaAutoResetLastStatusKey    = "openai_quota_auto_reset_last_status"
	openAIQuotaAutoResetLastErrorKey     = "openai_quota_auto_reset_last_error"

	openAIQuotaAutoResetInterval      = time.Minute
	openAIQuotaAutoResetRetryCooldown = 5 * time.Minute
	openAIQuotaAutoResetCallTimeout   = 45 * time.Second
)

type OpenAIQuotaAutoResetSettings struct {
	Enabled bool `json:"enabled"`
}

func (s *OpenAIQuotaService) SetAutoReset(ctx context.Context, accountID int64, enabled bool) (*OpenAIQuotaAutoResetSettings, error) {
	if s == nil || s.accountRepo == nil {
		return nil, infraerrors.InternalServer("OPENAI_QUOTA_NOT_CONFIGURED", "openai quota service is not configured")
	}
	account, err := s.accountRepo.GetByID(ctx, accountID)
	if err != nil || account == nil {
		return nil, infraerrors.NotFound("OPENAI_QUOTA_ACCOUNT_NOT_FOUND", "account not found")
	}
	if account.Platform != PlatformOpenAI || (account.Type != AccountTypeOAuth && !account.IsOpenAICompatibleQuotaBridge()) {
		return nil, infraerrors.BadRequest("OPENAI_QUOTA_INVALID_ACCOUNT", "automatic reset requires an OpenAI OAuth account or compatible quota bridge")
	}
	if account.IsShadow() {
		return nil, ErrSparkShadowResetNotSupported
	}

	updates := map[string]any{
		openAIQuotaAutoResetEnabledKey: enabled,
	}
	if enabled {
		// Enabling should be eligible for the next worker pass immediately.
		updates[openAIQuotaAutoResetLastAttemptAtKey] = nil
		updates[openAIQuotaAutoResetLastStatusKey] = "enabled"
		updates[openAIQuotaAutoResetLastErrorKey] = nil
	} else {
		updates[openAIQuotaAutoResetLastStatusKey] = "disabled"
	}
	if err := s.accountRepo.UpdateExtra(ctx, accountID, updates); err != nil {
		return nil, infraerrors.InternalServer("OPENAI_QUOTA_AUTO_RESET_UPDATE_FAILED", "failed to update automatic reset setting")
	}
	return &OpenAIQuotaAutoResetSettings{Enabled: enabled}, nil
}

func (s *OpenAIQuotaService) StartAutoResetWorker() {
	if s == nil || s.accountRepo == nil {
		return
	}
	s.autoResetMu.Lock()
	defer s.autoResetMu.Unlock()
	if s.autoResetCancel != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.autoResetCancel = cancel
	s.autoResetDone = done
	go func() {
		defer close(done)
		s.runAutoResetLoop(ctx)
	}()
}

func (s *OpenAIQuotaService) StopAutoResetWorker() {
	if s == nil {
		return
	}
	s.autoResetMu.Lock()
	cancel := s.autoResetCancel
	done := s.autoResetDone
	s.autoResetCancel = nil
	s.autoResetDone = nil
	s.autoResetMu.Unlock()

	if cancel == nil {
		return
	}
	cancel()
	if done != nil {
		<-done
	}
}

func (s *OpenAIQuotaService) runAutoResetLoop(ctx context.Context) {
	// Give startup migrations and cache warmup time to finish before the first scan.
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}

	s.runAutoResetCycle(ctx, time.Now())
	ticker := time.NewTicker(openAIQuotaAutoResetInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.runAutoResetCycle(ctx, now)
		}
	}
}

func (s *OpenAIQuotaService) runAutoResetCycle(ctx context.Context, now time.Time) {
	accounts, err := s.accountRepo.FindByExtraField(ctx, openAIQuotaAutoResetEnabledKey, true)
	if err != nil {
		slog.Warn("openai_quota_auto_reset_scan_failed", "error", err)
		return
	}

	// Intentionally serial: each enabled account can make multiple upstream calls.
	for i := range accounts {
		if ctx.Err() != nil {
			return
		}
		s.tryAutoResetAccount(ctx, &accounts[i], now)
	}
}

func (s *OpenAIQuotaService) tryAutoResetAccount(ctx context.Context, account *Account, now time.Time) {
	if account == nil ||
		account.Platform != PlatformOpenAI ||
		(account.Type != AccountTypeOAuth && !account.IsOpenAICompatibleQuotaBridge()) ||
		account.Status != StatusActive ||
		account.IsShadow() ||
		!resolveAccountExtraBool(account.Extra, openAIQuotaAutoResetEnabledKey) ||
		!hasObservedExhaustedOpenAIWindow(account) {
		return
	}
	if attemptedAt, ok := accountExtraTime(account.Extra, openAIQuotaAutoResetLastAttemptAtKey); ok &&
		now.Sub(attemptedAt) < openAIQuotaAutoResetRetryCooldown {
		return
	}

	attemptUpdates := map[string]any{
		openAIQuotaAutoResetLastAttemptAtKey: now.UTC().Format(time.RFC3339),
		openAIQuotaAutoResetLastStatusKey:    "checking",
		openAIQuotaAutoResetLastErrorKey:     nil,
	}
	// Fail closed. Without a durable attempt marker, a second process or restart
	// could consume another reset credit before the first attempt is recorded.
	if err := s.accountRepo.UpdateExtra(ctx, account.ID, attemptUpdates); err != nil {
		slog.Warn("openai_quota_auto_reset_mark_attempt_failed", "account_id", account.ID, "error", err)
		return
	}

	callCtx, cancel := context.WithTimeout(ctx, openAIQuotaAutoResetCallTimeout)
	defer cancel()

	usage, err := s.queryUsageForAutoReset(callCtx, account.ID)
	if err != nil {
		s.recordAutoResetResult(ctx, account.ID, "query_failed", "", now, err)
		return
	}
	if freshUpdates := buildCodexWindowExtraUpdates(usage.RateLimit, time.Now()); len(freshUpdates) > 0 {
		if err := s.accountRepo.UpdateExtra(ctx, account.ID, freshUpdates); err != nil {
			slog.Warn("openai_quota_auto_reset_persist_query_failed", "account_id", account.ID, "error", err)
		}
	}
	windowKey := exhaustedOpenAIWindowKey(usage.RateLimit, now)
	if windowKey == "" {
		s.recordAutoResetResult(ctx, account.ID, "not_exhausted", "", now, nil)
		return
	}
	if lastWindow, _ := account.Extra[openAIQuotaAutoResetLastWindowKey].(string); lastWindow == windowKey {
		s.recordAutoResetResult(ctx, account.ID, "already_reset", windowKey, now, nil)
		return
	}
	if usage.RateLimitResetCredits == nil || usage.RateLimitResetCredits.AvailableCount <= 0 {
		s.recordAutoResetResult(ctx, account.ID, "no_credits", "", now, nil)
		return
	}

	result, err := s.resetCreditForAutoReset(callCtx, account.ID)
	if err != nil {
		s.recordAutoResetResult(ctx, account.ID, "reset_failed", "", now, err)
		return
	}
	if result == nil {
		s.recordAutoResetResult(ctx, account.ID, "reset_failed", "", now, fmt.Errorf("upstream returned an empty reset result"))
		return
	}

	updates := map[string]any{
		openAIQuotaAutoResetLastWindowKey:  windowKey,
		openAIQuotaAutoResetLastResetAtKey: now.UTC().Format(time.RFC3339),
		openAIQuotaAutoResetLastStatusKey:  "success",
		openAIQuotaAutoResetLastErrorKey:   nil,
	}
	if refreshed, refreshErr := s.queryUsageForAutoReset(callCtx, account.ID); refreshErr == nil {
		for key, value := range buildCodexWindowExtraUpdates(refreshed.RateLimit, time.Now()) {
			updates[key] = value
		}
	}
	if err := s.accountRepo.UpdateExtra(ctx, account.ID, updates); err != nil {
		slog.Warn("openai_quota_auto_reset_persist_success_failed", "account_id", account.ID, "error", err)
	}
	slog.Info("openai_quota_auto_reset_success",
		"account_id", account.ID,
		"windows_reset", result.WindowsReset,
		"remaining_credits_before_reset", usage.RateLimitResetCredits.AvailableCount,
		"window", windowKey,
	)
}

func (s *OpenAIQuotaService) queryUsageForAutoReset(ctx context.Context, accountID int64) (*OpenAIQuotaUsage, error) {
	if s.autoResetQueryUsage != nil {
		return s.autoResetQueryUsage(ctx, accountID)
	}
	return s.QueryUsage(ctx, accountID)
}

func (s *OpenAIQuotaService) resetCreditForAutoReset(ctx context.Context, accountID int64) (*OpenAIQuotaResetResult, error) {
	if s.autoResetResetCredit != nil {
		return s.autoResetResetCredit(ctx, accountID)
	}
	return s.ResetCredit(ctx, accountID)
}

func (s *OpenAIQuotaService) recordAutoResetResult(ctx context.Context, accountID int64, status, windowKey string, now time.Time, resultErr error) {
	updates := map[string]any{
		openAIQuotaAutoResetLastStatusKey: status,
	}
	if windowKey != "" {
		updates[openAIQuotaAutoResetLastWindowKey] = windowKey
	}
	if resultErr != nil {
		updates[openAIQuotaAutoResetLastErrorKey] = truncate(resultErr.Error(), 240)
	} else {
		updates[openAIQuotaAutoResetLastErrorKey] = nil
	}
	if err := s.accountRepo.UpdateExtra(ctx, accountID, updates); err != nil {
		slog.Warn("openai_quota_auto_reset_result_failed", "account_id", accountID, "status", status, "error", err)
	}
	if resultErr != nil {
		slog.Warn("openai_quota_auto_reset_failed", "account_id", accountID, "status", status, "attempted_at", now, "error", resultErr)
	}
}

func hasObservedExhaustedOpenAIWindow(account *Account) bool {
	if account == nil {
		return false
	}
	if account.IsRateLimited() {
		return true
	}
	for _, key := range []string{
		"codex_5h_used_percent",
		"codex_7d_used_percent",
		"codex_primary_used_percent",
		"codex_secondary_used_percent",
	} {
		if value, ok := resolveAccountExtraNumber(account.Extra, key); ok && value >= 100 {
			return true
		}
	}
	return false
}

func exhaustedOpenAIWindowKey(rateLimit *OpenAIRateLimit, now time.Time) string {
	if rateLimit == nil {
		return ""
	}
	type namedWindow struct {
		name   string
		window *OpenAIRateLimitWindow
	}
	windows := []namedWindow{
		{name: "primary", window: rateLimit.PrimaryWindow},
		{name: "secondary", window: rateLimit.SecondaryWindow},
	}
	parts := make([]string, 0, len(windows))
	for _, item := range windows {
		if item.window == nil || item.window.UsedPercent < 100 {
			continue
		}
		resetAt := item.window.ResetAt
		if resetAt <= 0 && item.window.ResetAfterSeconds > 0 {
			// The derived boundary is stable across polls; minute precision avoids
			// tiny upstream timing jitter creating a new idempotency key.
			resetAt = (now.Unix() + item.window.ResetAfterSeconds) / 60 * 60
		}
		parts = append(parts, fmt.Sprintf("%s:%d:%d", item.name, item.window.LimitWindowSeconds, resetAt))
	}
	if len(parts) == 0 && rateLimit.LimitReached {
		parts = append(parts, "limit-reached")
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

func buildCodexWindowExtraUpdates(rateLimit *OpenAIRateLimit, now time.Time) map[string]any {
	if rateLimit == nil {
		return nil
	}
	usage := &OpenAIQuotaUsage{
		AdditionalRateLimits: []OpenAIAdditionalRateLimit{
			{MeteredFeature: "codex_bengalfox", RateLimit: rateLimit},
		},
	}
	return buildCodexSparkWindowExtraUpdates(usage, now)
}

func accountExtraTime(extra map[string]any, key string) (time.Time, bool) {
	if len(extra) == 0 {
		return time.Time{}, false
	}
	raw, ok := extra[key]
	if !ok || raw == nil {
		return time.Time{}, false
	}
	value := strings.TrimSpace(fmt.Sprint(raw))
	if value == "" || value == "<nil>" {
		return time.Time{}, false
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed, true
	}
	if unixSeconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		return time.Unix(unixSeconds, 0), true
	}
	return time.Time{}, false
}
