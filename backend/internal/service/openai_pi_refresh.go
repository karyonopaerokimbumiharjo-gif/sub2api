package service

import (
	"context"
	"errors"
	"time"
)

// RefreshPiAccount shares the automatic refresh lock and persistence boundary.
// A second click using the same credential snapshot must not rotate it again.
func (s *OpenAIOAuthService) RefreshPiAccount(ctx context.Context, account *Account) (*Account, error) {
	if !account.UsesNativePiRuntime() || s.refreshAPI == nil {
		return nil, errors.New("Pi credential refresh is unavailable")
	}
	executor := &manualPiRefresh{
		OpenAITokenRefresher: NewOpenAITokenRefresher(s, s.refreshAPI.accountRepo),
		access:               account.GetOpenAIAccessToken(), refresh: account.GetOpenAIRefreshToken(),
	}
	result, err := s.refreshAPI.RefreshIfNeeded(ctx, account, executor, 0)
	if err != nil {
		return nil, err
	}
	if result == nil || result.LockHeld || result.Account == nil {
		return nil, errors.New("Pi credential refresh is already running; retry after it completes")
	}
	if !result.Account.IsActive() || !result.Account.UsesNativePiRuntime() {
		return nil, errors.New("Pi account is no longer active")
	}
	// Return the durable state, and invalidate the access token cached before
	// rotation. Handlers must not persist their pre-refresh snapshot afterward.
	return s.refreshAPI.loadDurableAccountAfterRefresh(ctx, executor.CacheKey(account), account.ID)
}

type manualPiRefresh struct {
	*OpenAITokenRefresher
	access, refresh string
}

func (r *manualPiRefresh) CanRefresh(a *Account) bool {
	return a.UsesNativePiRuntime() && r.OpenAITokenRefresher.CanRefresh(a)
}

func (r *manualPiRefresh) NeedsRefresh(a *Account, _ time.Duration) bool {
	return a.GetOpenAIAccessToken() == r.access && a.GetOpenAIRefreshToken() == r.refresh
}
