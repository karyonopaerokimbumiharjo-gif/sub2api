package securityaudit

import (
	"context"
	"errors"
	"time"
)

func (s *RoutingPromptScanner) acquireCPABridgeSlot(ctx context.Context, endpoint ActiveEndpoint) (func(), error) {
	selector := s.accounts
	if selector == nil || s.concurrency == nil {
		return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true}
	}
	duration := time.Duration(endpoint.TimeoutMS) * time.Millisecond
	if duration <= 0 {
		duration = time.Duration(DefaultTimeoutMS) * time.Millisecond
	}
	waitCtx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	account, err := selector.FindCPABridgeForAudit(waitCtx, endpoint.BaseURL)
	if err != nil || account == nil {
		return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true}
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		slot, err := s.concurrency.AcquireAccountSlot(waitCtx, account.ID, account.Concurrency)
		if err != nil {
			return nil, unavailableGuardError(waitCtx, err)
		}
		if slot != nil && slot.Acquired {
			if slot.ReleaseFunc != nil {
				return slot.ReleaseFunc, nil
			}
			return func() {}, nil
		}
		select {
		case <-waitCtx.Done():
			return nil, unavailableGuardError(waitCtx, waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func unavailableGuardError(ctx context.Context, cause error) *GuardError {
	timeout := errors.Is(cause, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded)
	return &GuardError{Code: ErrorCodeUnavailable, Retryable: true, Timeout: timeout, Cause: cause}
}
