package service

import (
	"context"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
)

// WithPromptAuditLatency stores the actual wall-clock delay introduced by the
// synchronous prompt-audit gate. A negative value is normalized to zero.
func WithPromptAuditLatency(ctx context.Context, latencyMS int) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if latencyMS < 0 {
		latencyMS = 0
	}
	return context.WithValue(ctx, ctxkey.PromptAuditLatencyMS, latencyMS)
}

// PromptAuditLatencyFromContext returns a copy suitable for persisting on a
// usage log. Missing means the request did not pass through a measurable
// synchronous prompt-audit gate; callers must not turn that into a fake zero.
func PromptAuditLatencyFromContext(ctx context.Context) *int {
	if ctx == nil {
		return nil
	}
	latencyMS, ok := ctx.Value(ctxkey.PromptAuditLatencyMS).(int)
	if !ok || latencyMS < 0 {
		return nil
	}
	value := latencyMS
	return &value
}
