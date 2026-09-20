package service

import (
	"context"
	"time"
)

type openAIQuotaUsageQuerier interface {
	QueryUsage(context.Context, int64) (*OpenAIQuotaUsage, error)
}

// Body queries are complete snapshots, unlike incremental response headers.
// Clear missing windows, otherwise an old 5h value survives a 7d-only plan.
// Classify windows by their actual duration, never by primary/secondary order.
func buildCodexQuotaWindowExtraUpdates(rateLimit *OpenAIRateLimit, now time.Time) map[string]any {
	updates := map[string]any{"codex_usage_updated_at": now.Format(time.RFC3339)}
	for _, window := range []string{"5h", "7d"} {
		for _, field := range []string{"used_percent", "reset_after_seconds", "window_minutes", "reset_at"} {
			updates["codex_"+window+"_"+field] = nil
		}
	}
	if rateLimit == nil {
		return updates
	}
	for _, w := range []*OpenAIRateLimitWindow{rateLimit.PrimaryWindow, rateLimit.SecondaryWindow} {
		if w == nil {
			continue
		}
		name := ""
		switch w.LimitWindowSeconds {
		case 5 * 60 * 60:
			name = "5h"
		case 7 * 24 * 60 * 60:
			name = "7d"
		default:
			continue // Do not label an unknown duration as a 5h/7d quota.
		}
		prefix := "codex_" + name + "_"
		updates[prefix+"used_percent"] = w.UsedPercent
		updates[prefix+"window_minutes"] = int(w.LimitWindowSeconds / 60)
		if w.ResetAt <= 0 && w.ResetAfterSeconds <= 0 {
			continue // Missing reset metadata must not turn a fresh nonzero quota into zero.
		}
		resetAt := now.Add(time.Duration(w.ResetAfterSeconds) * time.Second)
		if w.ResetAt > 0 {
			resetAt = time.Unix(w.ResetAt, 0)
		}
		updates[prefix+"reset_after_seconds"] = max(int(resetAt.Sub(now).Seconds()), 0)
		updates[prefix+"reset_at"] = resetAt.UTC().Format(time.RFC3339)
	}
	return updates
}
