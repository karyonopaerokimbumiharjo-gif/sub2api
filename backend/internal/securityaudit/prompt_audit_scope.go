package securityaudit

import (
	"context"
	"fmt"
	"time"
)

// buildScopedPromptSnapshot is the single scope implementation used by both
// foreground and background audit paths. This prevents the old bug where the
// UI selected fast mode while the asynchronous worker silently audited full
// context.
func buildScopedPromptSnapshot(
	ctx context.Context,
	req Request,
	cfg ActiveConfig,
	mode string,
	segmentCache PromptSegmentAllowCache,
) (PromptSnapshot, error) {
	if req.RequireJev {
		extracted, err := extractRequestPromptSegments(req)
		if err != nil {
			return PromptSnapshot{}, err
		}
		return buildPromptSnapshot(req, extracted, extracted)
	}
	switch mode {
	case BlockingAuditModeFastLatest:
		return ExtractFastBlockingPromptSnapshot(req)
	case BlockingAuditModeIncrementalFull:
		plan, err := BuildIncrementalPromptPlan(req)
		if err != nil {
			return PromptSnapshot{}, err
		}
		knownAllowed := map[string]struct{}{}
		if segmentCache != nil {
			cacheCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
			knownAllowed, err = segmentCache.KnownAllowed(cacheCtx, req, cfg.ConfigVersion, plan.CandidateFingerprints())
			cancel()
			if err != nil {
				// A cache outage broadens the audit instead of allowing unchecked
				// context, and therefore cannot reduce safety coverage.
				LogWarn("prompt_audit.segment_cache_read_failed", map[string]any{
					"request_id": req.RequestID, "status": "failed", "error_code": "segment_cache_unavailable",
				})
				knownAllowed = map[string]struct{}{}
			}
		}
		snapshot, _, err := plan.Snapshot(knownAllowed)
		return snapshot, err
	case BlockingAuditModeFull:
		return ExtractPromptSnapshot(req)
	default:
		return PromptSnapshot{}, fmt.Errorf("unsupported prompt audit mode %q", mode)
	}
}
