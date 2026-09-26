package securityaudit

import (
	"context"
	"errors"
)

// Native mode replaces custom model audits, not deterministic local rules.
type nativeAuditPolicyEngine interface {
	NativeAuditEnabled() bool
	EvaluateNativeHardRules(context.Context, Request) (*PromptDecision, error)
}

func (c *Coordinator) nativeAuditSelected() bool {
	if c == nil || c.prompt == nil {
		return false
	}
	engine, ok := c.prompt.(nativeAuditPolicyEngine)
	return ok && engine.NativeAuditEnabled()
}

func (c *Coordinator) checkNative(ctx context.Context, req Request, engine nativeAuditPolicyEngine) Decision {
	rules, err := engine.EvaluateNativeHardRules(ctx, req)
	if err != nil {
		return prioritize(nil, unavailablePromptDecision(ErrorCodeUnavailable))
	}
	if rules != nil && !rules.AllowNextStage {
		return prioritize(nil, rules)
	}
	ready, ok := c.legacy.(interface{ NativeAuditReady(context.Context) bool })
	if !ok || !ready.NativeAuditReady(ctx) {
		return prioritize(nil, unavailablePromptDecision(ErrorCodeUnavailable))
	}
	legacy, err := c.checkLegacy(ctx, req)
	if err != nil {
		return prioritize(nil, unavailablePromptDecision(ErrorCodeUnavailable))
	}
	return prioritize(legacy, rules)
}

func (a *LegacyModerationAdapter) NativeAuditReady(ctx context.Context) bool {
	return a != nil && a.service != nil && a.service.NativeAuditReady(ctx)
}

func (s *PromptService) NativeAuditEnabled() bool {
	if s == nil || s.config == nil {
		return false
	}
	cfg, ok := s.config.Active()
	return ok && cfg.RiskControlEnabled && cfg.NativeAuditEnabled
}

func (s *PromptService) EvaluateNativeHardRules(ctx context.Context, req Request) (*PromptDecision, error) {
	if s == nil || s.config == nil || s.evaluator == nil {
		return nil, &GuardError{Code: ErrorCodeUnavailable}
	}
	cfg, ok := s.config.Active()
	if !ok {
		return nil, &GuardError{Code: ErrorCodeUnavailable}
	}
	snapshot, err := ExtractPromptSnapshot(req)
	if errors.Is(err, ErrNoPromptText) {
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	if err != nil {
		return nil, err
	}
	start := s.evaluator.clock.Now()
	result := MatchExplicitBypassSnapshotPolicy(snapshot, AllScannerIDs)
	if result == nil {
		result = MatchKnownRepositorySnapshotPolicy(snapshot, AllScannerIDs)
	}
	if result == nil {
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	return s.evaluator.finishEvaluation(ctx, cfg, snapshot, result, true, start, snapshotLogFields(snapshot))
}
