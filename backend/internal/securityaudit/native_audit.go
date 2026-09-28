package securityaudit

import (
	"context"
	"errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/auditpolicy"
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
	if provider, ok := engine.(interface{ NativePolicy() ActiveConfig }); ok {
		policy := provider.NativePolicy()
		req.NativeAuditProfile = policy.NativeAuditProfile
		req.NativeScanners = append([]string(nil), policy.Scanners...)
		req.NativeRiskCategories = auditpolicy.ResolveNativeCategories(policy.NativeRiskCategories, policy.Scanners, policy.OperatorPolicyEnabled)
		req.OperatorPolicyEnabled = policy.OperatorPolicyEnabled
	}
	rules, err := engine.EvaluateNativeHardRules(ctx, req)
	if err != nil {
		return prioritize(nil, unavailablePromptDecision(ErrorCodeUnavailable))
	}
	if rules != nil && !rules.AllowNextStage {
		return prioritize(nil, rules)
	}
	ready, ok := c.legacy.(interface{ NativeAuditReady(context.Context) bool })
	if !ok || !ready.NativeAuditReady(ctx) {
		if recorder, ok := c.legacy.(interface {
			RecordNativeUnavailable(context.Context, Request)
		}); ok {
			recorder.RecordNativeUnavailable(ctx, req)
		}
		return prioritize(nil, unavailablePromptDecision(ErrorCodeUnavailable))
	}

	legacy, err := c.checkLegacy(ctx, req)
	if err != nil {
		return prioritize(nil, unavailablePromptDecision(ErrorCodeUnavailable))
	}
	if legacy != nil && legacy.Action == "error" {
		return prioritize(nil, unavailablePromptDecision(ErrorCodeUnavailable))
	}
	if legacy != nil && legacy.Action == "review_required" {
		return prioritize(nil, unavailablePromptDecision(ErrorCodeReviewRequired))
	}
	if legacy != nil && legacy.BioTier == "B1" {
		if req.Stage != "http" && req.Stage != "native_output" {
			return prioritize(nil, unavailablePromptDecision(ErrorCodeReviewRequired))
		}
		result := &NormalizedResult{Decision: EventPass, Action: ActionAllow, RiskLevel: RiskLow}
		applyBioTier(result, "B1")
		rules = &PromptDecision{Kind: DecisionFlag, AllowNextStage: true, Result: result}
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
	if cfg.NativeAuditProfile == auditpolicy.NativeProfileUpstream {
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	snapshot, err := ExtractPromptSnapshot(req)
	if errors.Is(err, ErrNoPromptText) {
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	if err != nil {
		return nil, err
	}
	if cfg.NativeRiskCategories != nil && !auditpolicy.HasCategory(cfg.NativeRiskCategories, "jailbreak") {
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	start := s.evaluator.clock.Now()
	result := MatchExplicitBypassSnapshotPolicy(snapshot, AllScannerIDs)
	if result == nil {
		result = MatchKnownRepositorySnapshotPolicy(snapshot, AllScannerIDs)
	}
	if result == nil {
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	snapshot.Stage = "native_hard_rules"
	return s.evaluator.finishEvaluation(ctx, cfg, snapshot, result, true, start, snapshotLogFields(snapshot))
}

func (s *PromptService) AuditSelectionExclusive() bool {
	if s == nil || s.config == nil {
		return false
	}
	_, ok := s.config.Active()
	return ok
}

func (s *PromptService) NativePolicy() ActiveConfig {
	cfg, _ := s.config.Active()
	return cfg
}

func (a *LegacyModerationAdapter) RecordNativeUnavailable(ctx context.Context, req Request) {
	if a != nil && a.service != nil {
		a.service.RecordNativeUnavailable(ctx, moderationInput(req))
	}
}
