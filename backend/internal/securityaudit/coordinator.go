package securityaudit

import (
	"context"
	"errors"
	"net/http"
	"sync"
)

type LegacyEngine interface {
	Check(ctx context.Context, req Request) (*LegacyDecision, error)
}

type PromptEngine interface {
	EffectiveMode() Mode
	Enqueue(ctx context.Context, req Request) error
	Evaluate(ctx context.Context, req Request) (*PromptDecision, error)
}

type PromptRiskEscalationEngine interface {
	EvaluateKnownRisk(ctx context.Context, req Request) (*PromptDecision, error)
}

type PromptAuditGapRecorder interface {
	CaptureAuditGap(ctx context.Context, req Request)
}

type PromptBackgroundAuditEngine interface {
	HasBackgroundAudit() bool
}

type PromptBypassEngine interface {
	ShouldBypass(req Request) bool
	RecordUserBypass(ctx context.Context, req Request)
}

type OutputAuditEngine interface {
	ShouldAuditOutput(req Request, inputDecision DecisionKind) bool
	ObserveOutput(ctx context.Context, req Request, inputDecision DecisionKind, responseBody []byte, streaming bool)
}

type UpstreamPolicyFeedbackRecorder interface {
	RecordUpstreamPolicyFeedback(ctx context.Context, snapshot PromptSnapshot, code, message string) error
}

type LocalPolicyCacheRecorder interface {
	RecordLocalPolicyCacheBlock(ctx context.Context, snapshot PromptSnapshot, code, message string) error
}

type Coordinator struct {
	legacy LegacyEngine
	prompt PromptEngine
}

type jevProductEngine interface {
	JevBlockingReady() bool
	EnhanceCompaction(ctx context.Context, body []byte) ([]byte, JevCompactionReport, error)
}

func NewCoordinator(legacy LegacyEngine, prompt PromptEngine) *Coordinator {
	return &Coordinator{legacy: legacy, prompt: prompt}
}

func (c *Coordinator) JevBlockingReady() bool {
	if c == nil || c.prompt == nil {
		return false
	}
	engine, ok := c.prompt.(jevProductEngine)
	return ok && engine.JevBlockingReady()
}

func (c *Coordinator) EnhanceCompaction(ctx context.Context, body []byte) ([]byte, JevCompactionReport, error) {
	if c == nil || c.prompt == nil {
		return body, JevCompactionReport{}, &GuardError{Code: ErrorCodeUnavailable}
	}
	engine, ok := c.prompt.(jevProductEngine)
	if !ok || !engine.JevBlockingReady() {
		return body, JevCompactionReport{}, &GuardError{Code: ErrorCodeUnavailable}
	}
	return engine.EnhanceCompaction(ctx, body)
}

// RecordUpstreamPolicyFeedback is best-effort and intentionally separate from
// Check: the upstream response has already been returned, so recording must not
// change the client outcome or make the request fail twice.
func (c *Coordinator) RecordUpstreamPolicyFeedback(ctx context.Context, snapshot PromptSnapshot, code, message string) error {
	if c == nil || c.prompt == nil {
		return nil
	}
	recorder, ok := c.prompt.(UpstreamPolicyFeedbackRecorder)
	if !ok {
		return nil
	}
	return recorder.RecordUpstreamPolicyFeedback(ctx, snapshot, code, message)
}

func (c *Coordinator) RecordLocalPolicyCacheBlock(ctx context.Context, snapshot PromptSnapshot, code, message string) error {
	if c == nil || c.prompt == nil {
		return nil
	}
	recorder, ok := c.prompt.(LocalPolicyCacheRecorder)
	if !ok {
		return nil
	}
	return recorder.RecordLocalPolicyCacheBlock(ctx, snapshot, code, message)
}

func (c *Coordinator) ShouldAuditOutput(req Request, inputDecision DecisionKind) bool {
	if c == nil || c.prompt == nil {
		return false
	}
	engine, ok := c.prompt.(OutputAuditEngine)
	return ok && engine.ShouldAuditOutput(req, inputDecision)
}

func (c *Coordinator) ObserveOutput(ctx context.Context, req Request, inputDecision DecisionKind, responseBody []byte, streaming bool) {
	if c == nil || c.prompt == nil {
		return
	}
	if engine, ok := c.prompt.(OutputAuditEngine); ok {
		engine.ObserveOutput(ctx, req, inputDecision, responseBody, streaming)
	}
}

func (c *Coordinator) Check(ctx context.Context, req Request) Decision {
	if req.RequireJev && !c.JevBlockingReady() {
		return prioritize(nil, unavailablePromptDecision(ErrorCodeUnavailable))
	}
	if c == nil {
		return allowDecision(nil, nil)
	}
	// The explicit administrator-managed per-user bypass is the outermost
	// policy boundary. A match bypasses both the legacy content moderator and
	// every prompt-audit mode, including background jobs and cached blocks.
	if bypass, ok := c.prompt.(PromptBypassEngine); ok && !req.RequireJev && bypass.ShouldBypass(req) {
		bypass.RecordUserBypass(ctx, req.Clone())
		return allowDecision(nil, nil)
	}
	mode := ModeOff
	if c.prompt != nil {
		mode = c.prompt.EffectiveMode()
	}
	switch mode {
	case ModeAsync:
		if riskEngine, ok := c.prompt.(PromptRiskEscalationEngine); ok {
			prompt, err := riskEngine.EvaluateKnownRisk(ctx, req.Clone())
			if err != nil {
				return prioritize(nil, unavailablePromptDecision(ErrorCodeUnavailable))
			}
			if prompt != nil && prompt.Kind != DecisionAllow {
				return prioritize(nil, prompt)
			}
		}
		// Enqueue is deliberately best-effort. The implementation owns a bounded
		// context and copies request memory before it can outlive the Handler.
		_ = c.prompt.Enqueue(ctx, req.Clone())
		legacy, _ := c.checkLegacy(ctx, req)
		return prioritize(legacy, nil)
	case ModeBlocking:
		// Optional background coverage is independent from the foreground gate.
		// Enqueue owns a copied request and never delays the blocking decision.
		if background, ok := c.prompt.(PromptBackgroundAuditEngine); ok && background.HasBackgroundAudit() {
			_ = c.prompt.Enqueue(ctx, req.Clone())
		}
		return c.checkBlocking(ctx, req)
	default:
		if recorder, ok := c.prompt.(PromptAuditGapRecorder); ok {
			recorder.CaptureAuditGap(ctx, req.Clone())
		}
		legacy, _ := c.checkLegacy(ctx, req)
		return prioritize(legacy, nil)
	}
}

func (c *Coordinator) checkBlocking(ctx context.Context, req Request) Decision {
	var wg sync.WaitGroup
	wg.Add(2)
	var legacy *LegacyDecision
	var prompt *PromptDecision
	go func() {
		defer wg.Done()
		legacy, _ = c.checkLegacy(ctx, req)
	}()
	go func() {
		defer wg.Done()
		if c.prompt == nil {
			prompt = unavailablePromptDecision(ErrorCodeUnavailable)
			return
		}
		result, err := c.prompt.Evaluate(ctx, req.Clone())
		if err != nil {
			var guardErr *GuardError
			if errors.As(err, &guardErr) && guardErr.Code == ErrorCodeInvalidResponse {
				prompt = unavailablePromptDecision(ErrorCodeInvalidResponse)
				return
			}
			prompt = unavailablePromptDecision(ErrorCodeUnavailable)
			return
		}
		if result == nil {
			prompt = unavailablePromptDecision(ErrorCodeUnavailable)
			return
		}
		prompt = result
	}()
	wg.Wait()
	return prioritize(legacy, prompt)
}

func (c *Coordinator) checkLegacy(ctx context.Context, req Request) (*LegacyDecision, error) {
	if c.legacy == nil {
		return nil, nil
	}
	return c.legacy.Check(ctx, req)
}

func prioritize(legacy *LegacyDecision, prompt *PromptDecision) Decision {
	if legacy != nil && legacy.Blocked {
		status := legacy.StatusCode
		if status < 400 || status > 599 {
			status = http.StatusForbidden
		}
		code := legacy.ErrorCode
		if code == "" {
			code = "content_policy_violation"
		}
		return Decision{
			Kind: DecisionBlock, HTTPStatus: status, ErrorCode: code, ClientMessage: legacy.Message,
			Legacy: legacy, Prompt: prompt, AllowNextStage: false,
		}
	}
	if prompt == nil {
		return allowDecision(legacy, nil)
	}
	switch prompt.Kind {
	case DecisionBlock:
		return Decision{Kind: DecisionBlock, HTTPStatus: http.StatusForbidden, ErrorCode: ErrorCodeBlocked,
			ClientMessage: "提示词安全审计拒绝了该请求，请调整输入后重试", Legacy: legacy, Prompt: prompt}
	case DecisionInvalid:
		return Decision{Kind: DecisionInvalid, HTTPStatus: http.StatusServiceUnavailable, ErrorCode: ErrorCodeInvalidResponse,
			ClientMessage: "提示词安全审计暂时不可用，请稍后重试", Legacy: legacy, Prompt: prompt}
	case DecisionUnavailable:
		return Decision{Kind: DecisionUnavailable, HTTPStatus: http.StatusServiceUnavailable, ErrorCode: ErrorCodeUnavailable,
			ClientMessage: "提示词安全审计暂时不可用，请稍后重试", Legacy: legacy, Prompt: prompt}
	case DecisionFlag:
		return Decision{Kind: DecisionFlag, HTTPStatus: http.StatusOK, Legacy: legacy, Prompt: prompt, AllowNextStage: true}
	default:
		return allowDecision(legacy, prompt)
	}
}

func allowDecision(legacy *LegacyDecision, prompt *PromptDecision) Decision {
	return Decision{Kind: DecisionAllow, HTTPStatus: http.StatusOK, Legacy: legacy, Prompt: prompt, AllowNextStage: true}
}

func unavailablePromptDecision(code string) *PromptDecision {
	kind := DecisionUnavailable
	if code == ErrorCodeInvalidResponse {
		kind = DecisionInvalid
	}
	return &PromptDecision{Kind: kind, ErrorCode: code, AllowNextStage: false}
}
