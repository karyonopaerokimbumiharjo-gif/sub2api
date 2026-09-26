package securityaudit

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

type nativePromptFake struct {
	fakePromptEngine
	block bool
}

func (*nativePromptFake) NativeAuditEnabled() bool { return true }
func (*nativePromptFake) RequireJevSafety() bool   { return true }
func (f *nativePromptFake) EvaluateNativeHardRules(context.Context, Request) (*PromptDecision, error) {
	if f.block {
		return &PromptDecision{Kind: DecisionBlock}, nil
	}
	return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
}

type nativeLegacyFake struct {
	fakeLegacyEngine
	ready bool
}

func (f *nativeLegacyFake) NativeAuditReady(context.Context) bool { return f.ready }
func TestNativeAuditIsExclusiveAndFailClosed(t *testing.T) {
	p := &nativePromptFake{fakePromptEngine: fakePromptEngine{mode: ModeBlocking}}
	l := &nativeLegacyFake{ready: true}
	c := NewCoordinator(l, p)
	require.Equal(t, DecisionAllow, c.Check(context.Background(), Request{RequireJev: true}).Kind)
	require.Equal(t, int64(1), l.calls.Load())
	require.Zero(t, p.evaluates.Load())
	require.Zero(t, p.enqueues.Load())
	require.False(t, c.ShouldAuditOutput(Request{}, DecisionAllow))
	l.ready = false
	require.Equal(t, DecisionUnavailable, c.Check(context.Background(), Request{}).Kind)
	p.block = true
	require.Equal(t, DecisionBlock, c.Check(context.Background(), Request{}).Kind)
	require.Equal(t, int64(1), l.calls.Load())
}

func TestNativeAuditHardRulesPersistActualNativeSource(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		matched     bool
	}{
		{name: "existing hard-rule fixture", input: explicitBypassFixture, matched: true},
		{name: "ordinary request continues without a synthetic event", input: "Reply with exactly 4."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &fakeJobRepository{}
			scannerCalls := 0
			evaluator := newGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
				scannerCalls++
				return nil, nil
			}), repo, NewAtomicMetrics(), 2, 2)
			svc := &PromptService{
				config: &fakeConfigStore{active: true, cfg: ActiveConfig{
					NativeAuditEnabled: true, RiskControlEnabled: true, Enabled: true,
					ConfigVersion: 7, Scanners: AllScannerIDs,
				}},
				evaluator: evaluator,
			}
			req := Request{
				RequestID: "native-source-check", Protocol: "openai_responses", Stage: "http",
				Body: []byte(`{"input":` + string(mustJSON(t, tc.input)) + `}`),
			}
			decision, err := svc.EvaluateNativeHardRules(context.Background(), req)
			require.NoError(t, err)
			require.Zero(t, scannerCalls, "local hard rules must not invoke a classifier")
			require.Equal(t, "http", req.Stage, "source marking must not mutate the caller's request")
			if !tc.matched {
				require.Equal(t, DecisionAllow, decision.Kind)
				require.True(t, decision.AllowNextStage)
				require.Zero(t, repo.recordBlockingCalls)
				return
			}
			require.Equal(t, DecisionBlock, decision.Kind)
			require.False(t, decision.AllowNextStage)
			require.Equal(t, 1, repo.recordBlockingCalls)
			require.Equal(t, "native_hard_rules", repo.recordBlockingSnapshot.Stage)
			require.Equal(t, req.RequestID, repo.recordBlockingSnapshot.RequestID)
			require.Equal(t, explicitBypassPolicyID, repo.recordBlockingResult.PolicyID)
			require.NotEmpty(t, repo.recordBlockingSnapshot.FullPrompt)
			require.NotEmpty(t, repo.recordBlockingSnapshot.AuditedPrompt)
			event := &Event{ID: 1, Snapshot: repo.recordBlockingSnapshot}
			decoratePromptAuditEvent(event)
			require.Equal(t, AuditSourceNative, event.AuditSource)
			require.Equal(t, "prompt_audit", event.EventOrigin)
		})
	}
}
