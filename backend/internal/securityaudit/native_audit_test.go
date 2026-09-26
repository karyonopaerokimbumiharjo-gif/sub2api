package securityaudit

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
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
