package securityaudit

import (
	"context"
	"github.com/stretchr/testify/require"
	"net/url"
	"testing"
)

func TestOperatorPolicyRecoveredCatalogAndBoundaries(t *testing.T) {
	require.Len(t, deniedRepositoryEntries, 539)
	for _, entry := range deniedRepositoryEntries {
		for _, text := range []string{entry.FullName, "https://github.com/" + entry.FullName + ".", "https://raw.githubusercontent.com/" + entry.FullName + "/main/README.md", url.PathEscape(entry.FullName)} {
			result := matchOperatorRepositoryPolicy(text)
			require.NotNil(t, result, entry.FullName)
			require.Equal(t, ActionBlock, result.Action)
		}
	}
	for _, text := range []string{"CTF event schedule", "ＣＴＦ 竞赛", "夺旗赛介绍"} {
		require.NotNil(t, MatchCTFPolicy(text))
	}
	for _, text := range []string{"set a feature flag in Go", "general cryptography lecture", "write a Vue component"} {
		require.Nil(t, matchGlobalPolicyText(text))
	}
	require.NotNil(t, matchGlobalRequestPolicy([]byte(`{"input":"hello","tools":[{"description":"CTF schedule"}]}`)))
	require.Nil(t, matchGlobalRequestPolicy([]byte(`{"input":"hello","global_policy_id":"known_jailbreak_repository"}`)))
}

func TestOperatorPolicyToggleAndActualSource(t *testing.T) {
	for _, native := range []bool{false, true} {
		repo := &fakeJobRepository{}
		cfg := &fakeConfigStore{active: true, cfg: ActiveConfig{NativeAuditEnabled: native, OperatorPolicyEnabled: true, ConfigVersion: 4}}
		svc := &PromptService{config: cfg, evaluator: newGuardEvaluator(nil, repo, NewAtomicMetrics(), 1, 1)}
		req := Request{RequestID: "operator-test", Protocol: "openai_responses", Stage: "http", Body: []byte(`{"input":"CTF event schedule"}`)}
		d, err := svc.CheckOperatorPolicy(context.Background(), req)
		require.NoError(t, err)
		require.Equal(t, DecisionBlock, d.Kind)
		require.Equal(t, 1, repo.recordBlockingCalls)
		event := &Event{ID: 1, Snapshot: repo.recordBlockingSnapshot}
		decorateAuditEventSource(event)
		if native {
			require.Equal(t, AuditSourceNative, event.AuditSource)
		} else {
			require.Equal(t, AuditSourceLegacy, event.AuditSource)
		}
		cfg.cfg.OperatorPolicyEnabled = false
		d, err = svc.CheckOperatorPolicy(context.Background(), req)
		require.NoError(t, err)
		require.Nil(t, d)
		require.Equal(t, 1, repo.recordBlockingCalls)
	}
}

type exclusiveLocalFake struct{ fakePromptEngine }

func (*exclusiveLocalFake) AuditSelectionExclusive() bool { return true }
func TestLocalAuditNeverInvokesNativeModel(t *testing.T) {
	for _, mode := range []Mode{ModeBlocking, ModeAsync, ModeOff} {
		local := &exclusiveLocalFake{fakePromptEngine: fakePromptEngine{mode: mode, decision: &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}}}
		native := &fakeLegacyEngine{decision: &LegacyDecision{Blocked: true}}
		d := NewCoordinator(native, local).Check(context.Background(), Request{})
		require.True(t, d.AllowNextStage)
		require.Zero(t, native.calls.Load())
	}
}

func TestEmailFilterCanonicalizationAndDeletionHash(t *testing.T) {
	f := EventFilter{UserEmail: " Person@Example.Test "}
	where, args := buildEventWhere(f, 1)
	require.Contains(t, where, "lower(e.user_email_snapshot)=$1")
	require.Equal(t, []any{"person@example.test"}, args)
	require.Equal(t, canonicalEventFilter(f), canonicalEventFilter(EventFilter{UserEmail: "person@example.test"}))
	require.NotEqual(t, canonicalEventFilter(f), canonicalEventFilter(EventFilter{}))
}

func TestNativeSelectionReportsDormantCustomAudit(t *testing.T) {
	stored := DefaultStorageConfig()
	stored.NativeAuditEnabled = true
	stored.Enabled = true
	stored.BlockingEnabled = true
	require.Equal(t, ModeOff, PublicFromStorage(stored, true, nil).EffectiveMode)
	manager := &ConfigManager{}
	manager.expectedBlocking.Store(true)
	manager.snapshot.Store(&activeConfigSnapshot{active: ActiveConfig{NativeAuditEnabled: true, RiskControlEnabled: true, Enabled: true, BlockingEnabled: true}})
	require.False(t, manager.BlockingActivationDegraded())
	require.Equal(t, ModeOff, manager.EffectiveMode())
	manager.configUntrusted.Store(true)
	require.True(t, manager.BlockingActivationDegraded(), "invalid activation must still fail closed")
}
