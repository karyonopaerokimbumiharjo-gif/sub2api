package securityaudit

import (
	"context"
	"encoding/json"
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

func TestOriginalNativeProfileSkipsOnlyCustomNativeRules(t *testing.T) {
	repo := &fakeJobRepository{}
	cfg := &fakeConfigStore{active: true, cfg: ActiveConfig{NativeAuditEnabled: true, NativeAuditProfile: "upstream", OperatorPolicyEnabled: true, ConfigVersion: 4}}
	svc := &PromptService{config: cfg, evaluator: newGuardEvaluator(nil, repo, NewAtomicMetrics(), 1, 1)}
	req := Request{RequestID: "profile-test", Protocol: "openai_responses", Stage: "http", Body: []byte(`{"input":"CTF event schedule"}`)}
	d, err := svc.CheckOperatorPolicy(context.Background(), req)
	require.NoError(t, err)
	require.Nil(t, d)
	d, err = svc.EvaluateNativeHardRules(context.Background(), req)
	require.NoError(t, err)
	require.True(t, d.AllowNextStage)
	require.Zero(t, repo.recordBlockingCalls)
	// The saved enhanced/local global policy is restored when native is off.
	cfg.cfg.NativeAuditEnabled = false
	d, err = svc.CheckOperatorPolicy(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, DecisionBlock, d.Kind)
}

func TestNativeAuditProfileRoundTripKeepsEnhancedSelections(t *testing.T) {
	current := DefaultStorageConfig()
	current.NativeRiskCategories = []string{"pii", "operator_ctf"}
	public := PublicFromStorage(current, true, nil)
	require.Equal(t, "enhanced", public.NativeAuditProfile)
	raw, err := json.Marshal(public)
	require.NoError(t, err)
	var req UpdateConfigRequest
	require.NoError(t, json.Unmarshal(raw, &req))
	req.NativeAuditEnabled, req.NativeAuditProfile = true, "upstream"
	manager := &ConfigManager{}
	next, err := manager.buildNextStorage(current, req, 1)
	require.NoError(t, err)
	raw, err = json.Marshal(next)
	require.NoError(t, err)
	persisted, err := ParseStorageConfig(string(raw))
	require.NoError(t, err)
	require.Equal(t, "upstream", PublicFromStorage(persisted, true, nil).NativeAuditProfile)
	require.Equal(t, current.NativeRiskCategories, persisted.NativeRiskCategories)
	req.NativeAuditProfile = "" // a previous client must not silently switch modes
	next, err = manager.buildNextStorage(persisted, req, 1)
	require.NoError(t, err)
	require.Equal(t, "upstream", next.NativeAuditProfile)
	req.NativeAuditProfile = "enhanced"
	next, err = manager.buildNextStorage(persisted, req, 1)
	require.NoError(t, err)
	require.Equal(t, current.NativeRiskCategories, next.NativeRiskCategories)
	bad := persisted
	bad.NativeAuditProfile = "unknown-profile"
	require.Error(t, validateStorageConfig(bad))
	require.NotEqual(t, changeSummary(next), changeSummary(persisted))
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

func TestNativeCategoryConfigurationRoundTripAndLegacyMaster(t *testing.T) {
	current := DefaultStorageConfig()
	public := PublicFromStorage(current, true, nil)
	require.Len(t, public.NativeRiskCatalog, 21)
	raw, err := json.Marshal(public)
	require.NoError(t, err)
	var req UpdateConfigRequest
	require.NoError(t, json.Unmarshal(raw, &req))
	req.ExpectedConfigVersion = current.ConfigVersion
	req.NativeAuditEnabled = true
	req.NativeRiskCategories = []string{"pii", "operator_repository"}
	enabled := true
	req.OperatorPolicyEnabled = &enabled
	manager := &ConfigManager{}
	next, err := manager.buildNextStorage(current, req, 1)
	require.NoError(t, err)
	raw, err = json.Marshal(next)
	require.NoError(t, err)
	persisted, err := ParseStorageConfig(string(raw))
	require.NoError(t, err)
	require.Equal(t, req.NativeRiskCategories, PublicFromStorage(persisted, true, nil).NativeRiskCategories)
	cloned := cloneStorageConfig(persisted)
	cloned.NativeRiskCategories[0] = "hate"
	require.Equal(t, "pii", persisted.NativeRiskCategories[0])
	req.NativeRiskCategories = nil
	enabled = false
	next, err = manager.buildNextStorage(persisted, req, 1)
	require.NoError(t, err)
	require.Equal(t, []string{"pii"}, next.NativeRiskCategories)
	enabled = true
	restored, err := manager.buildNextStorage(next, req, 1)
	require.NoError(t, err)
	require.Equal(t, []string{"pii", "operator_ctf", "operator_repository"}, restored.NativeRiskCategories)
	req.NativeRiskCategories = []string{"not-a-category"}
	_, err = manager.buildNextStorage(restored, req, 1)
	require.Error(t, err)
}

func TestSelectedGlobalCategoriesAreIndependent(t *testing.T) {
	require.Nil(t, matchSelectedGlobalRequestPolicy([]byte(`{"input":"CTF event schedule"}`), false, true))
	require.NotNil(t, matchSelectedGlobalRequestPolicy([]byte(`{"input":"CTF event schedule"}`), true, false))
	repo := deniedRepositoryEntries[0].FullName
	body, _ := json.Marshal(map[string]string{"input": repo})
	require.NotNil(t, matchSelectedGlobalRequestPolicy(body, false, true))
	require.Nil(t, matchSelectedGlobalRequestPolicy(body, false, false))
}
