package securityaudit

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/auditpolicy"
	"github.com/stretchr/testify/require"
)

func TestOriginalExtensionsPersistIndependentlyAndOldClientsPreserveThem(t *testing.T) {
	current := DefaultStorageConfig()
	current.NativeRiskCategories = []string{"pii", "operator_ctf"}
	raw, err := json.Marshal(PublicFromStorage(current, true, nil))
	require.NoError(t, err)
	var req UpdateConfigRequest
	require.NoError(t, json.Unmarshal(raw, &req))
	req.NativeAuditEnabled, req.NativeAuditProfile = true, "upstream"
	req.NativeUpstreamExtensions = []string{"operator_repository", "biological_risk", "operator_repository"}
	manager := &ConfigManager{}
	next, err := manager.buildNextStorage(current, req, 1)
	require.NoError(t, err)
	raw, err = json.Marshal(next)
	require.NoError(t, err)
	saved, err := ParseStorageConfig(string(raw))
	require.NoError(t, err)
	public := PublicFromStorage(saved, true, nil)
	require.Equal(t, []string{"biological_risk", "operator_repository"}, public.NativeUpstreamExtensions)
	require.Equal(t, current.NativeRiskCategories, saved.NativeRiskCategories)
	active, err := ActiveFromStorage(saved, true, nil)
	require.NoError(t, err)
	clone := cloneActiveConfig(active)
	clone.NativeUpstreamExtensions[0] = "operator_ctf"
	require.Equal(t, "biological_risk", active.NativeUpstreamExtensions[0])
	req.NativeUpstreamExtensions = nil
	req.NativeAuditProfile = "enhanced"
	next, err = manager.buildNextStorage(saved, req, 1)
	require.NoError(t, err)
	require.Equal(t, saved.NativeUpstreamExtensions, next.NativeUpstreamExtensions)
	req.NativeUpstreamExtensions = []string{}
	next, err = manager.buildNextStorage(saved, req, 1)
	require.NoError(t, err)
	require.Empty(t, next.NativeUpstreamExtensions)
	require.NotEqual(t, changeSummary(saved), changeSummary(next))
	req.NativeUpstreamExtensions = []string{"pii"}
	require.Error(t, validateUpdateConfigRequest(req))
	saved.NativeUpstreamExtensions = []string{"pii"}
	require.Error(t, validateStorageConfig(saved))
}

func TestOriginalGlobalExtensionsAreIndependentOfEnhancedMaster(t *testing.T) {
	for _, category := range []string{"operator_ctf", "operator_repository"} {
		repo := &fakeJobRepository{}
		cfg := &fakeConfigStore{active: true, cfg: ActiveConfig{NativeAuditEnabled: true, NativeAuditProfile: "upstream", OperatorPolicyEnabled: false, NativeUpstreamExtensions: []string{category}, ConfigVersion: 4}}
		svc := &PromptService{config: cfg, evaluator: newGuardEvaluator(nil, repo, NewAtomicMetrics(), 1, 1)}
		for _, tc := range []struct{ category, text string }{{"operator_ctf", "CTF event schedule"}, {"operator_repository", deniedRepositoryEntries[0].FullName}} {
			body, _ := json.Marshal(map[string]string{"input": tc.text})
			req := Request{RequestID: "extension-fixture", Protocol: "openai_responses", Stage: "http", Body: body}
			d, err := svc.CheckOperatorPolicy(context.Background(), req)
			require.NoError(t, err)
			if tc.category == category {
				require.NotNil(t, d)
				require.Equal(t, DecisionBlock, d.Kind)
				require.Equal(t, "native_hard_rules", d.Snapshot.Stage)
			} else {
				require.Nil(t, d)
			}
		}
		cfg.cfg.NativeUpstreamExtensions = nil
		d, err := svc.CheckOperatorPolicy(context.Background(), Request{Body: []byte(`{"input":"CTF event schedule"}`)})
		require.NoError(t, err)
		require.Nil(t, d)
	}
}

func TestWhitelistPrecedesNativeAndGlobalExtensions(t *testing.T) {
	repo := &fakeJobRepository{}
	cfg := &fakeConfigStore{active: true, cfg: ActiveConfig{RiskControlEnabled: true, NativeAuditEnabled: true, NativeAuditProfile: "upstream", NativeUpstreamExtensions: auditpolicy.NormalizeUpstreamExtensions([]string{"operator_ctf"})}}
	svc := &PromptService{config: cfg, evaluator: newGuardEvaluator(nil, repo, NewAtomicMetrics(), 1, 1)}
	legacy := &fakeLegacyEngine{}
	coordinator := NewCoordinator(legacy, svc)
	req := Request{PromptAuditBypass: true, Protocol: "openai_responses", Stage: "http", Body: []byte(`{"input":"CTF event schedule"}`)}
	d := coordinator.Check(context.Background(), req)
	require.True(t, d.AllowNextStage)
	require.Zero(t, repo.recordBlockingCalls)
	require.Zero(t, legacy.calls.Load())
	req.PromptAuditBypass = false
	d = coordinator.Check(context.Background(), req)
	require.Equal(t, DecisionBlock, d.Kind)
	require.Equal(t, 1, repo.recordBlockingCalls)
}
