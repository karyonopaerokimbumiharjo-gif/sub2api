package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/auditpolicy"
	"github.com/Wei-Shaw/sub2api/internal/pkg/typesafe"
	"github.com/stretchr/testify/require"
)

func TestOriginalExtensionsSendExactQuestionsAndDetermineBioVerdicts(t *testing.T) {
	for _, tier := range []string{"B0", "B1", "B2", "B3", "B4"} {
		t.Run(tier, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request typesafe.Request
				require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
				require.Len(t, request.Questions, 16)
				for id, q := range typeSafeModerationQuestions() {
					require.Equal(t, q, request.Questions[id])
				}
				require.Contains(t, request.Questions, "bio_tier")
				require.Contains(t, request.Questions, "operator_ctf")
				require.Contains(t, request.Questions, "operator_repository")
				require.NotContains(t, request.Questions, "intent_pii")
				answers := map[string]any{}
				for id := range request.Questions {
					answers[id] = map[string]any{"type": "noul", "noul": 0.01}
				}
				probabilities := map[string]float64{"B0": 0, "B1": 0, "B2": 0, "B3": 0, "B4": 0}
				probabilities[tier] = 1
				answers["bio_tier"] = map[string]any{"type": "choice", "choice": tier, "probabilities": probabilities, "confidence": 1}
				require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"model": "jev-fixture", "answers": answers}))
			}))
			defer server.Close()
			cfg := defaultContentModerationConfig()
			cfg.Enabled = true
			cfg.Engine = "typesafe"
			cfg.RecordNonHits = true
			cfg.TypeSafe = &ContentModerationEngineConfig{BaseURL: "https://api.typesafe.ai", Model: "jev-fixture", APIKeys: []string{"fixture-key"}, TimeoutMS: 3000, Thresholds: ContentModerationDefaultThresholds()}
			raw, err := json.Marshal(cfg)
			require.NoError(t, err)
			repo := &contentModerationTestRepo{}
			svc := NewContentModerationService(&contentModerationTestSettingRepo{values: map[string]string{SettingKeyRiskControlEnabled: "true", SettingKeyContentModerationConfig: string(raw)}}, repo, nil, nil, nil, nil, nil, nil)
			svc.httpClient = nativeAuditTestClient(server)
			extensions := []string{"biological_risk", "operator_ctf", "operator_repository"}
			d, err := svc.Check(context.Background(), ContentModerationCheckInput{NativeAuditProfile: "upstream", NativeUpstreamExtensions: extensions, PolicyCategories: []string{"pii"}, Strict: true, Protocol: ContentModerationProtocolOpenAIResponses, Body: []byte(`{"input":"Ordinary synthetic safety-classifier fixture."}`)})
			require.NoError(t, err)
			require.Equal(t, tier == "B2" || tier == "B3" || tier == "B4", d.Blocked)
			require.Equal(t, tier, d.BioTier)
			if tier == "B2" {
				require.Equal(t, "review_required", d.Action)
			}
			logs := requireContentModerationLogCount(t, repo, 1)
			require.Equal(t, extensions, logs[0].EngineMeta.NativeUpstreamExtensions)
			require.Equal(t, 16, logs[0].EngineMeta.QuestionCount)
			require.Equal(t, TypeSafeUpstreamExtensionsRulesVersion, logs[0].EngineMeta.RulesVersion)
			require.Equal(t, auditpolicy.UpstreamCategories(extensions), logs[0].EngineMeta.SelectedCategories)
		})
	}
}

func TestOriginalExtensionsAdminProbeAndDeselection(t *testing.T) {
	cfg := defaultContentModerationConfig()
	svc := &ContentModerationService{settingRepo: &contentModerationTestSettingRepo{values: map[string]string{"prompt_audit_config": `{"native_audit_profile":"upstream","native_upstream_extensions":["operator_ctf"],"native_risk_categories":["pii","operator_repository"],"operator_policy_enabled":true}`}}}
	require.NoError(t, svc.applySavedNativePolicyForTest(context.Background(), cfg))
	require.Len(t, typeSafePolicyQuestions(cfg), 14)
	require.Contains(t, typeSafePolicyQuestions(cfg), "operator_ctf")
	require.NotContains(t, typeSafePolicyQuestions(cfg), "operator_repository")
	require.NotContains(t, typeSafePolicyQuestions(cfg), "bio_tier")
	applyModerationPolicySelection(cfg, nil, nil, true, "upstream", nil)
	require.Equal(t, typeSafeModerationQuestions(), typeSafePolicyQuestions(cfg))
	require.Empty(t, cfg.NativeUpstreamExtensions)
	require.False(t, cfg.OperatorPolicyEnabled)
}

func TestOriginalExtensionsCannotSilentlyUseAnUnsupportedEngine(t *testing.T) {
	cfg := defaultContentModerationConfig()
	cfg.NativeUpstreamExtensions = []string{"biological_risk"}
	status := 0
	_, err := (&ContentModerationService{}).callModerationOnceWithInput(context.Background(), cfg, "fixture-key", "ordinary fixture", &status)
	require.ErrorContains(t, err, "require the TypeSafe/Jev engine")
	require.Zero(t, status)
}
