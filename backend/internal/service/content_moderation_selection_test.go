package service

import (
	"context"
	"encoding/json"
	"github.com/Wei-Shaw/sub2api/internal/pkg/typesafe"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNativeSelectedCategoryAloneDeterminesVerdict(t *testing.T) {
	for _, tc := range []struct {
		category, question string
		score              float64
		blocked            bool
	}{
		{"pii", "intent_pii", 0.99, true}, {"harassment", "harassment", 0.1, false},
	} {
		t.Run(tc.category, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				var request typesafe.Request
				require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
				require.Len(t, request.Questions, 1)
				require.Contains(t, request.Questions, tc.question)
				// Extra unsolicited answers must not reactivate deselected categories.
				answers := map[string]any{tc.question: map[string]any{"type": "noul", "noul": tc.score}, "violence": map[string]any{"type": "noul", "noul": 1}}
				require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"model": "jev-fixture", "answers": answers}))
			}))
			defer server.Close()
			cfg := defaultContentModerationConfig()
			cfg.Enabled = true
			cfg.Engine = "typesafe"
			cfg.RecordNonHits = true
			thresholds := ContentModerationDefaultThresholds()
			for id := range thresholds {
				thresholds[id] = 0
			}
			thresholds["harassment"] = .98
			cfg.TypeSafe = &ContentModerationEngineConfig{BaseURL: "https://api.typesafe.ai", Model: "jev-fixture", APIKeys: []string{"fixture-key"}, TimeoutMS: 3000, Thresholds: thresholds}
			raw, _ := json.Marshal(cfg)
			repo := &contentModerationTestRepo{}
			svc := NewContentModerationService(&contentModerationTestSettingRepo{values: map[string]string{SettingKeyRiskControlEnabled: "true", SettingKeyContentModerationConfig: string(raw)}}, repo, nil, nil, nil, nil, nil, nil)
			svc.httpClient = nativeAuditTestClient(server)
			d, err := svc.Check(context.Background(), ContentModerationCheckInput{Strict: true, PolicyCategories: []string{tc.category}, Protocol: ContentModerationProtocolOpenAIResponses, Body: []byte(`{"input":"ordinary synthetic fixture"}`)})
			require.NoError(t, err)
			require.Equal(t, tc.blocked, d.Blocked)
			require.Equal(t, 1, calls)
			logs := requireContentModerationLogCount(t, repo, 1)
			require.Equal(t, []string{tc.category}, logs[0].EngineMeta.SelectedCategories)
			require.Equal(t, 1, logs[0].EngineMeta.QuestionCount)
			require.NotContains(t, logs[0].CategoryScores, "violence")
		})
	}
}

func TestNativeAdminTestUsesSavedSelection(t *testing.T) {
	cfg := defaultContentModerationConfig()
	svc := &ContentModerationService{settingRepo: &contentModerationTestSettingRepo{values: map[string]string{"prompt_audit_config": `{"native_risk_categories":["pii"],"operator_policy_enabled":false,"scanners":["violent"]}`}}}
	require.NoError(t, svc.applySavedNativePolicyForTest(context.Background(), cfg))
	require.Equal(t, []string{"pii"}, cfg.PolicyCategories)
	require.Equal(t, .90, cfg.Thresholds["intent_pii"])
	require.Len(t, typeSafePolicyQuestions(cfg), 1)
	result := buildContentModerationTestAuditResult(&moderationAPIResult{CategoryScores: map[string]float64{"intent_pii": .99}}, cfg.Thresholds)
	require.True(t, result.Flagged)
}
