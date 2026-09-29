package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

func TestNativeOriginalProfileUsesUnmodifiedThirteenQuestions(t *testing.T) {
	cfg := defaultContentModerationConfig()
	svc := &ContentModerationService{settingRepo: &contentModerationTestSettingRepo{values: map[string]string{"prompt_audit_config": `{"native_audit_profile":"upstream","native_risk_categories":["pii","operator_ctf","biological_risk"],"operator_policy_enabled":true,"scanners":["biological_risk"]}`}}}
	require.NoError(t, svc.applySavedNativePolicyForTest(context.Background(), cfg))
	require.Equal(t, typeSafeModerationQuestions(), typeSafePolicyQuestions(cfg))
	require.Len(t, typeSafePolicyQuestions(cfg), 13)
	require.False(t, cfg.OperatorPolicyEnabled)
	require.Empty(t, cfg.PolicyScanners)
	require.NotContains(t, cfg.Thresholds, "intent_biological_risk")
	cfg.Engine = "typesafe"
	meta := moderationAttemptMeta(cfg, ContentModerationInput{})
	require.Equal(t, TypeSafeModerationRulesVersion, meta.RulesVersion)
	require.Equal(t, "upstream", meta.NativeAuditProfile)
	require.Equal(t, 13, meta.QuestionCount)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request typesafe.Request
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		require.Equal(t, typeSafeModerationQuestions(), request.Questions)
		answers := map[string]any{}
		for id := range request.Questions {
			answers[id] = map[string]any{"type": "noul", "noul": 0.01}
		}
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"model": "jev-fixture", "answers": answers}))
	}))
	defer server.Close()
	svc.httpClient = nativeAuditTestClient(server)
	cfg.BaseURL, cfg.Model = "https://api.typesafe.ai", "jev-fixture"
	status := 0
	result, err := svc.callTypeSafeModeration(context.Background(), cfg, "fixture-key", "Ordinary format fixture.", &status)
	require.NoError(t, err)
	require.Equal(t, 200, status)
	require.Equal(t, "upstream", result.EngineMeta.NativeAuditProfile)
	require.Equal(t, TypeSafeModerationRulesVersion, result.EngineMeta.RulesVersion)
	require.Len(t, result.CategoryScores, 13)
	// A historical enhanced-policy hit must not preempt the original model.
	text := "Ordinary format fixture."
	content := ContentModerationInput{Text: text}
	content.Normalize()
	hashes := &contentModerationTestHashCache{hashes: map[string]struct{}{content.Hash(): {}}}
	extensionHash := sha256.Sum256([]byte("sub2api-0.2.8:extensions:biological_risk:" + content.Hash()))
	hashes.hashes[hex.EncodeToString(extensionHash[:])] = struct{}{}
	cfg.Enabled, cfg.RecordNonHits, cfg.PreHashCheckEnabled = true, true, true
	cfg.TypeSafe = &ContentModerationEngineConfig{BaseURL: "https://api.typesafe.ai", Model: "jev-fixture", APIKeys: []string{"fixture-key"}, TimeoutMS: 3000, Thresholds: ContentModerationDefaultThresholds()}
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	repo := &contentModerationTestRepo{}
	svc = NewContentModerationService(&contentModerationTestSettingRepo{values: map[string]string{SettingKeyRiskControlEnabled: "true", SettingKeyContentModerationConfig: string(raw)}}, repo, hashes, nil, nil, nil, nil, nil)
	svc.httpClient = nativeAuditTestClient(server)
	decision, err := svc.Check(context.Background(), ContentModerationCheckInput{NativeAuditProfile: "upstream", PolicyCategories: []string{"pii"}, OperatorPolicyEnabled: true, Strict: true, Protocol: ContentModerationProtocolOpenAIResponses, Body: []byte(`{"input":"Ordinary format fixture."}`)})
	require.NoError(t, err)
	require.True(t, decision.Allowed)
	require.NotEqual(t, ContentModerationActionHashBlock, decision.Action)
	logs := requireContentModerationLogCount(t, repo, 1)
	require.Equal(t, "upstream", logs[0].EngineMeta.NativeAuditProfile)
	require.Equal(t, 13, logs[0].EngineMeta.QuestionCount)
}
