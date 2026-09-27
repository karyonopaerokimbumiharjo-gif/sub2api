package service

import (
	"context"
	"encoding/json"
	"github.com/Wei-Shaw/sub2api/internal/pkg/auditpolicy"
	"github.com/Wei-Shaw/sub2api/internal/pkg/typesafe"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestContentModerationNativePolicySingleCallAndBioTiers(t *testing.T) {
	for _, tier := range []string{"B0", "B1", "B2", "B3", "B4"} {
		t.Run(tier, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				var request typesafe.Request
				require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
				require.Len(t, request.Questions, 21)
				for _, id := range []string{"intent_violent", "intent_non_violent_illegal_acts", "intent_sexual_content_or_sexual_acts", "intent_suicide_and_self_harm"} {
					require.NotContains(t, request.Questions, id)
				}
				answers := map[string]any{}
				for id, q := range request.Questions {
					if q.Type == "choice" {
						probabilities := map[string]float64{}
						for k := range q.Criteria {
							probabilities[k] = 0
						}
						probabilities[tier] = 1
						answers[id] = map[string]any{"type": "choice", "choice": tier, "confidence": 1, "probabilities": probabilities}
					} else {
						answers[id] = map[string]any{"type": "noul", "noul": 0}
					}
				}
				require.NoError(t, json.NewEncoder(w).Encode(map[string]any{"model": "jev-test", "answers": answers}))
			}))
			defer server.Close()
			cfg := defaultContentModerationConfig()
			cfg.Enabled = true
			cfg.Engine = "typesafe"
			cfg.RecordNonHits = true
			cfg.TypeSafe = &ContentModerationEngineConfig{BaseURL: "https://api.typesafe.ai", Model: "jev-test", APIKeys: []string{"fixture-key"}, TimeoutMS: 3000, Thresholds: ContentModerationDefaultThresholds()}
			raw, _ := json.Marshal(cfg)
			repo := &contentModerationTestRepo{}
			svc := NewContentModerationService(&contentModerationTestSettingRepo{values: map[string]string{SettingKeyRiskControlEnabled: "true", SettingKeyContentModerationConfig: string(raw)}}, repo, nil, nil, nil, nil, nil, nil)
			svc.httpClient = nativeAuditTestClient(server)
			scanners := []string{}
			for id := range auditpolicy.IntentRubrics {
				scanners = append(scanners, id)
			}
			d, err := svc.Check(context.Background(), ContentModerationCheckInput{Strict: true, PolicyScanners: scanners, OperatorPolicyEnabled: true, Protocol: ContentModerationProtocolOpenAIResponses, Body: []byte(`{"input":"General public health education."}`)})
			require.NoError(t, err)
			require.Equal(t, 1, calls)
			require.Equal(t, tier, d.BioTier)
			require.Equal(t, tier == "B2" || tier == "B3" || tier == "B4", d.Blocked)
			logs := requireContentModerationLogCount(t, repo, 1)
			require.Equal(t, TypeSafePolicyRulesVersion, logs[0].EngineMeta.RulesVersion)
			if tier == "B2" {
				require.Equal(t, "review_required", logs[0].Action)
				require.False(t, logs[0].Flagged)
				require.Zero(t, logs[0].ViolationCount)
			}
		})
	}
}

func TestContentModerationLocalControlsAndSingleNotificationRecord(t *testing.T) {
	cfg := defaultContentModerationConfig()
	cfg.Enabled = false // local controls must not enable the other model engine
	cfg.BlockMessage = "test refusal"
	cfg.BlockStatus = 409
	cfg.EmailOnHit = false
	cfg.AutoBanEnabled = false
	cfg.BlockedKeywords = []string{"LOCAL_TEST_DENY"}
	cfg.KeywordBlockingMode = ContentModerationKeywordModeKeywordAndAPI
	raw, _ := json.Marshal(cfg)
	repo := &contentModerationTestRepo{}
	svc := NewContentModerationService(&contentModerationTestSettingRepo{values: map[string]string{SettingKeyRiskControlEnabled: "true", SettingKeyContentModerationConfig: string(raw)}}, repo, nil, nil, nil, nil, nil, nil)
	input := ContentModerationCheckInput{RequestID: "local-fixture", Protocol: ContentModerationProtocolOpenAIResponses, Body: []byte(`{"input":"LOCAL_TEST_DENY"}`)}
	d, err := svc.CheckLocalKeywords(context.Background(), input, "LOCAL_TEST_DENY")
	require.NoError(t, err)
	require.True(t, d.Blocked)
	require.Equal(t, 409, d.StatusCode)
	logs := requireContentModerationLogCount(t, repo, 1)
	require.Equal(t, "legacy", logs[0].EngineMeta.AuditSource)
	for i := 0; i < 2; i++ {
		svc.RecordLocalAuditHit(context.Background(), ContentModerationCheckInput{RequestID: "single-fixture"}, "ordinary fixture", "ordinary fixture", "legacy", "test", map[string]float64{"test": 1}, true)
	}
	logs = requireContentModerationLogCount(t, repo, 2)
	require.Equal(t, "notification", logs[1].EngineMeta.EventRole)
}
