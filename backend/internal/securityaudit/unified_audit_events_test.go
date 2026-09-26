package securityaudit

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUnifiedAuditSourceUsesExecutionEvidence(t *testing.T) {
	for _, tc := range []struct{ stage, source string }{
		{"http", AuditSourceLegacy}, {"native_hard_rules", AuditSourceNative},
		{"native_moderation", AuditSourceNative}, {"audit_gap", AuditSourceGap},
		{"upstream_feedback", AuditSourceUpstream},
	} {
		event := &Event{ID: 1, Snapshot: PromptSnapshot{Stage: tc.stage}}
		decoratePromptAuditEvent(event)
		require.Equal(t, tc.source, event.AuditSource)
		require.Equal(t, "prompt_audit:1", event.EventKey)
	}
	legacy := &Event{ID: 1, Snapshot: PromptSnapshot{Stage: "audit_gap"}}
	decoratePromptAuditEvent(legacy)
	require.Equal(t, "not_audited", legacy.PolicyCode)
	native := &Event{ID: -1, Snapshot: PromptSnapshot{Stage: "native_moderation", RedactedPreview: "historical excerpt"}}
	decoratePromptAuditEvent(native)
	require.Equal(t, "content_moderation:1", native.EventKey)
	require.Equal(t, int64(1), native.NativeLogID)
	require.Equal(t, "excerpt_only", native.ContentAvailability)
	require.Equal(t, "native_content_moderation", native.PolicySource)
	require.Empty(t, native.Snapshot.FullPrompt)
	require.Empty(t, native.Snapshot.AuditedPrompt)
}

func TestUnifiedAuditListRelationExcludesStoredPromptContent(t *testing.T) {
	// Group/count reads the whole history. This relation must stay independent
	// of potentially large stored prompts, even for content-availability checks.
	relation := unifiedAuditEventRelation(false)
	require.NotContains(t, relation, "full_prompt")
	require.NotContains(t, relation, "audited_prompt")
	projection := pagedAuditEventColumns("e")
	require.Contains(t, projection, "WHERE stored.id=e.id")
	require.Contains(t, projection, "WHERE stored.id= -e.id")
	require.NotContains(t, projection, "%!", "SQL percent wildcards must survive formatting")
}

func TestUnifiedAuditSourceFilterAlsoBoundsDelete(t *testing.T) {
	now, end := time.Now(), time.Now().Add(time.Hour)
	filter := EventFilter{AuditSource: " NATIVE ", StartAt: &now, EndAt: &end}
	require.NoError(t, validateDeleteFilter(filter))
	where, args := buildEventWhere(filter, 1)
	require.Contains(t, where, "native_hard_rules")
	require.Equal(t, "native", args[0])
	require.NotEqual(t, FilterHash(filter, 10), FilterHash(EventFilter{StartAt: &now, EndAt: &end}, 10))
	filter.AuditSource = "unknown-value"
	require.Error(t, validateDeleteFilter(filter))
}

func TestUnifiedAuditHandlerNativeReadAndMutationBoundary(t *testing.T) {
	readCalls := 0
	service := &fakePromptAdminService{get: func(_ context.Context, id int64) (*Event, error) {
		readCalls++
		require.Equal(t, int64(-7), id)
		return &Event{ID: id, AuditSource: AuditSourceNative, EventOrigin: "content_moderation"}, nil
	}, deleteOne: func(context.Context, int64) (*DeleteResult, error) {
		t.Fatal("native read-only ID reached delete service")
		return nil, nil
	}, deleteIDs: func(context.Context, []int64) (*DeleteResult, error) {
		t.Fatal("mixed native/legacy IDs reached delete service")
		return nil, nil
	}}
	router := promptAdminRouter(service)
	response := promptAdminRequest(t, router, http.MethodGet, "/admin/prompt-audit/events/-7", nil)
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), `"event_origin":"content_moderation"`)
	response = promptAdminRequest(t, router, http.MethodDelete, "/admin/prompt-audit/events/-7", nil)
	require.Equal(t, http.StatusBadRequest, response.Code)
	response = promptAdminRequest(t, router, http.MethodPost, "/admin/prompt-audit/events/batch-delete", map[string]any{"ids": []int64{7, -7}})
	require.Equal(t, http.StatusBadRequest, response.Code)
	response = promptAdminRequest(t, router, http.MethodGet, "/admin/prompt-audit/events/-9223372036854775808", nil)
	require.Equal(t, http.StatusBadRequest, response.Code)
	require.Equal(t, 1, readCalls)
	response = promptAdminRequest(t, router, http.MethodGet, "/admin/prompt-audit/events?audit_source=not-real", nil)
	require.Equal(t, http.StatusBadRequest, response.Code)
}

func TestUnifiedAuditRepositoryMixesSourcesBeforePaginationAndPreservesEvidence(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	legacy, err := repo.RecordBlocking(ctx, integrationSnapshot("legacy"), 1, integrationResult(EventPass), true)
	require.NoError(t, err)
	hardSnapshot := integrationSnapshot("hard")
	hardSnapshot.Stage = "native_hard_rules"
	hardRule, err := repo.RecordBlocking(ctx, hardSnapshot, 1, integrationResult(EventCritical), true)
	require.NoError(t, err)
	var nativeID int64
	err = db.QueryRow(`INSERT INTO content_moderation_logs
		(request_id,endpoint,model,action,flagged,highest_category,category_scores,input_excerpt,full_prompt,audited_prompt,prompt_hash,content_truncated,engine_meta)
		VALUES ('native-request','/v1/responses','request-model','block',true,'violence','{"violence":0.9}',
		'native preview','received content','actual audited content',$1,true,'{"engine":"typesafe","model":"jev","rules_version":"test-v1"}') RETURNING id`, strings.Repeat("b", 64)).Scan(&nativeID)
	require.NoError(t, err)
	require.Equal(t, legacy.ID, nativeID, "test must exercise ID collision across tables")
	page, err := repo.ListEvents(ctx, EventFilter{}, 1, 2)
	require.NoError(t, err)
	require.Equal(t, int64(3), page.Total)
	require.Equal(t, 2, page.Pages)
	require.Len(t, page.Items, 2)
	require.Equal(t, -nativeID, page.Items[0].ID)
	require.Equal(t, hardRule.ID, page.Items[1].ID)
	require.Equal(t, "native", page.Items[0].AuditSource)
	require.Equal(t, "truncated", page.Items[0].ContentAvailability)
	require.Empty(t, page.Items[0].Snapshot.FullPrompt, "list must not return full evidence")
	page2, err := repo.ListEvents(ctx, EventFilter{}, 2, 2)
	require.NoError(t, err)
	require.Len(t, page2.Items, 1)
	require.Equal(t, legacy.ID, page2.Items[0].ID)
	require.Equal(t, "full", page2.Items[0].ContentAvailability)
	nativePage, err := repo.ListEvents(ctx, EventFilter{AuditSource: "native"}, 1, 20)
	require.NoError(t, err)
	require.Equal(t, int64(2), nativePage.Total)
	nativeDetail, err := repo.GetEvent(ctx, -nativeID)
	require.NoError(t, err)
	require.Equal(t, "received content", nativeDetail.Snapshot.FullPrompt)
	require.Equal(t, "actual audited content", nativeDetail.Snapshot.AuditedPrompt)
	require.Equal(t, "truncated", nativeDetail.ContentAvailability)
	require.Equal(t, "typesafe", nativeDetail.ScannerBackend)
	require.Contains(t, string(nativeDetail.NativeEngineMeta), "test-v1")
	require.Equal(t, EventCritical, nativeDetail.Decision)
	require.Equal(t, ActionBlock, nativeDetail.Action)
	legacyDetail, err := repo.GetEvent(ctx, legacy.ID)
	require.NoError(t, err)
	require.Equal(t, "legacy", legacyDetail.AuditSource)
	require.NotEqual(t, nativeDetail.EventKey, legacyDetail.EventKey)
	_, err = repo.DeleteEventsByIDs(ctx, []int64{legacy.ID, -nativeID})
	require.Error(t, err)
	_, err = repo.GetEvent(ctx, legacy.ID)
	require.NoError(t, err, "mixed deletion must not partially delete legacy records")
	start, end := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	preview, err := repo.PreviewDelete(ctx, EventFilter{AuditSource: "native", StartAt: &start, EndAt: &end})
	require.NoError(t, err)
	require.Equal(t, int64(1), preview.MatchedCount, "only persisted prompt hard-rule records are mutable")
}

func TestUnifiedAuditRepositoryHistoricalExcerptsErrorsFiltersAndAggregation(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	for _, stage := range []string{"http", "native_hard_rules"} {
		snapshot := integrationSnapshot("same")
		snapshot.Stage = stage
		_, err := repo.RecordBlocking(ctx, snapshot, 1, integrationResult(EventPass), true)
		require.NoError(t, err)
	}
	_, err := db.Exec(`INSERT INTO content_moderation_logs (request_id,action,input_excerpt) VALUES
		('history-one','allow','searchable historical excerpt'),('history-two','allow','other historical excerpt'),
		('failed-attempt','error','failed request excerpt')`)
	require.NoError(t, err)
	page, err := repo.ListEvents(ctx, EventFilter{Aggregate: true}, 1, 20)
	require.NoError(t, err)
	require.Equal(t, int64(5), page.Total, "different sources and empty-hash historical records must not merge")
	page, err = repo.ListEvents(ctx, EventFilter{AuditSource: "native", Keyword: "searchable"}, 1, 20)
	require.NoError(t, err)
	require.Equal(t, int64(1), page.Total)
	detail, err := repo.GetEvent(ctx, page.Items[0].ID)
	require.NoError(t, err)
	require.Equal(t, "excerpt_only", detail.ContentAvailability)
	require.Empty(t, detail.Snapshot.FullPrompt)
	require.Empty(t, detail.Snapshot.AuditedPrompt)
	page, err = repo.ListEvents(ctx, EventFilter{RequestID: "failed-attempt"}, 1, 20)
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	require.Equal(t, "error", page.Items[0].AuditStatus)
	require.Equal(t, EventReviewRequired, page.Items[0].Decision)
	require.Equal(t, RiskUnknown, page.Items[0].RiskLevel)
	require.Equal(t, "error", page.Items[0].NativeAction)
	require.Equal(t, ActionWarn, page.Items[0].Action, "failed-open audit must not masquerade as block/pass")
}

func TestUnifiedAuditHistoricalSourceMigrationRequiresExactEvidence(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	_, err := db.Exec(`INSERT INTO prompt_audit_policy_versions (config_version,config_snapshot)
		VALUES (70001,'{"native_audit_enabled":true}'),(70002,'{"native_audit_enabled":false}')
		ON CONFLICT (config_version) DO UPDATE SET config_snapshot=EXCLUDED.config_snapshot`)
	require.NoError(t, err)
	type expectedEvent struct {
		id     int64
		source string
	}
	var expected []expectedEvent
	for _, tc := range []struct {
		name, stage, backend, policy, source string
		version                              int64
	}{
		{"native-repository", "http", "local-repository-policy", "known_jailbreak_repository", "native", 70001},
		{"native-explicit", "http", "local-explicit-bypass-policy", "explicit_active_bypass", "native", 70001},
		{"old-policy", "http", "local-repository-policy", "known_jailbreak_repository", "legacy", 70002},
		{"missing-version", "http", "local-repository-policy", "known_jailbreak_repository", "legacy", 70003},
		{"wrong-policy", "http", "local-repository-policy", "other-policy", "legacy", 70001},
		{"gap", "audit_gap", "local-repository-policy", "known_jailbreak_repository", "audit_gap", 70001},
		{"output", "output", "local-repository-policy", "known_jailbreak_repository", "legacy", 70001},
	} {
		snapshot := integrationSnapshot(tc.name)
		snapshot.Stage = tc.stage
		result := integrationResult(EventCritical)
		result.ScannerBackend, result.PolicyID = tc.backend, tc.policy
		event, recordErr := repo.RecordBlocking(ctx, snapshot, tc.version, result, true)
		require.NoError(t, recordErr)
		expected = append(expected, expectedEvent{event.ID, tc.source})
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "migrations", "252_native_audit_event_source.sql"))
	require.NoError(t, err)
	for i := 0; i < 2; i++ {
		_, err = db.Exec(string(raw))
		require.NoError(t, err)
	}
	for _, want := range expected {
		event, getErr := repo.GetEvent(ctx, want.id)
		require.NoError(t, getErr)
		require.Equal(t, want.source, event.AuditSource)
	}
}

func TestUnifiedAuditUpstreamCyberPolicyIsNotANativeVerdict(t *testing.T) {
	db := openPromptAuditIntegrationDB(t)
	repo := NewPostgreSQLRepository(db)
	ctx := context.Background()
	_, err := db.Exec(`INSERT INTO content_moderation_logs (request_id,action,flagged,highest_category) VALUES
		('provider-rejected','cyber_policy',true,'cyber_policy'),
		('native-passed','allow',false,''),
		('failed-flagged-attempt','error',true,'violence')`)
	require.NoError(t, err)
	upstream, err := repo.ListEvents(ctx, EventFilter{AuditSource: AuditSourceUpstream}, 1, 20)
	require.NoError(t, err)
	require.Len(t, upstream.Items, 1)
	require.Equal(t, int64(1), upstream.Total)
	require.Negative(t, upstream.Items[0].ID)
	detail, err := repo.GetEvent(ctx, upstream.Items[0].ID)
	require.NoError(t, err)
	require.Equal(t, AuditSourceUpstream, detail.AuditSource)
	require.Equal(t, "content_moderation", detail.EventOrigin)
	require.Equal(t, "upstream_feedback", detail.Snapshot.Stage)
	require.Equal(t, "upstream_feedback", detail.Snapshot.AuditSubject)
	require.Equal(t, "openai-upstream-feedback", detail.ScannerBackend)
	require.Equal(t, "cyber_policy", detail.PolicyCode)
	require.Equal(t, "openai_upstream", detail.PolicySource)
	require.Equal(t, "provider-policy-feedback", detail.PolicyID)
	require.Equal(t, EventUpstreamPolicyBlock, detail.Decision)
	require.Equal(t, RiskUnknown, detail.RiskLevel)
	require.Equal(t, ActionBlock, detail.Action)
	native, err := repo.ListEvents(ctx, EventFilter{AuditSource: AuditSourceNative}, 1, 20)
	require.NoError(t, err)
	require.Equal(t, int64(2), native.Total)
	for _, event := range native.Items {
		require.NotEqual(t, "provider-rejected", event.Snapshot.RequestID)
		if event.NativeAction == "error" {
			require.Equal(t, EventReviewRequired, event.Decision)
			require.Equal(t, RiskUnknown, event.RiskLevel)
			require.Equal(t, ActionWarn, event.Action)
		}
	}
}
