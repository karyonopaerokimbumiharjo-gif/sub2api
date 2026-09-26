package securityaudit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

const (
	AuditSourceLegacy   = "legacy"
	AuditSourceNative   = "native"
	AuditSourceGap      = "audit_gap"
	AuditSourceUpstream = "upstream"
)

func validateEventSource(source string) error {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "", AuditSourceLegacy, AuditSourceNative, AuditSourceGap, AuditSourceUpstream:
		return nil
	default:
		return errors.New("unknown audit event source")
	}
}

// Source is determined from persisted execution evidence, never today's config.
// Keeping the same expression for reads and deletes prevents a source filter
// from silently broadening a destructive operation.
func auditSourceSQL(alias string) string {
	return fmt.Sprintf(`CASE
		WHEN %[1]s.stage IN ('native_moderation','native_hard_rules') THEN 'native'
		WHEN %[1]s.stage='audit_gap' THEN 'audit_gap'
		WHEN %[1]s.stage='upstream_feedback' THEN 'upstream'
		ELSE 'legacy' END`, alias)
}

func decorateAuditEventSource(event *Event) {
	event.EventOrigin = "prompt_audit"
	event.AuditSource = AuditSourceLegacy
	switch event.Snapshot.Stage {
	case "native_moderation", "native_hard_rules":
		event.AuditSource = AuditSourceNative
	case "audit_gap":
		event.AuditSource = AuditSourceGap
	case "upstream_feedback":
		event.AuditSource = AuditSourceUpstream
	}
	if event.ID < 0 {
		event.EventOrigin = "content_moderation"
		event.NativeLogID = -event.ID
		event.EventKey = fmt.Sprintf("content_moderation:%d", event.NativeLogID)
	} else {
		event.EventKey = fmt.Sprintf("prompt_audit:%d", event.ID)
	}
	if event.ContentAvailability == "" {
		switch {
		case strings.Contains(event.Snapshot.FullPrompt, "[middle omitted; beginning and latest tail retained]") || strings.Contains(event.Snapshot.AuditedPrompt, "[middle omitted; beginning and latest tail retained]"):
			event.ContentAvailability = "truncated"
		case event.Snapshot.FullPrompt != "" || event.Snapshot.AuditedPrompt != "":
			event.ContentAvailability = "full"
		case event.Snapshot.RedactedPreview != "":
			event.ContentAvailability = "excerpt_only"
		default:
			event.ContentAvailability = "unavailable"
		}
	}
}

func unifiedEventColumns(alias string) string {
	return eventColumns(alias) + fmt.Sprintf(",%[1]s.content_availability,%[1]s.native_action,%[1]s.native_error,%[1]s.native_engine_meta", alias)
}

// Only use this projection after selecting the bounded result page. Each
// content check uses its table's primary key; full prompts never enter the
// count/group relation or the materialized page.
func pagedAuditEventColumns(alias string) string {
	availability := fmt.Sprintf(`CASE WHEN %[1]s.id>0 THEN
		(SELECT %[2]s FROM prompt_audit_events stored WHERE stored.id=%[1]s.id)
		ELSE (SELECT %[3]s FROM content_moderation_logs stored WHERE stored.id= -%[1]s.id)
		END AS content_availability`, alias, legacyAuditContentAvailability("stored"), nativeAuditContentAvailability("stored"))
	return eventColumns(alias) + "," + availability + fmt.Sprintf(",%[1]s.native_action,%[1]s.native_error,%[1]s.native_engine_meta", alias)
}

func legacyAuditContentAvailability(alias string) string {
	return fmt.Sprintf(`CASE WHEN %[1]s.full_prompt LIKE '%%[middle omitted; beginning and latest tail retained]%%' OR %[1]s.audited_prompt LIKE '%%[middle omitted; beginning and latest tail retained]%%' THEN 'truncated'
		WHEN %[1]s.full_prompt<>'' OR %[1]s.audited_prompt<>'' THEN 'full'
		WHEN %[1]s.redacted_preview<>'' THEN 'excerpt_only' ELSE 'unavailable' END`, alias)
}

func nativeAuditContentAvailability(alias string) string {
	return fmt.Sprintf(`CASE WHEN %[1]s.content_truncated THEN 'truncated'
		WHEN %[1]s.full_prompt<>'' OR %[1]s.audited_prompt<>'' THEN 'full'
		WHEN %[1]s.input_excerpt<>'' THEN 'excerpt_only' ELSE 'unavailable' END`, alias)
}

func scanUnifiedEvent(row rowScanner, withFullPrompt, withDuplicateCount bool) (*Event, error) {
	return scanAuditEvent(row, withFullPrompt, withDuplicateCount, true)
}

// Negative IDs are a disjoint, reversible namespace for native log records.
// They can be opened without changing existing event URLs and cannot be passed
// to the positive-ID-only delete/review endpoints.
func (r *PostgreSQLRepository) getNativeEvent(ctx context.Context, id int64) (*Event, error) {
	if id == -1<<63 {
		return nil, ErrEventNotFound
	}
	query := `SELECT ` + unifiedEventColumns("e") + `,e.full_prompt,e.audited_prompt FROM (` + nativeAuditEventSelect(true) + `) e WHERE e.id=$1`
	event, err := scanUnifiedEvent(r.db.QueryRowContext(ctx, query, id), true, false)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEventNotFound
	}
	return event, err
}

func unifiedAuditEventRelation(withFullPrompt bool) string {
	availability := `''::text`
	if withFullPrompt {
		availability = legacyAuditContentAvailability("p")
	}
	legacy := `SELECT ` + eventColumns("p") + `,` + availability + ` AS content_availability,
		''::text AS native_action,''::text AS native_error,NULL::jsonb AS native_engine_meta`
	if withFullPrompt {
		legacy += `,p.full_prompt,p.audited_prompt`
	}
	legacy += ` FROM prompt_audit_events p`
	return `(` + legacy + ` UNION ALL ` + nativeAuditEventSelect(withFullPrompt) + `)`
}

func nativeAuditEventSelect(withFullPrompt bool) string {
	availability := `''::text`
	if withFullPrompt {
		availability = nativeAuditContentAvailability("l")
	}
	query := `SELECT
		-l.id AS id,0::bigint AS job_id,l.request_id,l.user_id,''::text AS username_snapshot,
		l.user_email AS user_email_snapshot,l.api_key_id,l.api_key_name AS api_key_name_snapshot,l.group_id,l.group_name,
		l.provider,l.endpoint,
		CASE WHEN l.endpoint LIKE '%/responses' THEN 'openai_responses'
			WHEN l.endpoint LIKE '%/chat/completions' THEN 'openai_chat'
			WHEN l.endpoint LIKE '%/messages' THEN 'anthropic_messages' ELSE l.provider END AS protocol,
		l.model,l.prompt_hash,''::text AS task_fingerprint,
		CASE WHEN l.action='cyber_policy' THEN 'upstream_feedback' ELSE 'input' END AS audit_subject,l.input_excerpt AS redacted_preview,
		CASE WHEN l.action='cyber_policy' THEN 'upstream_feedback' ELSE 'native_moderation' END AS stage,
		CASE WHEN l.action='error' THEN 'error' ELSE 'completed' END AS audit_status,
		CASE WHEN l.action='error' THEN 'review_required'
			WHEN l.action='cyber_policy' THEN 'upstream_policy_block'
			WHEN l.action IN ('block','hash_block','keyword_block') THEN 'critical'
			WHEN l.flagged THEN 'flag' ELSE 'pass' END AS decision,
		CASE WHEN l.action IN ('error','cyber_policy') THEN 'unknown' WHEN l.flagged THEN 'high' ELSE 'low' END AS risk_level,
		CASE WHEN l.action IN ('block','hash_block','keyword_block','cyber_policy') THEN 'Block'
			WHEN l.action='error' THEN 'Warn' ELSE 'Allow' END AS action,
		CASE WHEN l.highest_category<>'' AND l.flagged THEN jsonb_build_array(l.highest_category) ELSE '[]'::jsonb END AS categories,
		'[]'::jsonb AS intent_categories,'[]'::jsonb AS content_categories,
		CASE WHEN l.highest_category<>'' AND l.flagged THEN jsonb_build_array(l.highest_category) ELSE '[]'::jsonb END AS matched_scanners,
		l.category_scores AS scanner_scores,
		CASE WHEN l.matched_keyword<>'' THEN jsonb_build_object('keyword',l.matched_keyword) ELSE '{}'::jsonb END AS scanner_evidence,
		CASE WHEN l.action='cyber_policy' THEN 'openai-upstream-feedback'
			WHEN l.action IN ('hash_block','keyword_block') THEN 'native-'||l.action
			ELSE COALESCE(NULLIF(l.engine_meta->>'engine',''),'native-moderation') END AS scanner_backend,
		CASE WHEN l.action='cyber_policy' THEN 'cyber_policy' ELSE COALESCE(l.engine_meta->>'rules_version','') END AS scanner_version,
		''::text AS guard_endpoint_id,
		CASE WHEN l.action='cyber_policy' THEN 'provider-policy-feedback' ELSE 'sub2api-native' END AS policy_id,0::int AS policy_version,0::bigint AS config_version,
		1::int AS chunk_total,COALESCE(l.upstream_latency_ms,0) AS latency_ms,l.created_at,
		NULL::jsonb AS output_capture,NULL::jsonb AS policy_review,
		` + availability + ` AS content_availability,
		l.action AS native_action,l.error AS native_error,l.engine_meta AS native_engine_meta`
	if withFullPrompt {
		query += `,l.full_prompt,l.audited_prompt`
	}
	return query + ` FROM content_moderation_logs l`
}
