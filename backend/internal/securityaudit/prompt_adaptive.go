package securityaudit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"
)

type AdaptiveSampleRecord struct {
	Snapshot       PromptSnapshot
	ConfigVersion  int64
	Primary        *NormalizedResult
	Shadow         *NormalizedResult
	ShadowEndpoint string
	Status         string
	ErrorCode      string
}

type AdaptiveRuntimeStats struct {
	Pending       int64      `json:"pending"`
	ShadowMatch   int64      `json:"shadow_match"`
	Disagreement  int64      `json:"disagreement"`
	ShadowFailed  int64      `json:"shadow_failed"`
	ReviewedAllow int64      `json:"reviewed_allow"`
	ReviewedBlock int64      `json:"reviewed_block"`
	Total         int64      `json:"total"`
	LastUpdatedAt *time.Time `json:"last_updated_at,omitempty"`
}

func deterministicAuditSample(key string, rate int) bool {
	if rate <= 0 {
		return false
	}
	if rate >= 100 {
		return true
	}
	digest := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return int(binary.BigEndian.Uint64(digest[:8])%100) < rate
}

func nextShadowEndpoint(endpoints []ActiveEndpoint, primaryID string) (ActiveEndpoint, bool) {
	primaryID = strings.TrimSpace(primaryID)
	for index, endpoint := range endpoints {
		if endpoint.ID != primaryID {
			continue
		}
		if index+1 < len(endpoints) {
			return endpoints[index+1], true
		}
		return ActiveEndpoint{}, false
	}
	return ActiveEndpoint{}, false
}

func adaptiveResultsAgree(primary, shadow *NormalizedResult) bool {
	if primary == nil || shadow == nil || primary.Decision != shadow.Decision || primary.Action != shadow.Action {
		return false
	}
	return slices.Equal(primary.Categories, shadow.Categories) &&
		slices.Equal(primary.IntentCategories, shadow.IntentCategories) &&
		slices.Equal(primary.ContentCategories, shadow.ContentCategories)
}

func (r *PostgreSQLRepository) UpsertAdaptiveSample(ctx context.Context, sample AdaptiveSampleRecord) error {
	if r == nil || r.db == nil || sample.Primary == nil || strings.TrimSpace(sample.Snapshot.PromptHash) == "" {
		return nil
	}
	primaryCategories, _ := json.Marshal(sample.Primary.Categories)
	primaryIntentCategories, _ := json.Marshal(sample.Primary.IntentCategories)
	primaryContentCategories, _ := json.Marshal(sample.Primary.ContentCategories)
	shadowCategories := []byte("[]")
	shadowIntentCategories := []byte("[]")
	shadowContentCategories := []byte("[]")
	shadowDecision := ""
	if sample.Shadow != nil {
		shadowCategories, _ = json.Marshal(sample.Shadow.Categories)
		shadowIntentCategories, _ = json.Marshal(sample.Shadow.IntentCategories)
		shadowContentCategories, _ = json.Marshal(sample.Shadow.ContentCategories)
		shadowDecision = string(sample.Shadow.Decision)
	}
	status := strings.TrimSpace(sample.Status)
	if status == "" {
		status = "pending"
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO prompt_audit_adaptive_samples (
			request_id,user_id,prompt_hash,task_fingerprint,stage,audit_subject,
			redacted_preview,full_prompt,config_version,policy_version,
			primary_endpoint_id,shadow_endpoint_id,primary_decision,shadow_decision,
			primary_categories,shadow_categories,
			primary_intent_categories,primary_content_categories,
			shadow_intent_categories,shadow_content_categories,
			status,last_error_code
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
			$15::jsonb,$16::jsonb,$17::jsonb,$18::jsonb,$19::jsonb,$20::jsonb,$21,$22
		)
		ON CONFLICT (prompt_hash,stage,audit_subject,config_version,primary_endpoint_id,policy_version) DO UPDATE SET
			request_id=EXCLUDED.request_id,
			user_id=EXCLUDED.user_id,
			task_fingerprint=EXCLUDED.task_fingerprint,
			audit_subject=EXCLUDED.audit_subject,
			redacted_preview=EXCLUDED.redacted_preview,
			full_prompt=EXCLUDED.full_prompt,
			config_version=EXCLUDED.config_version,
			shadow_endpoint_id=EXCLUDED.shadow_endpoint_id,
			primary_decision=EXCLUDED.primary_decision,
			shadow_decision=EXCLUDED.shadow_decision,
			primary_categories=EXCLUDED.primary_categories,
			shadow_categories=EXCLUDED.shadow_categories,
			primary_intent_categories=EXCLUDED.primary_intent_categories,
			primary_content_categories=EXCLUDED.primary_content_categories,
			shadow_intent_categories=EXCLUDED.shadow_intent_categories,
			shadow_content_categories=EXCLUDED.shadow_content_categories,
			status=EXCLUDED.status,
			last_error_code=EXCLUDED.last_error_code,
			occurrence_count=prompt_audit_adaptive_samples.occurrence_count+1,
			updated_at=NOW()`,
		sample.Snapshot.RequestID, nullableID(sample.Snapshot.UserID), sample.Snapshot.PromptHash,
		sample.Snapshot.TaskFingerprint, normalizeStage(sample.Snapshot.Stage), sample.Snapshot.AuditSubject,
		sample.Snapshot.RedactedPreview, sample.Snapshot.FullPrompt, sample.ConfigVersion, sample.Primary.PolicyVersion,
		sample.Primary.GuardEndpointID, strings.TrimSpace(sample.ShadowEndpoint), string(sample.Primary.Decision), shadowDecision,
		primaryCategories, shadowCategories, primaryIntentCategories, primaryContentCategories,
		shadowIntentCategories, shadowContentCategories, status, strings.TrimSpace(sample.ErrorCode))
	return err
}

func (r *PostgreSQLRepository) AdaptiveStats(ctx context.Context) (AdaptiveRuntimeStats, error) {
	if r == nil || r.db == nil {
		return AdaptiveRuntimeStats{}, errors.New("prompt audit database unavailable")
	}
	row := r.db.QueryRowContext(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE review_status='pending'),
			COUNT(*) FILTER (WHERE status='shadow_match'),
			COUNT(*) FILTER (WHERE status='disagreement'),
			COUNT(*) FILTER (WHERE status='shadow_failed'),
			COUNT(*) FILTER (WHERE review_status='allow'),
			COUNT(*) FILTER (WHERE review_status='block'),
			COUNT(*),MAX(updated_at)
		FROM prompt_audit_adaptive_samples`)
	var stats AdaptiveRuntimeStats
	var updated sql.NullTime
	if err := row.Scan(
		&stats.Pending, &stats.ShadowMatch, &stats.Disagreement, &stats.ShadowFailed,
		&stats.ReviewedAllow, &stats.ReviewedBlock, &stats.Total, &updated,
	); err != nil {
		return AdaptiveRuntimeStats{}, err
	}
	if updated.Valid {
		value := updated.Time
		stats.LastUpdatedAt = &value
	}
	return stats, nil
}
