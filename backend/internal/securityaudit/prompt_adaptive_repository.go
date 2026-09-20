package securityaudit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

var ErrAdaptiveSampleNotFound = errors.New("prompt audit adaptive sample not found")

type AdaptiveSample struct {
	ID                       int64         `json:"id"`
	RequestID                string        `json:"request_id"`
	UserID                   int64         `json:"user_id"`
	PromptHash               string        `json:"prompt_hash"`
	TaskFingerprint          string        `json:"task_fingerprint"`
	Stage                    string        `json:"stage"`
	AuditSubject             string        `json:"audit_subject"`
	RedactedPreview          string        `json:"redacted_preview"`
	FullPrompt               string        `json:"full_prompt"`
	ConfigVersion            int64         `json:"config_version"`
	PolicyVersion            int           `json:"policy_version"`
	PrimaryEndpointID        string        `json:"primary_endpoint_id"`
	ShadowEndpointID         string        `json:"shadow_endpoint_id"`
	PrimaryDecision          EventDecision `json:"primary_decision"`
	ShadowDecision           EventDecision `json:"shadow_decision"`
	PrimaryCategories        []string      `json:"primary_categories"`
	ShadowCategories         []string      `json:"shadow_categories"`
	PrimaryIntentCategories  []string      `json:"primary_intent_categories"`
	PrimaryContentCategories []string      `json:"primary_content_categories"`
	ShadowIntentCategories   []string      `json:"shadow_intent_categories"`
	ShadowContentCategories  []string      `json:"shadow_content_categories"`
	Status                   string        `json:"status"`
	ReviewStatus             string        `json:"review_status"`
	ReviewNote               string        `json:"review_note"`
	ReviewedBy               int64         `json:"reviewed_by"`
	ReviewedAt               *time.Time    `json:"reviewed_at,omitempty"`
	OccurrenceCount          int64         `json:"occurrence_count"`
	LastErrorCode            string        `json:"last_error_code"`
	CreatedAt                time.Time     `json:"created_at"`
	UpdatedAt                time.Time     `json:"updated_at"`
}

type AdaptiveSamplePage struct {
	Items    []*AdaptiveSample `json:"items"`
	Total    int64             `json:"total"`
	Page     int               `json:"page"`
	PageSize int               `json:"page_size"`
	Pages    int               `json:"pages"`
}

type AdaptiveReviewRequest struct {
	Decision string `json:"decision" binding:"required"`
	Note     string `json:"note"`
}

func (r *PostgreSQLRepository) ListAdaptiveSamples(ctx context.Context, status string, page, pageSize int) (*AdaptiveSamplePage, error) {
	status = strings.TrimSpace(status)
	if !validAdaptiveSampleFilter(status) {
		return nil, infraerrors.BadRequest("prompt_audit_invalid_adaptive_filter", "自适应样本筛选无效")
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	where := ""
	args := make([]any, 0, 3)
	if status != "" && status != "all" {
		if status == "allow" || status == "block" || status == "review_pending" {
			reviewStatus := status
			if status == "review_pending" {
				reviewStatus = "pending"
			}
			where = " WHERE review_status=$1"
			args = append(args, reviewStatus)
		} else {
			where = " WHERE status=$1"
			args = append(args, status)
		}
	}
	var total int64
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM prompt_audit_adaptive_samples"+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	limitIndex := len(args) + 1
	queryArgs := append(append([]any(nil), args...), pageSize, (page-1)*pageSize)
	rows, err := r.db.QueryContext(ctx,
		"SELECT "+adaptiveSampleColumns()+" FROM prompt_audit_adaptive_samples"+where+
			fmt.Sprintf(" ORDER BY updated_at DESC,id DESC LIMIT $%d OFFSET $%d", limitIndex, limitIndex+1),
		queryArgs...,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	items := make([]*AdaptiveSample, 0, pageSize)
	for rows.Next() {
		sample, scanErr := scanAdaptiveSample(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, sample)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	pages := 0
	if total > 0 {
		pages = int((total + int64(pageSize) - 1) / int64(pageSize))
	}
	return &AdaptiveSamplePage{Items: items, Total: total, Page: page, PageSize: pageSize, Pages: pages}, nil
}

func (r *PostgreSQLRepository) ReviewAdaptiveSample(ctx context.Context, id, actorID int64, request AdaptiveReviewRequest) (*AdaptiveSample, error) {
	if id <= 0 {
		return nil, infraerrors.BadRequest("prompt_audit_invalid_adaptive_sample_id", "自适应样本 ID 无效")
	}
	decision := strings.TrimSpace(strings.ToLower(request.Decision))
	if decision != "allow" && decision != "block" {
		return nil, infraerrors.BadRequest("prompt_audit_invalid_adaptive_review", "复核结论只能是 Allow 或 Block")
	}
	note := strings.TrimSpace(request.Note)
	if len([]rune(note)) > 2000 {
		return nil, infraerrors.BadRequest("prompt_audit_invalid_adaptive_review", "复核备注不能超过 2000 个字符")
	}
	sample, err := scanAdaptiveSample(r.db.QueryRowContext(ctx, `
		UPDATE prompt_audit_adaptive_samples
		SET review_status=$2,review_note=$3,reviewed_by=NULLIF($4,0),reviewed_at=NOW(),updated_at=NOW()
		WHERE id=$1
		RETURNING `+adaptiveSampleColumns(), id, decision, note, actorID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAdaptiveSampleNotFound
	}
	return sample, err
}

func validAdaptiveSampleFilter(value string) bool {
	switch value {
	case "", "all", "pending", "shadow_match", "disagreement", "shadow_failed", "review_pending", "allow", "block":
		return true
	default:
		return false
	}
}

func adaptiveSampleColumns() string {
	return `id,request_id,COALESCE(user_id,0),prompt_hash,task_fingerprint,stage,audit_subject,
		redacted_preview,full_prompt,config_version,policy_version,primary_endpoint_id,shadow_endpoint_id,
		primary_decision,shadow_decision,primary_categories,shadow_categories,
		primary_intent_categories,primary_content_categories,shadow_intent_categories,shadow_content_categories,
		status,review_status,review_note,COALESCE(reviewed_by,0),reviewed_at,occurrence_count,last_error_code,created_at,updated_at`
}

func scanAdaptiveSample(row rowScanner) (*AdaptiveSample, error) {
	sample := &AdaptiveSample{}
	var primaryCategories, shadowCategories []byte
	var primaryIntent, primaryContent, shadowIntent, shadowContent []byte
	var reviewedAt sql.NullTime
	if err := row.Scan(
		&sample.ID, &sample.RequestID, &sample.UserID, &sample.PromptHash, &sample.TaskFingerprint,
		&sample.Stage, &sample.AuditSubject, &sample.RedactedPreview, &sample.FullPrompt,
		&sample.ConfigVersion, &sample.PolicyVersion, &sample.PrimaryEndpointID, &sample.ShadowEndpointID,
		&sample.PrimaryDecision, &sample.ShadowDecision, &primaryCategories, &shadowCategories,
		&primaryIntent, &primaryContent, &shadowIntent, &shadowContent,
		&sample.Status, &sample.ReviewStatus, &sample.ReviewNote, &sample.ReviewedBy, &reviewedAt,
		&sample.OccurrenceCount, &sample.LastErrorCode, &sample.CreatedAt, &sample.UpdatedAt,
	); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(primaryCategories, &sample.PrimaryCategories)
	_ = json.Unmarshal(shadowCategories, &sample.ShadowCategories)
	_ = json.Unmarshal(primaryIntent, &sample.PrimaryIntentCategories)
	_ = json.Unmarshal(primaryContent, &sample.PrimaryContentCategories)
	_ = json.Unmarshal(shadowIntent, &sample.ShadowIntentCategories)
	_ = json.Unmarshal(shadowContent, &sample.ShadowContentCategories)
	if reviewedAt.Valid {
		value := reviewedAt.Time
		sample.ReviewedAt = &value
	}
	return sample, nil
}
