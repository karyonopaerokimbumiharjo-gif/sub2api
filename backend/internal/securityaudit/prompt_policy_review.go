package securityaudit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

// Reviews supplement the original supplier signal; they never overwrite it or
// turn an administrator's cache release into an upstream policy exemption.
type PolicyReview struct {
	Action     string    `json:"action"`
	Reason     string    `json:"reason"`
	ActorID    int64     `json:"actor_id"`
	ReviewedAt time.Time `json:"reviewed_at"`
}

type PolicyReviewRequest struct {
	Action string `json:"action"`
	Reason string `json:"reason"`
}

func (s *PromptService) ReviewPolicyEvent(ctx context.Context, eventID, actorID int64, req PolicyReviewRequest) (*Event, error) {
	req.Reason = strings.TrimSpace(req.Reason)
	if actorID <= 0 || (req.Action != "confirmed" && req.Action != "cleared") || req.Reason == "" || utf8.RuneCountInString(req.Reason) > 1000 {
		return nil, infraerrors.BadRequest("policy_review_invalid", "请选择确认拦截或解除本地缓存，并填写 1–1000 字的复核理由")
	}
	if s == nil || s.repo == nil {
		return nil, errors.New("policy review unavailable")
	}
	tx, err := s.repo.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	event, err := scanEvent(tx.QueryRowContext(ctx, "SELECT "+eventDetailColumns("e")+" FROM prompt_audit_events e WHERE e.id=$1 FOR UPDATE", eventID), true)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEventNotFound
	}
	if err != nil {
		return nil, err
	}
	if event.Decision != EventUpstreamPolicyBlock || event.PolicyCode != "bio_policy" {
		return nil, infraerrors.BadRequest("policy_review_not_supported", "此入口仅复核上游生物安全拦截，不会解除其他安全规则")
	}
	if req.Action == "cleared" {
		if s.payload == nil || s.payload.client == nil {
			return nil, errors.New("policy cache unavailable; review was not saved")
		}
		snapshot := event.Snapshot
		fingerprint := snapshot.TaskFingerprint
		if fingerprint == "" {
			fingerprint = snapshot.PromptHash
		}
		keys := service.BioPromptBlockKeys(snapshot.UserID, snapshot.APIKeyID, snapshot.Provider, event.PolicyCode, fingerprint, snapshot.FullPrompt, event.ConfigVersion, snapshot.Model)
		for i := range keys {
			keys[i] = service.BioPromptBlockCachePrefix + keys[i]
		}
		if len(keys) > 0 {
			if err := s.payload.client.Del(ctx, keys...).Err(); err != nil {
				return nil, err
			}
		}
	}
	event.PolicyReview = &PolicyReview{Action: req.Action, Reason: RedactPreview(req.Reason, 1000), ActorID: actorID, ReviewedAt: time.Now().UTC()}
	raw, err := json.Marshal(event.PolicyReview)
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE prompt_audit_events SET policy_review=$1::jsonb WHERE id=$2", raw, eventID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	decoratePromptAuditEvent(event)
	return event, nil
}
