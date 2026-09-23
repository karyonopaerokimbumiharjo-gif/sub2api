package jruntime

import (
	"context"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/executiontrace"
)

// ListEvents is used only by the administrator-authenticated usage route.
// It returns execution metadata, never encrypted bodies or grant secrets.
func (s *Store) ListEvents(ctx context.Context, filter string, limit int) ([]executiontrace.Event, error) {
	if limit < 1 || limit > 200 {
		limit = 100
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT e.created_at,'j:'||e.api_key_id||':'||e.task_id,
 t.account_id,t.user_id,e.api_key_id,e.task_id,e.stage,e.actor,e.model,e.call_id,e.tool,e.outcome,e.input_tokens,e.output_tokens
 FROM j_events e JOIN j_tasks t ON t.api_key_id=e.api_key_id AND t.task_id=e.task_id
 WHERE ($1='' OR e.task_id=$1 OR e.call_id=$1 OR 'j:'||e.api_key_id||':'||e.task_id=$1)
 ORDER BY e.id DESC LIMIT $2`, filter, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []executiontrace.Event{}
	for rows.Next() {
		var event executiontrace.Event
		var created time.Time
		if err := rows.Scan(&created, &event.RequestID, &event.AccountID, &event.UserID, &event.APIKeyID, &event.TaskID, &event.Stage, &event.Actor, &event.Model, &event.CallID, &event.Tool, &event.Reason, &event.InputTokens, &event.OutputTokens); err != nil {
			return nil, err
		}
		event.Time, event.Durable = created.UnixMilli(), true
		out = append(out, event)
	}
	return out, rows.Err()
}

// Sensitive payloads expire after 24 hours; metadata and replay tombstones stay
// for 90 days. A stopped process never resumes a task with uncertain effects.
func (s *Store) Prune(ctx context.Context) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	queries := []string{
		`UPDATE j_tasks SET status='failed',updated_at=NOW() WHERE status='running' AND created_at<NOW()-INTERVAL '10 minutes'`,
		`UPDATE j_tasks SET result=NULL WHERE expires_at<NOW() AND result IS NOT NULL`,
		`UPDATE j_tool_calls SET payload=decode('','hex'),result=NULL,status=CASE WHEN status='queued' THEN 'cancelled' WHEN status='dispatched' THEN 'unknown' ELSE status END WHERE expires_at<NOW() AND (octet_length(payload)>0 OR result IS NOT NULL)`,
		`UPDATE j_tool_grants SET tools=decode('','hex') WHERE (expires_at<NOW() OR revoked_at IS NOT NULL) AND octet_length(tools)>0`,
		`DELETE FROM j_tasks WHERE created_at<NOW()-INTERVAL '90 days'`,
		`DELETE FROM j_tool_grants g WHERE g.expires_at<NOW() AND NOT EXISTS(SELECT 1 FROM j_tool_calls c WHERE c.grant_id=g.id)`,
	}
	for _, query := range queries {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// StartJanitor is tied to Wire's application cleanup, not to request contexts.
func (s *Store) StartJanitor() func() {
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
			_ = s.Prune(bounded)
			cancel()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	s.stopJanitor = func() { stop(); <-done }
	return s.stopJanitor
}

func (s *Store) Stop() {
	if s != nil && s.stopJanitor != nil {
		s.stopJanitor()
	}
}
