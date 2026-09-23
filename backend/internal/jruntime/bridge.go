package jruntime

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

const MaxToolPayload = 2 << 20

// A bridge creates grants from an operator-owned local manifest. The model
// never receives the grant secret and cannot add commands or alter schemas.
type Grant struct {
	ID        string    `json:"id"`
	TaskID    string    `json:"task_id"`
	DeviceID  string    `json:"device_id"`
	Secret    string    `json:"secret,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

func nonce() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}
func grantBinding(user, key int64, id string) Binding {
	return Binding{UserID: user, KeyID: key, TaskID: "grant:" + id}
}

func (s *Store) Grant(ctx context.Context, user, key int64, session, task, device string, tools []Tool, ttl time.Duration) (*Grant, error) {
	enabled, err := s.Allowed(ctx, user, key)
	if err != nil {
		return nil, err
	}
	if !enabled || session == "" || len(session) > 256 || task == "" || len(task) > 128 || device == "" || len(device) > 128 || ttl <= 0 || ttl > time.Hour || len(tools) == 0 || len(tools) > 64 {
		return nil, ErrTool
	}
	seen := map[string]bool{}
	for _, tool := range tools {
		if tool.Type != "function" || tool.Name == "" || len(tool.Name) > 128 || tool.Name == HandoffTool || seen[tool.Name] || validateJSON(tool.Parameters) != nil {
			return nil, ErrTool
		}
		seen[tool.Name] = true
	}
	raw, err := json.Marshal(tools)
	if err != nil || len(raw) > 256<<10 {
		return nil, ErrTool
	}
	g := &Grant{ID: uuid.NewString(), TaskID: task, DeviceID: device, ExpiresAt: time.Now().Add(ttl)}
	g.Secret, err = nonce()
	if err != nil {
		return nil, err
	}
	sealed, err := s.seal(grantBinding(user, key, g.ID), raw)
	if err != nil {
		return nil, err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO j_tool_grants(id,user_id,api_key_id,session_hash,tools,secret_hash,expires_at,task_id,device_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, g.ID, user, key, digest([]byte(session)), sealed, digest([]byte(g.Secret)), g.ExpiresAt, task, device)
	if err != nil {
		return nil, err
	}
	return g, nil
}

func (s *Store) RevokeGrant(ctx context.Context, user, key int64, id string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE j_tool_grants SET revoked_at=NOW() WHERE id=$1 AND user_id=$2 AND api_key_id=$3`, id, user, key)
	return err
}

type BridgeRunner struct {
	Store   *Store
	GrantID string
}

func (r *BridgeRunner) Authorize(ctx context.Context, b Binding, tool Tool, call Call) error {
	if r.Store == nil || len(call.Arguments) > MaxToolPayload || validateJSON([]byte(call.Arguments)) != nil {
		return ErrTool
	}
	allowed, activeErr := r.Store.Allowed(ctx, b.UserID, b.KeyID)
	if activeErr != nil || !allowed {
		return ErrTool
	}
	var raw []byte
	err := r.Store.DB.QueryRowContext(ctx, `SELECT g.tools FROM j_tool_grants g JOIN j_key_settings k ON k.api_key_id=g.api_key_id AND k.enabled
 WHERE g.id=$1 AND g.user_id=$2 AND g.api_key_id=$3 AND g.session_hash=$4 AND g.task_id=$5 AND g.device_id<>'' AND g.revoked_at IS NULL AND g.expires_at>NOW()`, r.GrantID, b.UserID, b.KeyID, digest([]byte(b.SessionID)), b.TaskID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrTool
	}
	if err != nil {
		return err
	}
	plain, err := r.Store.open(grantBinding(b.UserID, b.KeyID, r.GrantID), raw)
	if err != nil {
		return ErrTool
	}
	var declared []Tool
	if json.Unmarshal(plain, &declared) != nil {
		return ErrTool
	}
	for _, allowed := range declared {
		if allowed.Name == call.Name && tool.Name == call.Name && sameToolSchema(allowed, tool) {
			return nil
		}
	}
	return ErrTool
}

func sameToolSchema(a, b Tool) bool {
	var left, right any
	if json.Unmarshal(a.Parameters, &left) != nil || json.Unmarshal(b.Parameters, &right) != nil {
		return false
	}
	l, _ := json.Marshal(left)
	r, _ := json.Marshal(right)
	return a.Type == b.Type && string(l) == string(r)
}

func (r *BridgeRunner) Run(ctx context.Context, b Binding, call Call) (json.RawMessage, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	raw, err := json.Marshal(call)
	if err != nil {
		return nil, err
	}
	sealed, err := r.Store.seal(b, raw)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(2 * time.Minute)
	if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	// The INSERT also checks the grant again after authorization, eliminating a
	// revoke/dispatch gap. Conflict is never treated as permission to re-run.
	res, err := r.Store.DB.ExecContext(ctx, `INSERT INTO j_tool_calls(api_key_id,task_id,call_id,grant_id,payload,status,expires_at)
 SELECT $1,$2,$3,g.id,$4,'queued',$5 FROM j_tool_grants g JOIN j_key_settings k ON k.api_key_id=g.api_key_id AND k.enabled
 WHERE g.id=$6 AND g.user_id=$7 AND g.api_key_id=$1 AND g.session_hash=$8 AND g.task_id=$2 AND g.device_id<>'' AND g.revoked_at IS NULL AND g.expires_at>NOW()`, b.KeyID, b.TaskID, call.ID, sealed, deadline, r.GrantID, b.UserID, digest([]byte(b.SessionID)))
	if err != nil {
		return nil, ErrUnknownOutcome
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		return nil, ErrTool
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			_, _ = r.Store.DB.ExecContext(cleanup, `UPDATE j_tool_calls SET status=CASE WHEN status='queued' THEN 'cancelled' ELSE 'unknown' END,updated_at=NOW() WHERE api_key_id=$1 AND task_id=$2 AND call_id=$3 AND status IN ('queued','dispatched')`, b.KeyID, b.TaskID, call.ID)
			cancel()
			return nil, ErrUnknownOutcome
		case <-ticker.C:
			var status string
			var result []byte
			var valid bool
			err = r.Store.DB.QueryRowContext(ctx, `SELECT c.status,c.result,(g.revoked_at IS NULL AND g.expires_at>NOW() AND c.expires_at>NOW() AND k.enabled)
 FROM j_tool_calls c JOIN j_tool_grants g ON g.id=c.grant_id JOIN j_key_settings k ON k.api_key_id=c.api_key_id
 WHERE c.api_key_id=$1 AND c.task_id=$2 AND c.call_id=$3`, b.KeyID, b.TaskID, call.ID).Scan(&status, &result, &valid)
			if err != nil {
				return nil, ErrUnknownOutcome
			}
			if status == "completed" {
				out, err := r.Store.open(b, result)
				return out, err
			}
			if !valid || status == "cancelled" || status == "unknown" {
				return nil, ErrUnknownOutcome
			}
		}
	}
}

type Delivery struct {
	TaskID    string    `json:"task_id"`
	Call      Call      `json:"call"`
	Lease     string    `json:"lease"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Local runners check before dispatch and while a child is running. A cancelled
// request, revoked grant, disabled J mode or lost lease stops only this child.
func (s *Store) CheckTool(ctx context.Context, user, key int64, grant, secret, task, call, lease string) (bool, error) {
	var active bool
	err := s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM j_tool_calls c
 JOIN j_tool_grants g ON g.id=c.grant_id JOIN j_tasks t ON t.api_key_id=c.api_key_id AND t.task_id=c.task_id
 JOIN j_key_settings j ON j.api_key_id=c.api_key_id JOIN api_keys k ON k.id=c.api_key_id
 WHERE c.api_key_id=$1 AND c.task_id=$2 AND c.call_id=$3 AND g.id=$4 AND g.user_id=$5
 AND g.task_id=c.task_id AND g.device_id<>'' AND g.secret_hash=$6 AND c.lease_hash=$7 AND c.status='dispatched' AND t.status='running'
 AND g.revoked_at IS NULL AND g.expires_at>NOW() AND c.expires_at>NOW() AND t.expires_at>NOW()
 AND j.enabled AND k.deleted_at IS NULL AND k.status='active' AND (k.expires_at IS NULL OR k.expires_at>NOW()))`, key, task, call, grant, user, digest([]byte(secret)), digest([]byte(lease))).Scan(&active)
	return active, err
}

// Poll delivers at most once. A crashed runner leaves an unknown outcome; it is
// never leased again to a different process or replayed on another backend.
func (s *Store) Poll(ctx context.Context, user, key int64, id, secret string) (*Delivery, error) {
	active, err := s.Allowed(ctx, user, key)
	if err != nil || !active {
		return nil, ErrTool
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var valid bool
	err = tx.QueryRowContext(ctx, `SELECT TRUE FROM j_tool_grants g JOIN j_key_settings k ON k.api_key_id=g.api_key_id AND k.enabled WHERE g.id=$1 AND g.user_id=$2 AND g.api_key_id=$3 AND g.secret_hash=$4 AND g.revoked_at IS NULL AND g.expires_at>NOW() FOR SHARE OF g,k`, id, user, key, digest([]byte(secret))).Scan(&valid)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTool
	}
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, ErrTool
	}
	d := &Delivery{}
	var payload []byte
	var callID string
	err = tx.QueryRowContext(ctx, `SELECT c.task_id,c.call_id,c.payload,c.expires_at FROM j_tool_calls c JOIN j_tasks t ON t.api_key_id=c.api_key_id AND t.task_id=c.task_id
 WHERE c.grant_id=$1 AND c.api_key_id=$2 AND c.task_id=(SELECT task_id FROM j_tool_grants WHERE id=$1) AND c.status='queued' AND c.expires_at>NOW() AND t.status='running'
 ORDER BY c.updated_at LIMIT 1 FOR UPDATE OF c SKIP LOCKED`, id, key).Scan(&d.TaskID, &callID, &payload, &d.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	plain, err := s.open(Binding{UserID: user, KeyID: key, TaskID: d.TaskID}, payload)
	if err != nil {
		return nil, err
	}
	if json.Unmarshal(plain, &d.Call) != nil {
		return nil, ErrTool
	}
	d.Lease, err = nonce()
	if err != nil {
		return nil, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE j_tool_calls SET status='dispatched',lease_hash=$4,updated_at=NOW() WHERE api_key_id=$1 AND task_id=$2 AND call_id=$3`, key, d.TaskID, callID, digest([]byte(d.Lease)))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return d, nil
}

func (s *Store) CompleteTool(ctx context.Context, user, key int64, grant, secret, task, call, lease string, output json.RawMessage) error {
	if len(output) > MaxToolPayload || validateJSON(output) != nil {
		return ErrTool
	}
	sealed, err := s.seal(Binding{UserID: user, KeyID: key, TaskID: task}, output)
	if err != nil {
		return err
	}
	r, err := s.DB.ExecContext(ctx, `UPDATE j_tool_calls c SET status='completed',result=$8,updated_at=NOW()
 FROM j_tool_grants g,j_tasks t,j_key_settings k WHERE c.grant_id=g.id AND c.api_key_id=k.api_key_id AND k.enabled
 AND t.api_key_id=c.api_key_id AND t.task_id=c.task_id AND t.status='running'
 AND c.api_key_id=$1 AND c.task_id=$2 AND c.call_id=$3 AND c.grant_id=$4 AND c.lease_hash=$5 AND c.status='dispatched' AND c.expires_at>NOW()
 AND g.task_id=c.task_id AND g.device_id<>'' AND g.user_id=$6 AND g.secret_hash=$7 AND g.revoked_at IS NULL AND g.expires_at>NOW()`, key, task, call, grant, digest([]byte(lease)), user, digest([]byte(secret)), sealed)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrTool
	}
	return nil
}
