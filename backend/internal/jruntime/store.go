package jruntime

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInProgress = errors.New("j_task_in_progress")
	ErrReplay     = errors.New("j_task_cannot_be_replayed")
	ErrBinding    = errors.New("j_task_binding_mismatch")
)

// Store keeps durable, metadata-only child-call evidence. Replayed responses
// are encrypted and scoped to the exact caller, session, model and request.
type Store struct {
	DB          *sql.DB
	cipher      cipher.AEAD
	stopJanitor func()
}

func NewStore(db *sql.DB, secret string) (*Store, error) {
	if db == nil || len(secret) < 32 {
		return nil, errors.New("j_store_configuration_required")
	}
	key := sha256.Sum256([]byte("sub2api-j-storage-v1:" + secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Store{DB: db, cipher: aead}, nil
}

func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func (s *Store) Enabled(ctx context.Context, userID, keyID int64) (bool, error) {
	var enabled bool
	err := s.DB.QueryRowContext(ctx, `SELECT COALESCE(j.enabled,FALSE) FROM api_keys k
 LEFT JOIN j_key_settings j ON j.api_key_id=k.id WHERE k.id=$1 AND k.user_id=$2 AND k.deleted_at IS NULL`, keyID, userID).Scan(&enabled)
	return enabled, err
}

func (s *Store) Allowed(ctx context.Context, userID, keyID int64) (bool, error) {
	var enabled bool
	err := s.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM api_keys k JOIN j_key_settings j ON j.api_key_id=k.id
 WHERE k.id=$1 AND k.user_id=$2 AND k.deleted_at IS NULL AND k.status='active' AND (k.expires_at IS NULL OR k.expires_at>NOW()) AND j.enabled)`, keyID, userID).Scan(&enabled)
	return enabled, err
}

func (s *Store) SetEnabled(ctx context.Context, userID, keyID int64, enabled bool) error {
	r, err := s.DB.ExecContext(ctx, `INSERT INTO j_key_settings(api_key_id,enabled)
 SELECT id,$3 FROM api_keys WHERE id=$1 AND user_id=$2 AND deleted_at IS NULL
 ON CONFLICT(api_key_id) DO UPDATE SET enabled=EXCLUDED.enabled,updated_at=NOW()`, keyID, userID, enabled)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrBinding
	}
	return nil
}

func (s *Store) seal(b Binding, raw []byte) ([]byte, error) {
	nonce := make([]byte, s.cipher.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.cipher.Seal(nonce, nonce, raw, []byte(fmt.Sprintf("%d:%d:%s", b.UserID, b.KeyID, b.TaskID))), nil
}

func (s *Store) open(b Binding, raw []byte) ([]byte, error) {
	n := s.cipher.NonceSize()
	if len(raw) < n {
		return nil, ErrReplay
	}
	return s.cipher.Open(nil, raw[:n], raw[n:], []byte(fmt.Sprintf("%d:%d:%s", b.UserID, b.KeyID, b.TaskID)))
}

// Begin never resumes abandoned work. A completed duplicate returns its stored
// result; unknown side effects and concurrent attempts are never dispatched again.
func (s *Store) Begin(ctx context.Context, b Binding, body []byte) (*Result, error) {
	if b.UserID <= 0 || b.KeyID <= 0 || b.AccountID <= 0 || len(b.TaskID) == 0 || len(b.TaskID) > 128 || b.SessionID == "" || b.BaseModel == "" {
		return nil, ErrBinding
	}
	enabled, err := s.Allowed(ctx, b.UserID, b.KeyID)
	if err != nil || !enabled {
		return nil, ErrBinding
	}
	r, err := s.DB.ExecContext(ctx, `INSERT INTO j_tasks(api_key_id,task_id,user_id,account_id,session_hash,base_model,request_hash,status,policy_version)
 VALUES($1,$2,$3,$4,$5,$6,$7,'running',$8) ON CONFLICT DO NOTHING`, b.KeyID, b.TaskID, b.UserID, b.AccountID, digest([]byte(b.SessionID)), b.BaseModel, digest(body), PolicyVersion)
	if err != nil {
		return nil, err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n == 1 {
		return nil, nil
	}
	var uid, aid int64
	var session, model, hash, status string
	var ciphertext []byte
	var expiry time.Time
	err = s.DB.QueryRowContext(ctx, `SELECT user_id,account_id,session_hash,base_model,request_hash,status,result,expires_at FROM j_tasks WHERE api_key_id=$1 AND task_id=$2`, b.KeyID, b.TaskID).Scan(&uid, &aid, &session, &model, &hash, &status, &ciphertext, &expiry)
	if err != nil {
		return nil, err
	}
	if uid != b.UserID || aid != b.AccountID || session != digest([]byte(b.SessionID)) || model != b.BaseModel || hash != digest(body) {
		return nil, ErrBinding
	}
	if time.Now().After(expiry) {
		return nil, ErrReplay
	}
	if status == "running" {
		return nil, ErrInProgress
	}
	if status != "completed" {
		return nil, ErrReplay
	}
	plain, err := s.open(b, ciphertext)
	if err != nil {
		return nil, ErrReplay
	}
	var result Result
	if json.Unmarshal(plain, &result) != nil {
		return nil, ErrReplay
	}
	return &result, nil
}

func (s *Store) Record(ctx context.Context, b Binding, event Event) error {
	if event.InputTokens < 0 || event.OutputTokens < 0 || len(event.Stage) > 64 || len(event.Tool) > 128 || len(event.CallID) > 128 || len(event.Outcome) > 128 {
		return ErrBinding
	}
	r, err := s.DB.ExecContext(ctx, `INSERT INTO j_events(api_key_id,task_id,stage,actor,model,call_id,tool,outcome,input_tokens,output_tokens)
 SELECT api_key_id,task_id,$6,$7,$8,$9,$10,$11,$12,$13 FROM j_tasks
 WHERE api_key_id=$1 AND task_id=$2 AND user_id=$3 AND account_id=$4 AND session_hash=$5 AND status='running' AND expires_at>NOW()
 AND ($6='execution_end' OR EXISTS(SELECT 1 FROM j_key_settings j JOIN api_keys k ON k.id=j.api_key_id WHERE j.api_key_id=$1 AND j.enabled AND k.deleted_at IS NULL AND k.user_id=$3 AND k.status='active' AND (k.expires_at IS NULL OR k.expires_at>NOW())))`,
		b.KeyID, b.TaskID, b.UserID, b.AccountID, digest([]byte(b.SessionID)), event.Stage, event.Actor, event.Model, event.CallID, event.Tool, event.Outcome, event.InputTokens, event.OutputTokens)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrBinding
	}
	return nil
}

func (s *Store) Finish(ctx context.Context, b Binding, result Result, runErr error) error {
	status := "completed"
	if runErr != nil {
		status = "failed"
	}
	if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
		status = "cancelled"
	}
	if result.NextActor == "" {
		result.NextActor = "jev"
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return err
	}
	sealed, err := s.seal(b, raw)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	r, err := tx.ExecContext(ctx, `UPDATE j_tasks SET status=$6,result=$7,next_actor=$8,response_id=$9,updated_at=NOW() WHERE api_key_id=$1 AND task_id=$2 AND user_id=$3 AND account_id=$4 AND session_hash=$5 AND status='running'`, b.KeyID, b.TaskID, b.UserID, b.AccountID, digest([]byte(b.SessionID)), status, sealed, result.NextActor, responseID(result.Response))
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrBinding
	}
	if runErr == nil {
		var response struct {
			Output []struct {
				Type   string `json:"type"`
				CallID string `json:"call_id"`
			} `json:"output"`
		}
		if json.Unmarshal(result.Response, &response) != nil {
			return ErrReplay
		}
		for _, item := range response.Output {
			if item.Type == "function_call" || item.Type == "custom_tool_call" {
				if item.CallID == "" || len(item.CallID) > 128 {
					return ErrBinding
				}
				_, err = tx.ExecContext(ctx, `INSERT INTO j_client_calls(api_key_id,call_id,task_id,actor) VALUES($1,$2,$3,$4)`, b.KeyID, item.CallID, b.TaskID, result.NextActor)
				if err != nil {
					return err
				}
			}
		}
	}
	return tx.Commit()
}

// Phase checks only the newest client tool outputs. Historical calls in an
// ordinary full-input Responses request do not reset the current owner phase.
func (s *Store) Phase(ctx context.Context, b Binding, body []byte) (string, error) {
	var request struct {
		Input json.RawMessage `json:"input"`
	}
	if json.Unmarshal(body, &request) != nil {
		return "", ErrBinding
	}
	items, err := inputItems(request.Input)
	if err != nil {
		return "", err
	}
	actor := ""
	for i := len(items) - 1; i >= 0; i-- {
		var item struct {
			Type   string `json:"type"`
			CallID string `json:"call_id"`
		}
		if json.Unmarshal(items[i], &item) != nil {
			return "", ErrBinding
		}
		if item.Type != "function_call_output" && item.Type != "custom_tool_call_output" {
			break
		}
		var phase string
		err := s.DB.QueryRowContext(ctx, `SELECT c.actor FROM j_client_calls c JOIN j_tasks t ON t.api_key_id=c.api_key_id AND t.task_id=c.task_id
 WHERE c.api_key_id=$1 AND c.call_id=$2 AND t.user_id=$3 AND t.account_id=$4 AND t.session_hash=$5 AND t.base_model=$6 AND t.status='completed' AND t.expires_at>NOW()`, b.KeyID, item.CallID, b.UserID, b.AccountID, digest([]byte(b.SessionID)), b.BaseModel).Scan(&phase)
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrBinding
		}
		if err != nil {
			return "", err
		}
		if actor != "" && actor != phase {
			return "", ErrBinding
		}
		actor = phase
	}
	if actor == "" {
		actor = "jev"
	}
	return actor, nil
}
