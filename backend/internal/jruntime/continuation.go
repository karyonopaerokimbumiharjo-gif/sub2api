package jruntime

import (
	"context"
	"encoding/json"
	"strings"
)

func responseID(raw []byte) any {
	var envelope struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.ID == "" {
		return nil
	}
	return envelope.ID
}

// Expand resolves only this gateway's encrypted J history. It never forwards a
// virtual response ID upstream or accepts another key/session/model's history.
func (s *Store) Expand(ctx context.Context, b Binding, body []byte) ([]byte, int64, error) {
	var request map[string]json.RawMessage
	if json.Unmarshal(body, &request) != nil {
		return nil, 0, ErrBinding
	}
	var previous string
	if raw := request["previous_response_id"]; len(raw) > 0 && json.Unmarshal(raw, &previous) != nil {
		return nil, 0, ErrBinding
	}
	if strings.TrimSpace(previous) == "" {
		return body, 0, nil
	}
	var task string
	var account int64
	var encrypted []byte
	err := s.DB.QueryRowContext(ctx, `SELECT t.task_id,t.account_id,t.result FROM j_tasks t JOIN j_key_settings j ON j.api_key_id=t.api_key_id AND j.enabled
 WHERE t.api_key_id=$1 AND t.user_id=$2 AND t.session_hash=$3 AND t.base_model=$4 AND t.response_id=$5 AND t.status='completed' AND t.expires_at>NOW()`, b.KeyID, b.UserID, digest([]byte(b.SessionID)), b.BaseModel, previous).Scan(&task, &account, &encrypted)
	if err != nil {
		return nil, 0, ErrBinding
	}
	b.TaskID = task
	plain, err := s.open(b, encrypted)
	if err != nil {
		return nil, 0, ErrBinding
	}
	var result Result
	if json.Unmarshal(plain, &result) != nil || len(result.History) == 0 {
		return nil, 0, ErrBinding
	}
	input, err := inputItems(request["input"])
	if err != nil {
		return nil, 0, err
	}
	request["input"], _ = json.Marshal(append(result.History, input...))
	delete(request, "previous_response_id")
	out, err := json.Marshal(request)
	if len(out) > DefaultBudget().MaxBytes {
		return nil, 0, ErrBudget
	}
	return out, account, err
}

// A repeated idempotency key must retain the original account before scheduling.
func (s *Store) ExistingAccount(ctx context.Context, user, key int64, task string) (int64, error) {
	var id int64
	err := s.DB.QueryRowContext(ctx, `SELECT COALESCE((SELECT account_id FROM j_tasks WHERE api_key_id=$1 AND user_id=$2 AND task_id=$3),0)`, key, user, task).Scan(&id)
	return id, err
}

func (s *Store) ClientCallAccount(ctx context.Context, b Binding, body []byte) (int64, error) {
	var request struct {
		Input json.RawMessage `json:"input"`
	}
	if json.Unmarshal(body, &request) != nil {
		return 0, ErrBinding
	}
	items, err := inputItems(request.Input)
	if err != nil || len(items) == 0 {
		return 0, err
	}
	var item struct {
		Type   string `json:"type"`
		CallID string `json:"call_id"`
	}
	if json.Unmarshal(items[len(items)-1], &item) != nil {
		return 0, ErrBinding
	}
	if item.Type != "function_call_output" && item.Type != "custom_tool_call_output" {
		return 0, nil
	}
	var id int64
	err = s.DB.QueryRowContext(ctx, `SELECT t.account_id FROM j_client_calls c JOIN j_tasks t ON t.api_key_id=c.api_key_id AND t.task_id=c.task_id
 WHERE c.api_key_id=$1 AND c.call_id=$2 AND t.user_id=$3 AND t.session_hash=$4 AND t.base_model=$5 AND t.status='completed' AND t.expires_at>NOW()`, b.KeyID, item.CallID, b.UserID, digest([]byte(b.SessionID)), b.BaseModel).Scan(&id)
	if err != nil {
		return 0, ErrBinding
	}
	return id, nil
}
