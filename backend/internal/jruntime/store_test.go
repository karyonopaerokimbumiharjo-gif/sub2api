package jruntime

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"os"
	"sync"
	"testing"
	"time"
)

func journalFixture(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("PROMPT_AUDIT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PostgreSQL test DSN is required")
	}
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	schema := "jtest_" + uuid.NewString()
	schema = "\"" + schema + "\""
	_, err = db.Exec("CREATE SCHEMA " + schema)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = db.Exec("DROP SCHEMA " + schema + " CASCADE"); db.Close() })
	_, err = db.Exec("SET search_path TO " + schema)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE users(id BIGINT PRIMARY KEY);CREATE TABLE accounts(id BIGINT PRIMARY KEY);CREATE TABLE api_keys(id BIGINT PRIMARY KEY,user_id BIGINT,deleted_at TIMESTAMPTZ,status TEXT DEFAULT 'active',expires_at TIMESTAMPTZ);
 INSERT INTO users VALUES(1),(2);INSERT INTO accounts VALUES(3),(4);INSERT INTO api_keys(id,user_id,deleted_at) VALUES(2,1,NULL),(5,2,NULL);`)
	require.NoError(t, err)
	raw, err := os.ReadFile("schema.sql")
	require.NoError(t, err)
	_, err = db.Exec(string(raw))
	require.NoError(t, err)
	_, err = db.Exec(string(raw))
	require.NoError(t, err)
	s, err := NewStore(db, "synthetic-storage-secret-of-sufficient-length")
	require.NoError(t, err)
	return s
}

func TestJournalScopedIdempotencyAndEncryptedReplay(t *testing.T) {
	s := journalFixture(t)
	ctx := context.Background()
	b := fixtureBinding("gpt-5.6-sol")
	body := fixtureBody()
	enabled, err := s.Enabled(ctx, 1, 2)
	require.NoError(t, err)
	require.False(t, enabled)
	require.ErrorIs(t, s.SetEnabled(ctx, 2, 2, true), ErrBinding)
	require.NoError(t, s.SetEnabled(ctx, 1, 2, true))
	enabled, err = s.Enabled(ctx, 1, 2)
	require.NoError(t, err)
	require.True(t, enabled)
	first, err := s.Begin(ctx, b, body)
	require.NoError(t, err)
	require.Nil(t, first)
	_, err = s.Begin(ctx, b, body)
	require.ErrorIs(t, err, ErrInProgress)
	for _, changed := range []Binding{{UserID: 2, KeyID: 2, AccountID: 3, TaskID: b.TaskID, SessionID: b.SessionID, BaseModel: b.BaseModel}, {UserID: 1, KeyID: 2, AccountID: 4, TaskID: b.TaskID, SessionID: b.SessionID, BaseModel: b.BaseModel}} {
		_, err = s.Begin(ctx, changed, body)
		require.ErrorIs(t, err, ErrBinding)
	}
	require.NoError(t, s.Record(ctx, b, Event{Stage: "model_call", Actor: "base", Model: b.BaseModel, InputTokens: 7, OutputTokens: 2}))
	result := Result{Response: fixtureResponse(b.BaseModel).Body, NextActor: "base", BaseCalls: 1, BaseInputTokens: 7, BaseOutputTokens: 2}
	require.NoError(t, s.Finish(ctx, b, result, nil))
	replay, err := s.Begin(ctx, b, body)
	require.NoError(t, err)
	require.Equal(t, result, *replay)
	var encrypted []byte
	require.NoError(t, s.DB.QueryRow(`SELECT result FROM j_tasks`).Scan(&encrypted))
	require.NotContains(t, string(encrypted), "The job is finished")
	_, err = s.Begin(ctx, b, []byte(`{"different":true}`))
	require.ErrorIs(t, err, ErrBinding)
	require.ErrorIs(t, s.Record(ctx, b, Event{Stage: "tool_dispatch"}), ErrBinding)
}

func TestJournalConcurrentClaimAndFailureNeverReplay(t *testing.T) {
	s := journalFixture(t)
	ctx := context.Background()
	b := fixtureBinding("gpt-5.6-sol")
	require.NoError(t, s.SetEnabled(ctx, b.UserID, b.KeyID, true))
	var wg sync.WaitGroup
	outcomes := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.Begin(ctx, b, fixtureBody()); outcomes <- err }()
	}
	wg.Wait()
	close(outcomes)
	created := 0
	for err := range outcomes {
		if err == nil {
			created++
		} else {
			require.ErrorIs(t, err, ErrInProgress)
		}
	}
	require.Equal(t, 1, created)
	require.NoError(t, s.Finish(ctx, b, Result{NextActor: "base"}, ErrUnknownOutcome))
	_, err := s.Begin(ctx, b, fixtureBody())
	require.ErrorIs(t, err, ErrReplay)
}

func TestJournalClientPhaseIsKeySessionAccountAndModelScoped(t *testing.T) {
	s := journalFixture(t)
	ctx := context.Background()
	b := fixtureBinding("gpt-5.6-sol")
	require.NoError(t, s.SetEnabled(ctx, b.UserID, b.KeyID, true))
	_, err := s.Begin(ctx, b, fixtureBody())
	require.NoError(t, err)
	response := fixtureResponse(b.BaseModel, map[string]any{"type": "function_call", "call_id": "opaque-call", "name": "check_job", "arguments": "{}"})
	require.NoError(t, s.Finish(ctx, b, Result{Response: response.Body, NextActor: "base"}, nil))
	body := []byte(`{"input":[{"type":"function_call_output","call_id":"opaque-call","output":"done"}]}`)
	phase, err := s.Phase(ctx, b, body)
	require.NoError(t, err)
	require.Equal(t, "base", phase)
	changed := b
	changed.SessionID = "another"
	_, err = s.Phase(ctx, changed, body)
	require.ErrorIs(t, err, ErrBinding)
	changed = b
	changed.KeyID = 5
	changed.UserID = 2
	_, err = s.Phase(ctx, changed, body)
	require.ErrorIs(t, err, ErrBinding)
	_, err = s.DB.Exec(`UPDATE j_tasks SET expires_at=$1`, time.Now().Add(-time.Hour))
	require.NoError(t, err)
	_, err = s.Begin(ctx, b, fixtureBody())
	require.ErrorIs(t, err, ErrReplay)
	var result Result
	require.NoError(t, json.Unmarshal([]byte(`{}`), &result))
}

func TestJournalContinuationOwnershipAndExpiryErasure(t *testing.T) {
	s := journalFixture(t)
	ctx := context.Background()
	b := fixtureBinding("gpt-5.6-sol")
	require.NoError(t, s.SetEnabled(ctx, b.UserID, b.KeyID, true))
	_, err := s.Begin(ctx, b, fixtureBody())
	require.NoError(t, err)
	r := Result{NextActor: "base", Response: json.RawMessage(`{"id":"resp_local","status":"completed","output":[]}`), History: []json.RawMessage{json.RawMessage(`{"role":"user","content":"private-history"}`)}}
	require.NoError(t, s.Finish(ctx, b, r, nil))
	body := []byte(`{"model":"gpt-5.6-sol","previous_response_id":"resp_local","input":"next"}`)
	expanded, account, err := s.Expand(ctx, b, body)
	require.NoError(t, err)
	require.Equal(t, b.AccountID, account)
	require.Contains(t, string(expanded), "private-history")
	require.NotContains(t, string(expanded), "previous_response_id")
	other := b
	other.SessionID = "different"
	_, _, err = s.Expand(ctx, other, body)
	require.ErrorIs(t, err, ErrBinding)
	other = b
	other.BaseModel = "gpt-5.6-terra"
	_, _, err = s.Expand(ctx, other, body)
	require.ErrorIs(t, err, ErrBinding)
	_, err = s.DB.Exec(`UPDATE j_tasks SET expires_at=NOW()-INTERVAL '1 hour'`)
	require.NoError(t, err)
	require.NoError(t, s.Prune(ctx))
	var erased bool
	require.NoError(t, s.DB.QueryRow(`SELECT result IS NULL FROM j_tasks`).Scan(&erased))
	require.True(t, erased)
	_, _, err = s.Expand(ctx, b, body)
	require.ErrorIs(t, err, ErrBinding)
}

func TestJournalDisablingModeStopsFurtherExecution(t *testing.T) {
	s := journalFixture(t)
	ctx := context.Background()
	b := fixtureBinding("gpt-5.6-sol")
	_, err := s.Begin(ctx, b, fixtureBody())
	require.ErrorIs(t, err, ErrBinding)
	require.NoError(t, s.SetEnabled(ctx, b.UserID, b.KeyID, true))
	_, err = s.Begin(ctx, b, fixtureBody())
	require.NoError(t, err)
	require.NoError(t, s.SetEnabled(ctx, b.UserID, b.KeyID, false))
	require.ErrorIs(t, s.Record(ctx, b, Event{Stage: "tool_dispatch"}), ErrBinding)
	require.NoError(t, s.Record(ctx, b, Event{Stage: "execution_end", Outcome: "cancelled"}))
}

func TestJournalMigrationMatchesRuntimeSchema(t *testing.T) {
	schema, err := os.ReadFile("schema.sql")
	require.NoError(t, err)
	migration, err := os.ReadFile("../../migrations/245_j_execution_journal.sql")
	require.NoError(t, err)
	require.Equal(t, string(schema), string(migration))
}
