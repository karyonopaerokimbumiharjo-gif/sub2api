package jruntime

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestBridgeGrantIsolationAndExactlyOnceDelivery(t *testing.T) {
	s := journalFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b := fixtureBinding("gpt-5.6-sol")
	require.NoError(t, s.SetEnabled(ctx, b.UserID, b.KeyID, true))
	g, err := s.Grant(ctx, b.UserID, b.KeyID, b.SessionID, []Tool{fixtureTool}, time.Minute)
	require.NoError(t, err)
	r := &BridgeRunner{Store: s, GrantID: g.ID}
	call := Call{ID: "call-one", Name: fixtureTool.Name, Arguments: `{"job":"job-a"}`}
	require.NoError(t, r.Authorize(ctx, b, fixtureTool, call))
	other := b
	other.UserID = 2
	require.ErrorIs(t, r.Authorize(ctx, other, fixtureTool, call), ErrTool)
	other = b
	other.SessionID = "another-session"
	require.ErrorIs(t, r.Authorize(ctx, other, fixtureTool, call), ErrTool)
	altered := fixtureTool
	altered.Parameters = json.RawMessage(`{"type":"object"}`)
	require.ErrorIs(t, r.Authorize(ctx, b, altered, call), ErrTool)
	_, err = s.Begin(ctx, b, fixtureBody())
	require.NoError(t, err)
	type runResult struct {
		output json.RawMessage
		err    error
	}
	finished := make(chan runResult, 1)
	go func() { out, e := r.Run(ctx, b, call); finished <- runResult{out, e} }()
	var d *Delivery
	require.Eventually(t, func() bool {
		d, err = s.Poll(ctx, b.UserID, b.KeyID, g.ID, g.Secret)
		require.NoError(t, err)
		return d != nil
	}, time.Second, 10*time.Millisecond)
	require.Equal(t, call, d.Call)
	twice, err := s.Poll(ctx, b.UserID, b.KeyID, g.ID, g.Secret)
	require.NoError(t, err)
	require.Nil(t, twice)
	require.ErrorIs(t, s.CompleteTool(ctx, b.UserID, b.KeyID, g.ID, g.Secret, d.TaskID, call.ID, "wrong-lease", json.RawMessage(`{"ok":true}`)), ErrTool)
	require.NoError(t, s.CompleteTool(ctx, b.UserID, b.KeyID, g.ID, g.Secret, d.TaskID, call.ID, d.Lease, json.RawMessage(`{"ok":true}`)))
	outcome := <-finished
	require.NoError(t, outcome.err)
	require.JSONEq(t, `{"ok":true}`, string(outcome.output))
	require.ErrorIs(t, s.CompleteTool(ctx, b.UserID, b.KeyID, g.ID, g.Secret, d.TaskID, call.ID, d.Lease, json.RawMessage(`{"ok":true}`)), ErrTool)
	require.NoError(t, s.RevokeGrant(ctx, b.UserID, b.KeyID, g.ID))
	require.ErrorIs(t, r.Authorize(ctx, b, fixtureTool, call), ErrTool)
}

func TestBridgeCancelledDispatchCannotBeReplayed(t *testing.T) {
	s := journalFixture(t)
	ctx := context.Background()
	b := fixtureBinding("gpt-5.6-sol")
	require.NoError(t, s.SetEnabled(ctx, b.UserID, b.KeyID, true))
	g, err := s.Grant(ctx, b.UserID, b.KeyID, b.SessionID, []Tool{fixtureTool}, time.Minute)
	require.NoError(t, err)
	_, err = s.Begin(ctx, b, fixtureBody())
	require.NoError(t, err)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	r := &BridgeRunner{Store: s, GrantID: g.ID}
	call := Call{ID: "cancelled-call", Name: fixtureTool.Name, Arguments: `{"job":"job-a"}`}
	ended := make(chan error, 1)
	go func() { _, e := r.Run(runCtx, b, call); ended <- e }()
	var d *Delivery
	require.Eventually(t, func() bool {
		d, err = s.Poll(ctx, b.UserID, b.KeyID, g.ID, g.Secret)
		require.NoError(t, err)
		return d != nil
	}, time.Second, 10*time.Millisecond)
	cancel()
	require.ErrorIs(t, <-ended, ErrUnknownOutcome)
	require.ErrorIs(t, s.CompleteTool(ctx, b.UserID, b.KeyID, g.ID, g.Secret, d.TaskID, call.ID, d.Lease, json.RawMessage(`{"ok":true}`)), ErrTool)
	again, err := s.Poll(ctx, b.UserID, b.KeyID, g.ID, g.Secret)
	require.NoError(t, err)
	require.Nil(t, again)
	_, err = r.Run(ctx, b, call)
	require.ErrorIs(t, err, ErrUnknownOutcome)
}
