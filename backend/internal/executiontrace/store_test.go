package executiontrace

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStoreRedactsUntrustedMetadata(t *testing.T) {
	store := NewStore(8, time.Hour)
	store.Append(Event{
		RequestID: "request-1", Stage: "client_tool_result", Tool: "function_call_output",
		CallID: "sk-client-secret", Model: "secret words", Reason: "token-secret",
		ResponseID: "resp_ok", Status: 200,
	})
	events := store.List("request-1", 10)
	require.Len(t, events, 1)
	require.Equal(t, "", events[0].Model)
	require.Equal(t, "request_failed", events[0].Reason)
	require.Equal(t, "function_call_output", events[0].Tool)
	require.Len(t, events[0].CallID, 16)
	raw, err := json.Marshal(events)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "sk-client-secret")
	require.NotContains(t, string(raw), "token-secret")
	require.NotContains(t, string(raw), "secret words")
	require.NotContains(t, string(raw), "state_source")
}

func TestStoreBoundedTTLAndRequestLimit(t *testing.T) {
	store := NewStore(2, time.Minute)
	now := time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	for _, id := range []string{"request-1", "request-2", "request-3"} {
		store.Append(Event{RequestID: id, Stage: "request"})
	}
	got := store.List("", 99)
	require.Len(t, got, 2)
	require.Equal(t, "request-3", got[0].RequestID)
	require.Equal(t, "request-2", got[1].RequestID)
	now = now.Add(2 * time.Minute)
	require.Empty(t, store.List("", 99))

	perRequest := NewStore(100, time.Hour)
	for range 40 {
		perRequest.Append(Event{RequestID: "request-one", Stage: "gpt_response"})
	}
	require.Len(t, perRequest.List("request-one", 100), maxEventsPerRequest)
	require.Empty(t, perRequest.List("unsafe request", 100))
}

func TestStoreRejectsUnknownStagesAndOversizedIdentifiers(t *testing.T) {
	store := NewStore(8, time.Hour)
	store.Append(Event{RequestID: "request-1", Stage: "prompt body"})
	store.Append(Event{RequestID: strings.Repeat("x", 129), Stage: "request"})
	require.Empty(t, store.List("", 10))
}

func TestStoreRetainsBothFailureAndEndAfterSaturation(t *testing.T) {
	store := NewStore(100, time.Hour)
	store.Append(Event{RequestID: "many", Stage: "request"})
	for range 40 {
		store.Append(Event{RequestID: "many", Stage: "tool_call"})
	}
	store.Append(Event{RequestID: "many", Stage: "request_failed", Reason: "upstream_failed"})
	store.Append(Event{RequestID: "many", Stage: "request_end", Status: 502})
	events := store.List("many", 100)
	require.Len(t, events, maxEventsPerRequest)
	require.Equal(t, "request_end", events[0].Stage)
	require.Equal(t, "request_failed", events[1].Stage)
	dropped := 0
	for _, event := range events {
		dropped += event.EventsDropped
	}
	require.Equal(t, 43-maxEventsPerRequest, dropped)
}
