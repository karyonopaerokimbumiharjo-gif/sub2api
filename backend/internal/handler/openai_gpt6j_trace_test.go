package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/executiontrace"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestGPT6JTraceRecordsMetadataWithoutBodies(t *testing.T) {
	previous := executiontrace.Default
	executiontrace.Default = executiontrace.NewStore(16, time.Hour)
	t.Cleanup(func() { executiontrace.Default = previous })

	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest("POST", "/v1/responses", nil)
	c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), ctxkey.RequestID, "request-1"))
	body := []byte(`{"model":"gpt-6j","input":[{"type":"function_call_output","call_id":"secret-call-id","output":"private tool output"},{"role":"user","content":"private prompt"}]}`)
	end := beginGPT6JTrace(c, body)
	recordGPT6JTrace(c, executiontrace.Event{Stage: "guard_result", Reason: "allowed"})
	recorder.WriteHeader(200)
	end()

	events := executiontrace.Default.List("request-1", 20)
	require.Len(t, events, 4)
	require.Equal(t, "request_end", events[0].Stage)
	require.Equal(t, 200, events[0].Status)
	require.Equal(t, "guard_result", events[1].Stage)
	require.Equal(t, "client_tool_result", events[2].Stage)
	require.Len(t, events[2].CallID, 16)
	require.Equal(t, "request", events[3].Stage)
	raw, err := json.Marshal(events)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "private tool output")
	require.NotContains(t, string(raw), "private prompt")
	require.NotContains(t, string(raw), "secret-call-id")
}

func TestGPT6JTraceIgnoresUnmarkedRequest(t *testing.T) {
	previous := executiontrace.Default
	executiontrace.Default = executiontrace.NewStore(16, time.Hour)
	t.Cleanup(func() { executiontrace.Default = previous })
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	recordGPT6JTrace(c, executiontrace.Event{Stage: "request_failed", Reason: "upstream_error"})
	require.Empty(t, executiontrace.Default.List("", 10))
}

func TestTraceSamplesRecentToolsAcrossResponsesAndChat(t *testing.T) {
	for _, chat := range []bool{false, true} {
		previous := executiontrace.Default
		executiontrace.Default = executiontrace.NewStore(64, time.Hour)
		t.Cleanup(func() { executiontrace.Default = previous })
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("POST", "/", nil)
		items := make([]map[string]string, 12)
		for i := range items {
			if chat {
				items[i] = map[string]string{"role": "tool", "tool_call_id": fmt.Sprintf("call-%d", i), "content": "private"}
			} else {
				items[i] = map[string]string{"type": "function_call_output", "call_id": fmt.Sprintf("call-%d", i), "output": "private"}
			}
		}
		key := "input"
		if chat {
			key = "messages"
		}
		body, _ := json.Marshal(map[string]any{key: items})
		end := beginGPT6JTrace(c, body)
		end()
		events := executiontrace.Default.List("", 100)
		require.Len(t, events, 10)
		// The first retained tool result is the fifth, not the oldest entry.
		expected := executiontrace.NewStore(4, time.Hour)
		expected.Append(executiontrace.Event{RequestID: "expected", Stage: "client_tool_result", CallID: "call-4"})
		require.Equal(t, expected.List("", 1)[0].CallID, events[8].CallID)
		require.Equal(t, 12, events[8].ToolResultsSeen)
		require.Equal(t, 4, events[8].ToolResultsOmitted)
		require.True(t, events[8].HistorySample)
	}
}
