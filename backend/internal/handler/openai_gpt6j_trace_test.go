package handler

import (
	"context"
	"encoding/json"
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
