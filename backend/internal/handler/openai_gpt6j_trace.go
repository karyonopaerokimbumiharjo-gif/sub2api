package handler

import (
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/executiontrace"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/tidwall/gjson"
)

const gpt6jTraceIDContextKey = "sub2api.gpt6j.trace_id"

// beginGPT6JTrace starts a metadata-only trace. The body is examined solely
// for known tool-result item types and their opaque call IDs; it is never stored.
func beginGPT6JTrace(c *gin.Context, body []byte) func() {
	if c == nil || c.Request == nil {
		return func() {}
	}
	requestID, _ := c.Request.Context().Value(ctxkey.RequestID).(string)
	requestID = strings.TrimSpace(requestID)
	if requestID == "" {
		requestID = uuid.NewString()
	}
	c.Set(gpt6jTraceIDContextKey, requestID)
	started := time.Now()
	recordGPT6JTrace(c, executiontrace.Event{Stage: "request", Model: gjson.GetBytes(body, "model").String()})
	recordedToolResults := 0
	for _, item := range gjson.GetBytes(body, "input").Array() {
		if recordedToolResults >= 8 {
			break
		}
		kind := item.Get("type").String()
		if kind != "function_call_output" && kind != "custom_tool_call_output" {
			continue
		}
		callID := strings.TrimSpace(item.Get("call_id").String())
		recordGPT6JTrace(c, executiontrace.Event{Stage: "client_tool_result", Tool: kind, CallID: callID})
		recordedToolResults++
	}
	return func() {
		recordGPT6JTrace(c, executiontrace.Event{
			Stage: "request_end", Status: c.Writer.Status(), DurationMS: time.Since(started).Milliseconds(),
		})
	}
}

func recordGPT6JTrace(c *gin.Context, event executiontrace.Event) {
	if c == nil {
		return
	}
	requestID, ok := c.Get(gpt6jTraceIDContextKey)
	if !ok {
		return
	}
	event.RequestID, _ = requestID.(string)
	executiontrace.Default.Append(event)
}
