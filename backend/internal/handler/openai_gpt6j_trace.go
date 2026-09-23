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
	results := make([]executiontrace.Event, 0, 8)
	for _, item := range gjson.GetBytes(body, "input").Array() {
		kind := item.Get("type").String()
		if kind == "function_call_output" || kind == "custom_tool_call_output" {
			results = append(results, executiontrace.Event{Stage: "client_tool_result", Tool: kind, CallID: strings.TrimSpace(item.Get("call_id").String())})
		}
	}
	for _, item := range gjson.GetBytes(body, "messages").Array() {
		if item.Get("role").String() == "tool" {
			results = append(results, executiontrace.Event{Stage: "client_tool_result", Tool: "chat_tool_result", CallID: strings.TrimSpace(item.Get("tool_call_id").String())})
		}
	}
	seen := len(results)
	if len(results) > 8 {
		results = results[len(results)-8:]
	}
	for i, event := range results {
		event.HistorySample = true
		if i == 0 {
			event.ToolResultsSeen = seen
			event.ToolResultsOmitted = seen - len(results)
		}
		recordGPT6JTrace(c, event)
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
