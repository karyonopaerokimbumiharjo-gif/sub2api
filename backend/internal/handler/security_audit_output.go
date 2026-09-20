package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"

	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
	"github.com/gin-gonic/gin"
)

const (
	securityAuditOutputCaptureContextKey = "sub2api.security_audit.output_capture"
	maxSecurityAuditOutputCaptureBytes   = 1 << 20
)

type securityAuditOutputWriter struct {
	gin.ResponseWriter
	coordinator   *securityaudit.Coordinator
	request       securityaudit.Request
	inputDecision securityaudit.DecisionKind
	streaming     bool

	mu        sync.Mutex
	buffer    bytes.Buffer
	truncated bool
	once      sync.Once
}

func installSecurityAuditOutputCapture(c *gin.Context, coordinator *securityaudit.Coordinator, request securityaudit.Request, inputDecision securityaudit.DecisionKind) {
	if c == nil || c.Request == nil || coordinator == nil || request.Stage != "http" {
		return
	}
	if _, exists := c.Get(securityAuditOutputCaptureContextKey); exists {
		return
	}
	if !coordinator.ShouldAuditOutput(request, inputDecision) {
		return
	}
	writer := &securityAuditOutputWriter{
		ResponseWriter: c.Writer,
		coordinator:    coordinator,
		request:        request.Clone(),
		inputDecision:  inputDecision,
		streaming:      requestBodyStreams(request.Body),
	}
	c.Writer = writer
	c.Set(securityAuditOutputCaptureContextKey, true)
	done := c.Request.Context().Done()
	if done != nil {
		go func() {
			<-done
			writer.finish()
		}()
	}
}

func (w *securityAuditOutputWriter) Write(value []byte) (int, error) {
	w.capture(value)
	written, err := w.ResponseWriter.Write(value)
	if w.streaming && containsOutputTerminal(value) {
		w.finish()
	}
	return written, err
}

func (w *securityAuditOutputWriter) WriteString(value string) (int, error) {
	w.capture([]byte(value))
	written, err := w.ResponseWriter.WriteString(value)
	if w.streaming && containsOutputTerminal([]byte(value)) {
		w.finish()
	}
	return written, err
}

func (w *securityAuditOutputWriter) capture(value []byte) {
	if w == nil || len(value) == 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	remaining := maxSecurityAuditOutputCaptureBytes - w.buffer.Len()
	if remaining <= 0 {
		w.truncated = true
		return
	}
	if len(value) > remaining {
		value = value[:remaining]
		w.truncated = true
	}
	_, _ = w.buffer.Write(value)
}

func (w *securityAuditOutputWriter) finish() {
	if w == nil {
		return
	}
	w.once.Do(func() {
		status := w.Status()
		if status < 200 || status >= 300 {
			return
		}
		w.mu.Lock()
		body := append([]byte(nil), w.buffer.Bytes()...)
		w.mu.Unlock()
		if len(body) == 0 {
			return
		}
		w.coordinator.ObserveOutput(context.Background(), w.request, w.inputDecision, body, w.streaming)
	})
}

func requestBodyStreams(body []byte) bool {
	var envelope struct {
		Stream bool `json:"stream"`
	}
	return json.Unmarshal(body, &envelope) == nil && envelope.Stream
}

func containsOutputTerminal(value []byte) bool {
	text := string(value)
	return strings.Contains(text, "[DONE]") ||
		strings.Contains(text, "response.completed") ||
		strings.Contains(text, "message_stop")
}
