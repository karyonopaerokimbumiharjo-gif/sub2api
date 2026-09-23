package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"

	"github.com/Wei-Shaw/sub2api/internal/pkg/sseparse"
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

	mu          sync.Mutex
	buffer      bytes.Buffer
	truncated   bool
	observed    int64
	terminal    string
	parser      sseparse.Parser
	writeFailed bool
	once        sync.Once
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
	c.Set(securityAuditOutputCaptureContextKey, writer)
}

// SecurityAuditOutputFinalizer runs before Gin recycles its context/writer. It
// also closes partial responses and client cancellations without a background
// goroutine racing on a pooled ResponseWriter.
func SecurityAuditOutputFinalizer() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if value, ok := c.Get(strictOutputKey); ok {
				if w, ok := value.(*strictOutputWriter); ok {
					w.finish(c.Request.Context())
				}
				return
			}
			if value, ok := c.Get(securityAuditOutputCaptureContextKey); ok {
				if writer, ok := value.(*securityAuditOutputWriter); ok {
					writer.mu.Lock()
					if c.Request.Context().Err() != nil && writer.terminal != "completed" {
						writer.terminal = "cancelled"
					}
					writer.mu.Unlock()
					writer.finish()
				}
			}
		}()
		c.Next()
	}
}

func (w *securityAuditOutputWriter) Write(value []byte) (int, error) {
	written, err := w.ResponseWriter.Write(value)
	w.capture(value[:written])
	if err != nil {
		w.mu.Lock()
		w.writeFailed = true
		w.mu.Unlock()
	}
	// Finalize at handler exit: a later failure must not be hidden by a
	// success marker earlier in the same transport write.
	return written, err
}

func (w *securityAuditOutputWriter) WriteString(value string) (int, error) {
	return w.Write([]byte(value))
}

func (w *securityAuditOutputWriter) capture(value []byte) {
	if w == nil || len(value) == 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.observed += int64(len(value))
	if w.streaming {
		w.parser.Feed(value, func(event sseparse.Event) {
			if terminal := event.Terminal(); terminal != "" && (w.terminal == "" || w.terminal == "completed") {
				w.terminal = terminal
			}
		})
	}
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
		terminal := w.terminal
		if terminal == "" {
			terminal = "incomplete"
			if !w.streaming && !w.writeFailed && json.Valid(body) {
				terminal = "completed"
			}
		}
		request := w.request.Clone()
		request.OutputCapture = &securityaudit.OutputCapture{
			CapturedBytes: len(body), ObservedBytes: w.observed,
			Truncated: w.truncated || w.parser.Truncated,
			Complete:  terminal == "completed" && !w.truncated && !w.parser.Truncated && !w.writeFailed,
			Terminal:  terminal,
		}
		w.mu.Unlock()
		w.coordinator.ObserveOutput(context.Background(), request, w.inputDecision, body, w.streaming)
	})
}

func requestBodyStreams(body []byte) bool {
	var envelope struct {
		Stream bool `json:"stream"`
	}
	return json.Unmarshal(body, &envelope) == nil && envelope.Stream
}
