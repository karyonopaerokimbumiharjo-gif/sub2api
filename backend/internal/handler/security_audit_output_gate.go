package handler

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"

	"github.com/Wei-Shaw/sub2api/internal/jruntime"
	"github.com/Wei-Shaw/sub2api/internal/pkg/sseparse"
	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
	"github.com/gin-gonic/gin"
)

const strictOutputKey = "sub2api.security_audit.strict_output"

// Withholds headers and every response byte until a complete output is reviewed.
// It intentionally buffers SSE for limited assistance; Flush cannot bypass it.
type strictOutputWriter struct {
	gin.ResponseWriter
	header       http.Header
	status, size int
	body         bytes.Buffer
	overflow     bool
	coordinator  *securityaudit.Coordinator
	request      securityaudit.Request
	stream       bool
	once         sync.Once
}

func installStrictOutput(c *gin.Context, coordinator *securityaudit.Coordinator, req securityaudit.Request) {
	if _, ok := c.Get(strictOutputKey); ok {
		return
	}
	w := &strictOutputWriter{ResponseWriter: c.Writer, header: c.Writer.Header().Clone(), status: 200, size: -1, coordinator: coordinator, request: req.Clone(), stream: requestBodyStreams(req.Body)}
	c.Writer = w
	c.Set(strictOutputKey, w)
}
func (w *strictOutputWriter) Header() http.Header { return w.header }
func (w *strictOutputWriter) Status() int         { return w.status }
func (w *strictOutputWriter) Size() int           { return w.size }
func (w *strictOutputWriter) Written() bool       { return w.size >= 0 }
func (w *strictOutputWriter) WriteHeader(status int) {
	if !w.Written() {
		w.status = status
	}
}
func (w *strictOutputWriter) WriteHeaderNow() {
	if w.size < 0 {
		w.size = 0
	}
}
func (w *strictOutputWriter) Write(p []byte) (int, error) {
	w.WriteHeaderNow()
	if w.body.Len()+len(p) > maxSecurityAuditOutputCaptureBytes {
		w.overflow = true
		return 0, errors.New("strict_output_limit_exceeded")
	}
	n, err := w.body.Write(p)
	w.size += n
	return n, err
}
func (w *strictOutputWriter) WriteString(p string) (int, error) { return w.Write([]byte(p)) }
func (w *strictOutputWriter) Flush()                            { w.WriteHeaderNow() }
func (w *strictOutputWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, errors.New("strict_output_upgrade_not_supported")
}
func (w *strictOutputWriter) Pusher() http.Pusher { return nil }
func (w *strictOutputWriter) finish(ctx context.Context) {
	w.once.Do(func() {
		if ctx.Err() != nil {
			return
		}
		body := w.body.Bytes()
		if w.status >= 200 && w.status < 300 {
			decision := securityaudit.Decision{HTTPStatus: 503, ErrorCode: securityaudit.ErrorCodeUnavailable, ClientMessage: "输出安全检查未完成，本次未返回生成内容"}
			if !w.overflow && completeStrictOutput(body, w.stream) {
				decision = w.coordinator.GateOutput(ctx, w.request, body, w.stream)
			}
			if ctx.Err() != nil {
				return
			}
			if !decision.AllowNextStage {
				status := decision.HTTPStatus
				if status < 400 {
					status = 503
				}
				w.ResponseWriter.Header().Set("Content-Type", "application/json")
				w.ResponseWriter.Header().Del("Content-Length")
				w.ResponseWriter.WriteHeader(status)
				safe, _ := json.Marshal(map[string]any{"error": map[string]string{"type": "safety_error", "code": decision.ErrorCode, "message": decision.ClientMessage}})
				_, _ = w.ResponseWriter.Write(safe)
				return
			}
		}
		if w.overflow {
			w.ResponseWriter.WriteHeader(502)
			return
		}
		for k := range w.ResponseWriter.Header() {
			w.ResponseWriter.Header().Del(k)
		}
		for k, v := range w.header {
			w.ResponseWriter.Header()[k] = append([]string(nil), v...)
		}
		w.ResponseWriter.Header().Del("Content-Length")
		w.ResponseWriter.WriteHeader(w.status)
		_, _ = w.ResponseWriter.Write(body)
	})
}

func completeStrictOutput(body []byte, stream bool) bool {
	if !stream {
		var envelope struct {
			Status  string `json:"status"`
			Object  string `json:"object"`
			Choices []struct {
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
		}
		if json.Unmarshal(body, &envelope) != nil {
			return false
		}
		if envelope.Status != "" {
			return envelope.Status == "completed"
		}
		if len(envelope.Choices) > 0 {
			for _, v := range envelope.Choices {
				if v.FinishReason == nil || (*v.FinishReason != "stop" && *v.FinishReason != "tool_calls" && *v.FinishReason != "function_call") {
					return false
				}
			}
			return true
		}
		return false
	}
	var parser sseparse.Parser
	terminal := ""
	invalid := false
	parser.Feed(body, func(event sseparse.Event) {
		if end := event.Terminal(); end != "" {
			if end != "completed" {
				invalid = true
			}
			terminal = end
		}
		var envelope struct {
			Choices []struct {
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
		}
		if json.Unmarshal(event.Data, &envelope) == nil {
			for _, v := range envelope.Choices {
				if v.FinishReason != nil && *v.FinishReason != "stop" && *v.FinishReason != "tool_calls" && *v.FinishReason != "function_call" {
					invalid = true
				}
			}
		}
	})
	return terminal == "completed" && !invalid && !parser.Truncated
}

// A model-produced tool action must pass the same gate before local side effects.
type gatedJTools struct {
	jruntime.ToolRunner
	gate *strictOutputWriter
}

func (g *gatedJTools) Authorize(ctx context.Context, b jruntime.Binding, t jruntime.Tool, c jruntime.Call) error {
	if err := g.ToolRunner.Authorize(ctx, b, t, c); err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{"status": "completed", "output": []any{map[string]string{"type": "function_call", "name": c.Name, "arguments": c.Arguments}}})
	if d := g.gate.coordinator.GateOutput(ctx, g.gate.request, body, false); !d.AllowNextStage {
		return jruntime.ErrSafety
	}
	return nil
}
