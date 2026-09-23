package handler

import (
	"context"
	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"strings"
	"testing"
)

type strictGateStub struct {
	outputAuditEngineStub
	allow     bool
	gateCalls int
	recorder  *httptest.ResponseRecorder
}

func (s *strictGateStub) GateOutput(_ context.Context, _ securityaudit.Request, body []byte, _ bool) securityaudit.Decision {
	s.gateCalls++
	if s.recorder.Body.Len() != 0 {
		panic("output leaked before review")
	}
	return securityaudit.Decision{AllowNextStage: s.allow, HTTPStatus: 403, ErrorCode: "blocked", ClientMessage: "blocked"}
}
func TestStrictOutputWithholdsEveryByte(t *testing.T) {
	for _, allow := range []bool{true, false} {
		for _, stream := range []bool{true, false} {
			t.Run(strings.Join([]string{map[bool]string{true: "allow", false: "deny"}[allow], map[bool]string{true: "sse", false: "json"}[stream]}, "/"), func(t *testing.T) {
				rec := httptest.NewRecorder()
				s := &strictGateStub{allow: allow, recorder: rec}
				router := gin.New()
				router.Use(SecurityAuditOutputFinalizer())
				router.POST("/", func(c *gin.Context) {
					request := securityaudit.Request{Stage: "http"}
					if stream {
						request.Body = []byte(`{"stream":true}`)
					}
					installStrictOutput(c, securityaudit.NewCoordinator(nil, s), request)
					c.Writer.Header().Set("Content-Type", "text/event-stream")
					if stream {
						_, _ = c.Writer.WriteString("data: {\"type\":\"response.output_text.delta\",\"delta\":\"private_text\"}\n\n")
						c.Writer.Flush()
						require.Empty(t, rec.Body.String())
						_, _ = c.Writer.WriteString("data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n")
					} else {
						_, _ = c.Writer.WriteString(`{"status":"completed","output_text":"private_text"}`)
					}
					require.Empty(t, rec.Body.String())
				})
				router.ServeHTTP(rec, httptest.NewRequest("POST", "/", nil))
				require.Equal(t, 1, s.gateCalls)
				if allow {
					require.Equal(t, 200, rec.Code)
					require.Contains(t, rec.Body.String(), "private_text")
				} else {
					require.Equal(t, 403, rec.Code)
					require.NotContains(t, rec.Body.String(), "private_text")
					require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
				}
			})
		}
	}
}
func TestStrictOutputIncompleteOversizedAndCancelledNeverReleased(t *testing.T) {
	for _, kind := range []string{"incomplete", "oversized", "cancelled", "failed_after_done", "length"} {
		t.Run(kind, func(t *testing.T) {
			rec := httptest.NewRecorder()
			s := &strictGateStub{allow: true, recorder: rec}
			c, _ := gin.CreateTestContext(rec)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c.Request = httptest.NewRequest("POST", "/", nil).WithContext(ctx)
			installStrictOutput(c, securityaudit.NewCoordinator(nil, s), securityaudit.Request{Stage: "http", Body: []byte(`{"stream":true}`)})
			w := c.Writer.(*strictOutputWriter)
			_, _ = w.WriteString("data: {\"delta\":\"private_text\"}\n\n")
			switch kind {
			case "oversized":
				_, _ = w.WriteString(strings.Repeat("x", maxSecurityAuditOutputCaptureBytes))
			case "cancelled":
				cancel()
			case "failed_after_done":
				_, _ = w.WriteString("data: [DONE]\n\ndata: {\"type\":\"response.failed\"}\n\n")
			case "length":
				_, _ = w.WriteString("data: {\"choices\":[{\"finish_reason\":\"length\"}]}\n\ndata: [DONE]\n\n")
			}
			w.finish(ctx)
			require.Zero(t, s.gateCalls)
			require.NotContains(t, rec.Body.String(), "private_text")
			if kind != "cancelled" {
				require.Equal(t, 503, rec.Code)
			} else {
				require.Empty(t, rec.Body.String())
			}
		})
	}
}
