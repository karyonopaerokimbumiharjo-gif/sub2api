package handler

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type outputAuditEngineStub struct {
	body      []byte
	streaming bool
	calls     int
	capture   *securityaudit.OutputCapture
}

func (*outputAuditEngineStub) EffectiveMode() securityaudit.Mode { return securityaudit.ModeBlocking }
func (*outputAuditEngineStub) Enqueue(context.Context, securityaudit.Request) error {
	return nil
}
func (*outputAuditEngineStub) Evaluate(context.Context, securityaudit.Request) (*securityaudit.PromptDecision, error) {
	return &securityaudit.PromptDecision{Kind: securityaudit.DecisionAllow, AllowNextStage: true}, nil
}
func (*outputAuditEngineStub) ShouldAuditOutput(securityaudit.Request, securityaudit.DecisionKind) bool {
	return true
}
func (s *outputAuditEngineStub) ObserveOutput(_ context.Context, req securityaudit.Request, _ securityaudit.DecisionKind, body []byte, streaming bool) {
	s.calls++
	s.capture = req.OutputCapture
	s.body = append([]byte(nil), body...)
	s.streaming = streaming
}

func TestSecurityAuditOutputWriterCapturesAllNonStreamingWrites(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest("POST", "/v1/chat/completions", nil)
	engine := &outputAuditEngineStub{}
	coordinator := securityaudit.NewCoordinator(nil, engine)

	installSecurityAuditOutputCapture(c, coordinator, securityaudit.Request{
		RequestID: "output-multi-write", Stage: "http", Body: []byte(`{"stream":false}`),
	}, securityaudit.DecisionAllow)
	w, ok := c.Writer.(*securityAuditOutputWriter)
	require.True(t, ok)

	_, err := w.Write([]byte(`{"choices":[{"message":{"content":"first`))
	require.NoError(t, err)
	require.Zero(t, engine.calls, "non-streaming output must not finalize on the first partial write")
	_, err = w.WriteString(` second"}}]}`)
	require.NoError(t, err)
	require.Zero(t, engine.calls)

	w.finish()
	require.Equal(t, 1, engine.calls)
	require.Equal(t, `{"choices":[{"message":{"content":"first second"}}]}`, string(engine.body))
	require.False(t, engine.streaming)
}

func TestSecurityAuditOutputWriterFinalizesStreamingTerminalOnce(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest("POST", "/v1/responses", nil)
	engine := &outputAuditEngineStub{}
	coordinator := securityaudit.NewCoordinator(nil, engine)

	installSecurityAuditOutputCapture(c, coordinator, securityaudit.Request{
		RequestID: "output-stream", Stage: "http", Body: []byte(`{"stream":true}`),
	}, securityaudit.DecisionAllow)
	w, ok := c.Writer.(*securityAuditOutputWriter)
	require.True(t, ok)

	_, err := w.WriteString("data: {\"delta\":\"hello\"}\n\n")
	require.NoError(t, err)
	require.Zero(t, engine.calls)
	_, err = w.WriteString("data: [DONE]\n\n")
	require.NoError(t, err)
	require.Zero(t, engine.calls)
	w.finish()
	require.True(t, engine.streaming)
	require.Equal(t, 1, engine.calls)
}

func TestOutputAuditDoesNotFinishOnTextAndTracksPartial(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/v1/responses", nil)
	engine := &outputAuditEngineStub{}
	installSecurityAuditOutputCapture(c, securityaudit.NewCoordinator(nil, engine), securityaudit.Request{Stage: "http", Body: []byte(`{"stream":true}`)}, securityaudit.DecisionAllow)
	w := c.Writer.(*securityAuditOutputWriter)
	_, _ = w.WriteString("data: {\"type\":\"response.output_text.delta\",\"delta\":\"response.completed [DONE] message_stop\"}\n\n")
	require.Zero(t, engine.calls)
	_, _ = w.WriteString(strings.Repeat("x", maxSecurityAuditOutputCaptureBytes))
	_, _ = w.WriteString("\n\ndata: [DO")
	require.Zero(t, engine.calls)
	_, _ = w.WriteString("NE]\n\n")
	require.Zero(t, engine.calls)
	w.finish()
	require.Equal(t, 1, engine.calls)
	require.True(t, engine.capture.Truncated)
	require.False(t, engine.capture.Complete)
	require.Greater(t, engine.capture.ObservedBytes, int64(engine.capture.CapturedBytes))
	require.Equal(t, "completed", engine.capture.Terminal)
}

func TestOutputAuditMiddlewareFinishesNonStreamingAndCancelled(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		engine := &outputAuditEngineStub{}
		router := gin.New()
		router.Use(SecurityAuditOutputFinalizer())
		router.POST("/", func(c *gin.Context) {
			installSecurityAuditOutputCapture(c, securityaudit.NewCoordinator(nil, engine), securityaudit.Request{Stage: "http"}, securityaudit.DecisionAllow)
			_, _ = c.Writer.WriteString(`{"output":[]}`)
		})
		req := httptest.NewRequest("POST", "/", nil)
		ctx, cancel := context.WithCancel(req.Context())
		defer cancel()
		if cancelled {
			cancel()
		}
		router.ServeHTTP(httptest.NewRecorder(), req.WithContext(ctx))
		require.Equal(t, 1, engine.calls)
		require.Equal(t, !cancelled, engine.capture.Complete)
		if cancelled {
			require.Equal(t, "cancelled", engine.capture.Terminal)
		}
	}
}

func TestOutputAuditRecordsEmptyCancelledStream(t *testing.T) {
	engine := &outputAuditEngineStub{}
	router := gin.New()
	router.Use(SecurityAuditOutputFinalizer())
	router.POST("/", func(c *gin.Context) {
		installSecurityAuditOutputCapture(c, securityaudit.NewCoordinator(nil, engine), securityaudit.Request{Stage: "http", Body: []byte(`{"stream":true}`)}, securityaudit.DecisionAllow)
	})
	req := httptest.NewRequest("POST", "/", nil)
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	router.ServeHTTP(httptest.NewRecorder(), req.WithContext(ctx))
	require.Equal(t, 1, engine.calls)
	require.Equal(t, "cancelled", engine.capture.Terminal)
	require.False(t, engine.capture.Complete)
	require.Empty(t, engine.body)
}

func TestOutputAuditFailureCannotBeOverwrittenByDone(t *testing.T) {
	engine := &outputAuditEngineStub{}
	router := gin.New()
	router.Use(SecurityAuditOutputFinalizer())
	router.POST("/", func(c *gin.Context) {
		installSecurityAuditOutputCapture(c, securityaudit.NewCoordinator(nil, engine), securityaudit.Request{Stage: "http", Body: []byte(`{"stream":true}`)}, securityaudit.DecisionAllow)
		_, _ = c.Writer.WriteString("data: {\"type\":\"response.failed\"}\n\ndata: [DONE]\n\n")
	})
	router.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil))
	require.Equal(t, 1, engine.calls)
	require.Equal(t, "failed", engine.capture.Terminal)
	require.False(t, engine.capture.Complete)
}
