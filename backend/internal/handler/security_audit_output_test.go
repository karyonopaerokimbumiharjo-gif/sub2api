package handler

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type outputAuditEngineStub struct {
	body      []byte
	streaming bool
	calls     int
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
func (s *outputAuditEngineStub) ObserveOutput(_ context.Context, _ securityaudit.Request, _ securityaudit.DecisionKind, body []byte, streaming bool) {
	s.calls++
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
	require.Equal(t, 1, engine.calls)
	require.True(t, engine.streaming)
	w.finish()
	require.Equal(t, 1, engine.calls)
}
