package service

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestDetectOpenAIBioPolicy(t *testing.T) {
	for _, payload := range []string{
		`{"error":{"code":"bio_policy","message":"blocked for possible biological risk"}}`,
		`{"type":"response.failed","response":{"error":{"code":"bio_policy","message":"blocked"}}}`,
	} {
		hit, code, message := detectOpenAIBioPolicy([]byte(payload))
		require.True(t, hit)
		require.Equal(t, "bio_policy", code)
		require.NotEmpty(t, message)
	}

	hit, code, message := detectOpenAIBioPolicy([]byte(`{"error":{"code":"server_error","message":"boom"}}`))
	require.False(t, hit)
	require.Empty(t, code)
	require.Empty(t, message)
}

func TestMarkOpsBioPolicyFirstWinsAndClear(t *testing.T) {
	c, _ := gin.CreateTestContext(nil)
	require.Nil(t, GetOpsBioPolicy(c))

	MarkOpsBioPolicy(c, BioPolicyMark{Code: "bio_policy", Message: "first", UpstreamStatus: http.StatusBadGateway})
	MarkOpsBioPolicy(c, BioPolicyMark{Code: "bio_policy", Message: "second"})
	require.Equal(t, "first", GetOpsBioPolicy(c).Message)
	require.Equal(t, http.StatusBadGateway, GetOpsBioPolicy(c).UpstreamStatus)

	ClearOpsBioPolicy(c)
	require.Nil(t, GetOpsBioPolicy(c))
	MarkOpsBioPolicy(c, BioPolicyMark{Code: "bio_policy", Message: "third"})
	require.Equal(t, "third", GetOpsBioPolicy(c).Message)
}

func TestSanitizeOpenAIPolicyFailureBodyDropsInstructions(t *testing.T) {
	raw := []byte(`{"type":"response.failed","response":{"id":"resp_1","status":"failed","model":"gpt-test","error":{"code":"bio_policy","message":"blocked"},"instructions":"secret Oracle Anti-Patterns"}}`)
	clean := sanitizeOpenAIPolicyFailureBody(raw)
	require.Contains(t, clean, `"code":"bio_policy"`)
	require.Contains(t, clean, `"status":"failed"`)
	require.NotContains(t, clean, "instructions")
	require.NotContains(t, clean, "Oracle")
	require.Empty(t, sanitizeOpenAIPolicyFailureBody([]byte(`{"type":"response.failed","response":{"instructions":"truncated"`)))
}

func TestBioPolicyNeverTriggersAccountFailover(t *testing.T) {
	svc := &OpenAIGatewayService{}
	body := []byte(`{"error":{"code":"bio_policy","message":"possible biological risk"}}`)
	require.False(t, svc.shouldFailoverOpenAIUpstreamResponse(nil, http.StatusBadGateway, "", body))
	require.False(t, openAIStreamFailedEventShouldFailover(body, "temporary server error"))
	require.False(t, openAIStreamErrorEventShouldFailover(body, "temporary server error"))
	require.True(t, svc.shouldFailoverOpenAIUpstreamResponse(nil, http.StatusBadGateway, "temporary upstream outage", []byte(`{"error":{"message":"temporary upstream outage"}}`)))
}

func TestHandleErrorResponseBioPolicyMapsUpstream502ToSemantic403(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(nil))
	body := `{"error":{"code":"bio_policy","message":"flagged for possible biological risk"}}`
	resp := &http.Response{
		StatusCode: http.StatusBadGateway,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}
	svc := &OpenAIGatewayService{}

	result, err := svc.handleErrorResponse(context.Background(), resp, c, compatCyberOAuthAccount(), nil)
	require.Error(t, err)
	require.Nil(t, result)
	require.Equal(t, http.StatusForbidden, recorder.Code)
	require.JSONEq(t, `{"error":{"type":"invalid_request_error","code":"bio_policy","message":"`+OpenAIBioPolicyClientMessage+`"}}`, recorder.Body.String())
	mark := GetOpsBioPolicy(c)
	require.NotNil(t, mark)
	require.Equal(t, http.StatusBadGateway, mark.UpstreamStatus)
}

func TestApplyOpenAIStreamFailedBioPolicyMapsTo403AndMarks(t *testing.T) {
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	payload := []byte(`{"type":"response.failed","response":{"error":{"code":"bio_policy","message":"flagged"}}}`)

	status, errType, message, matched := applyOpenAIStreamFailedErrorPassthroughRule(c, PlatformOpenAI, payload, "flagged")
	require.True(t, matched)
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, "invalid_request_error", errType)
	require.Equal(t, OpenAIBioPolicyClientMessage, message)
	require.NotNil(t, GetOpsBioPolicy(c))
}
