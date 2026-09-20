package service

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestOpenAIGatewayServiceGenerateTextUsesInternalCodexResponses(t *testing.T) {
	upstream := &httpUpstreamRecorder{resp: &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body: io.NopCloser(strings.NewReader(
			"data: {\"type\":\"response.output_text.delta\",\"delta\":\"Safety: Safe\\n\"}\n\n" +
				"data: {\"type\":\"response.output_text.delta\",\"delta\":\"Categories: None\"}\n\n" +
				"data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":120,\"output_tokens\":8,\"input_tokens_details\":{\"cached_tokens\":20}}}}\n\n",
		)),
	}}
	svc := &OpenAIGatewayService{cfg: &config.Config{}, httpUpstream: upstream}
	account := &Account{
		ID: 16, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Concurrency: 2,
		Credentials: map[string]any{
			"access_token":       "oauth-token",
			"chatgpt_account_id": "chatgpt-account",
			"model_mapping": map[string]any{
				"gpt-5.3-codex-spark": "gpt-5.3-codex-spark",
			},
		},
	}

	result, err := svc.GenerateText(context.Background(), account, "gpt-5.3-codex-spark", "classify", "hello", 512)
	require.NoError(t, err)
	require.Equal(t, "Safety: Safe\nCategories: None", result.Text)
	require.Equal(t, "gpt-5.3-codex-spark", result.MappedModel)
	require.Equal(t, 120, result.Usage.InputTokens)
	require.Equal(t, 8, result.Usage.OutputTokens)
	require.Equal(t, 20, result.Usage.CacheReadInputTokens)
	require.Equal(t, chatgptCodexURL, upstream.lastReq.URL.String())
	require.Equal(t, "chatgpt.com", upstream.lastReq.Host)
	require.Equal(t, "Bearer oauth-token", upstream.lastReq.Header.Get("Authorization"))
	require.Equal(t, "low", gjson.GetBytes(upstream.lastBody, "reasoning.effort").String())
	require.False(t, gjson.GetBytes(upstream.lastBody, "max_output_tokens").Exists())
	require.False(t, gjson.GetBytes(upstream.lastBody, "store").Bool())
	require.Equal(t, "classify", gjson.GetBytes(upstream.lastBody, "instructions").String())
	require.Equal(t, "hello", gjson.GetBytes(upstream.lastBody, "input.0.content.0.text").String())
}

func TestParseOpenAIAuditSSERejectsFailedResponse(t *testing.T) {
	_, _, err := parseOpenAIAuditSSE(strings.NewReader(
		"data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"message\":\"plan gated\"}}}\n\n",
	))
	require.EqualError(t, err, "plan gated")
}

func TestOpenAIGatewayServiceGenerateTextReturnsTypedUpstreamStatus(t *testing.T) {
	upstream := &httpUpstreamRecorder{resp: &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"error":{"message":"rate limited"}}`)),
	}}
	svc := &OpenAIGatewayService{cfg: &config.Config{}, httpUpstream: upstream}
	account := &Account{ID: 16, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Credentials: map[string]any{
		"access_token": "oauth-token", "chatgpt_account_id": "chatgpt-account",
	}}

	_, err := svc.GenerateText(context.Background(), account, "gpt-5.3-codex-spark", "classify", "hello", 512)
	var upstreamErr *UpstreamFailoverError
	require.ErrorAs(t, err, &upstreamErr)
	require.Equal(t, http.StatusTooManyRequests, upstreamErr.StatusCode)
}
