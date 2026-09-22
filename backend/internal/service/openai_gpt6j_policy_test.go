package service

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestGPT6JFinalRequestRejectsMappedModel(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/v1/responses", nil)
	c.Set(OpenAIGPT6JContextKey, true)
	svc := &OpenAIGatewayService{}
	account := &Account{
		ID:          1,
		Platform:    PlatformOpenAI,
		Type:        AccountTypeOAuth,
		Credentials: map[string]any{"access_token": "test-token", "chatgpt_account_id": "test-account"},
	}
	body := []byte(`{"model":"gpt-5.6-sol"}`)
	_, err := svc.buildUpstreamRequest(context.Background(), c, account, body, "unused", false, "", false)
	require.Error(t, err)
	_, err = svc.buildUpstreamRequestOpenAIPassthrough(context.Background(), c, account, body, "unused")
	require.Error(t, err)
	require.NoError(t, validateGPT6JUpstreamModel(c, "gpt-6-astra"))
}
