package service

import (
	"context"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	"net/http"
	"testing"
)

func TestBasisPointsModelPermissionIsRequestScoped(t *testing.T) {
	account := &Account{ID: 48, Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Credentials: map[string]any{"base_url": "http://cpa:8317"}, Extra: map[string]any{"cpa_auth_id": "bound", BasisPointsEnabledExtraKey: true}}
	body := []byte(`{"error":{"code":"basispoints_model_not_available","message":"Model permission required","retryable":false}}`)
	svc := &OpenAIGatewayService{}
	require.False(t, svc.shouldFailoverOpenAIUpstreamResponse(account, 403, "", body))
	c, rec := newOpenAIUpstreamErrorTestContext(t)
	_, err := svc.handleErrorResponse(context.Background(), newOpenAIUpstreamErrorResponse(403, string(body)), c, account, nil, "gpt-6-sol")
	require.Error(t, err)
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Equal(t, "basispoints_model_not_available", gjson.GetBytes(rec.Body.Bytes(), "error.code").String())
	require.False(t, gjson.GetBytes(rec.Body.Bytes(), "error.retryable").Bool())
	account.Extra[BasisPointsEnabledExtraKey] = false
	require.True(t, svc.shouldFailoverOpenAIUpstreamResponse(account, 403, "", body))
	account.Extra[BasisPointsEnabledExtraKey] = true
	require.True(t, svc.shouldFailoverOpenAIUpstreamResponse(account, 403, "", []byte(`{"error":{"code":"account_deactivated"}}`)))
}
