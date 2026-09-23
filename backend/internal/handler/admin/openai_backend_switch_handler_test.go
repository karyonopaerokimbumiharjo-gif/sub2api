package admin

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPiCredentialsFromCPAOnlyKeepsOAuthIdentity(t *testing.T) {
	source := map[string]any{
		"access_token":       "access",
		"refresh_token":      "refresh",
		"id_token":           "id",
		"email":              "user@example.com",
		"chatgpt_account_id": "acct-1",
		"expires_at":         "2026-09-24T00:00:00Z",
		"proxy_url":          "http://proxy.invalid",
		"retry":              4,
		"weight":             2,
		"sub2_proxy_id":      "pool-1",
		"base_url":           "http://cpa:8317",
	}

	got := piCredentialsFromCPA(source)
	require.Equal(t, "access", got["access_token"])
	require.Equal(t, "refresh", got["refresh_token"])
	require.Equal(t, "user@example.com", got["email"])
	require.Equal(t, "acct-1", got["chatgpt_account_id"])
	for _, key := range []string{"proxy_url", "retry", "weight", "sub2_proxy_id", "base_url"} {
		require.NotContains(t, got, key)
	}
}
