//go:build unit

package service

import (
	"context"
	"net/http"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

func TestCPA429ModelCooldownKeepsSharedBridgeAvailable(t *testing.T) {
	for _, field := range []string{"code", "type"} {
		t.Run(field, func(t *testing.T) {
			repo := &oauth429RateLimitRepo{}
			limits := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
			gateway := &OpenAIGatewayService{rateLimitService: limits}
			limits.SetAccountRuntimeBlocker(gateway)
			account := &Account{ID: 30, Platform: PlatformOpenAI, Type: AccountTypeAPIKey,
				Credentials: map[string]any{"base_url": "http://cpa:8317"}, Status: StatusActive, Schedulable: true}
			body := []byte(`{"error":{"` + field + `":"model_cooldown","message":"All credentials for model gpt-6-astra are cooling down"}}`)
			headers := http.Header{"Retry-After": []string{"300"}}
			require.False(t, gateway.handleOpenAIAccountUpstreamError(context.Background(), account, http.StatusTooManyRequests, headers, body, "gpt-6-astra"))
			require.Zero(t, repo.setRateLimitedCalls)
			require.False(t, gateway.isOpenAIAccountRuntimeBlocked(account))
			require.True(t, account.IsSchedulable())
			// The account-test/direct rate-limit path must preserve the same boundary.
			limits.HandleUpstreamError(context.Background(), account, http.StatusTooManyRequests, headers, body)
			require.Zero(t, repo.setRateLimitedCalls)
		})
	}
}

func TestCPA429OrdinaryQuotaStillBlocksBridge(t *testing.T) {
	repo := &oauth429RateLimitRepo{}
	limits := NewRateLimitService(repo, nil, &config.Config{}, nil, nil)
	gateway := &OpenAIGatewayService{rateLimitService: limits}
	limits.SetAccountRuntimeBlocker(gateway)
	account := &Account{ID: 30, Platform: PlatformOpenAI, Type: AccountTypeAPIKey,
		Credentials: map[string]any{"base_url": "http://cpa:8317"}}
	gateway.handleOpenAIAccountUpstreamError(context.Background(), account, http.StatusTooManyRequests, http.Header{}, []byte(`{"error":{"code":"rate_limit_exceeded"}}`), "gpt-6-astra")
	require.Equal(t, 1, repo.setRateLimitedCalls)
	require.True(t, gateway.isOpenAIAccountRuntimeBlocked(account))
	account.Credentials["base_url"] = "https://example.invalid"
	require.False(t, isCPAModelCooldown(account, []byte(`{"error":{"code":"model_cooldown"}}`)))
	require.False(t, isCPAModelCooldown(nil, []byte(`{"error":{"code":"model_cooldown"}}`)))
}
