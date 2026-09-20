package service

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	gocache "github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/require"
)

func TestGetAvailableModels_OpenAIAPIKeyLiveCatalogRefreshAndWhitelist(t *testing.T) {
	groupID := int64(1)
	cfg := upstreamModelSyncTestConfig()
	cfg.Security.URLAllowlist.AllowInsecureHTTP = true
	upstream := &httpUpstreamRecorder{responses: []*http.Response{
		{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"data":[{"id":"gpt-6-astra"}]}`))},
		{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"data":[{"id":"gpt-6-astra"},{"id":"future-upstream-model"}]}`))},
	}}
	repo := &modelsListAccountRepoStub{byGroup: map[int64][]Account{groupID: {
		{ID: 30, Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Credentials: map[string]any{
			"api_key": "test-key", "base_url": "http://cpa:8317/v1",
		}},
		{ID: 31, Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Credentials: map[string]any{
			"api_key": "must-not-query", "base_url": "http://cpa:8317/v1", "model_mapping": map[string]any{"public-alias": "private-upstream-model"},
		}},
	}}}
	svc := &GatewayService{accountRepo: repo, httpUpstream: upstream, cfg: cfg,
		modelsListCache: gocache.New(time.Minute, time.Minute), modelsListCacheTTL: time.Minute}
	first := svc.GetAvailableModels(context.Background(), &groupID, PlatformOpenAI)
	require.Equal(t, []string{"gpt-6-astra", "public-alias"}, first)
	require.NotContains(t, first, "gpt-5.4", "an unmapped CPA account must not restore static models absent from its live catalog")
	require.Len(t, upstream.requests, 1)
	require.Equal(t, "http://cpa:8317/v1/models", upstream.lastReq.URL.String())
	require.Equal(t, "Bearer test-key", upstream.lastReq.Header.Get("Authorization"))
	require.Equal(t, first, svc.GetAvailableModels(context.Background(), &groupID, PlatformOpenAI))
	require.Len(t, upstream.requests, 1, "cached list should not repeatedly query upstream")
	svc.modelsListCache.Flush()
	require.Equal(t, []string{"future-upstream-model", "gpt-6-astra", "public-alias"}, svc.GetAvailableModels(context.Background(), &groupID, PlatformOpenAI))
	require.Len(t, upstream.requests, 2)
}

func TestCPAConfiguredCodexCatalogDoesNotRestoreStaticDefaults(t *testing.T) {
	accounts := []Account{
		{ID: 30, Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Credentials: map[string]any{
			"base_url": "http://cpa:8317/v1",
		}},
		{ID: 31, Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Credentials: map[string]any{
			"base_url": "http://cpa:8317/v1", "model_mapping": map[string]any{"public-alias": "private-upstream-model"},
		}},
	}

	models := openAIConfiguredCodexModelIDsForGroup(accounts, &Group{Platform: PlatformOpenAI})
	require.Equal(t, []string{"public-alias"}, models, "CPA configured manifests must not expand into a static default catalog")
}

func TestGetAvailableModels_OpenAIAPIKeyLiveFailureKeepsDefaultFallback(t *testing.T) {
	groupID := int64(1)
	cfg := upstreamModelSyncTestConfig()
	cfg.Security.URLAllowlist.AllowInsecureHTTP = true
	upstream := &httpUpstreamRecorder{resp: &http.Response{StatusCode: http.StatusServiceUnavailable,
		Body: io.NopCloser(strings.NewReader(`{"error":"unavailable"}`))}}
	repo := &modelsListAccountRepoStub{byGroup: map[int64][]Account{groupID: {
		{ID: 30, Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Credentials: map[string]any{
			"api_key": "test-key", "base_url": "http://cpa:8317/v1",
		}},
	}}}
	svc := &GatewayService{accountRepo: repo, httpUpstream: upstream, cfg: cfg}
	require.Nil(t, svc.GetAvailableModels(context.Background(), &groupID, PlatformOpenAI))
	require.Len(t, upstream.requests, 1)
}

func TestGetAvailableModels_NonCPAAPIKeyKeepsDefaultFallback(t *testing.T) {
	groupID := int64(1)
	upstream := &httpUpstreamRecorder{}
	repo := &modelsListAccountRepoStub{byGroup: map[int64][]Account{groupID: {
		{ID: 1, Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Credentials: map[string]any{
			"api_key": "test-key", "base_url": "https://provider.example/v1",
		}},
	}}}
	svc := &GatewayService{accountRepo: repo, httpUpstream: upstream, cfg: upstreamModelSyncTestConfig()}
	require.Nil(t, svc.GetAvailableModels(context.Background(), &groupID, PlatformOpenAI))
	require.Empty(t, upstream.requests)
}
