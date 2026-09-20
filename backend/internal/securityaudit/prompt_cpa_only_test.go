package securityaudit

import (
	"context"
	"github.com/Wei-Shaw/sub2api/internal/pkg/cpapolicy"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

func TestAuditRoutesRejectUnsupportedAndAllowScopedOpenCode(t *testing.T) {
	scanner := &RoutingPromptScanner{}
	for _, ep := range []ActiveEndpoint{
		{Protocol: EndpointProtocolOpenAIInternal, BaseURL: cpapolicy.BaseURL},
		{Protocol: EndpointProtocolAntigravityInternal},
		{Protocol: EndpointProtocolOpenAICompatible, BaseURL: "https://example.com"},
		{Protocol: EndpointProtocolOpenAICompatible, BaseURL: cpapolicy.BaseURL, AccountID: 27},
	} {
		_, err := scanner.Scan(context.Background(), ep, "safe probe", nil)
		require.Error(t, err)
	}
	_, err := NewSecureHTTPClient(ActiveEndpoint{BaseURL: "https://example.com", TimeoutMS: 1000})
	require.Error(t, err)
	client, err := NewSecureHTTPClient(ActiveEndpoint{BaseURL: cpapolicy.BaseURL, TimeoutMS: 1000})
	require.NoError(t, err)
	require.Equal(t, http.ErrUseLastResponse, client.CheckRedirect(nil, nil))
	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	require.Nil(t, transport.Proxy)
}

func TestOpenCodeAuditEndpointIsScoped(t *testing.T) {
	client, err := NewSecureHTTPClient(ActiveEndpoint{BaseURL: openCodeAuditBaseURL, TimeoutMS: 1000})
	require.NoError(t, err)
	require.NotNil(t, client)
	require.Equal(t, openCodeAuditBaseURL+"/v1/chat/completions", func() string { u, _ := ChatCompletionsURL(openCodeAuditBaseURL); return u }())
	require.NoError(t, validateStorageConfig(storageConfig{Enabled: true, BlockingEnabled: false, BackgroundAuditMode: "incremental_full", Strategy: "priority", WorkerCount: 1, PromptChunkConcurrency: 1, QueueCapacity: 1, Scanners: []string{"jailbreak"}, AllGroups: true, Endpoints: []StorageEndpoint{{ID: "deepseek-fallback", Name: "DeepSeek", Protocol: EndpointProtocolOpenAICompatible, Adapter: EndpointAdapterGenericLLM, BaseURL: openCodeAuditBaseURL, Model: "deepseek-v4-flash", TimeoutMS: 1000, InputLimit: 128, Enabled: true}}}))
}

func TestOpenCodeAuditEndpointAllowsV41Flash(t *testing.T) {
	storage := storageConfig{Enabled: true, BackgroundAuditMode: "incremental_full", Strategy: "priority", WorkerCount: 1, PromptChunkConcurrency: 1, QueueCapacity: 1, Scanners: []string{"jailbreak"}, AllGroups: true, Endpoints: []StorageEndpoint{{ID: "deepseek-fallback", Name: "DeepSeek", Protocol: EndpointProtocolOpenAICompatible, Adapter: EndpointAdapterGenericLLM, BaseURL: openCodeAuditBaseURL, Model: "deepseek-v4.1-flash", TimeoutMS: 1000, InputLimit: 128, Enabled: true}}}
	require.NoError(t, validateStorageConfig(storage))
}

func TestCPAOnlyAuditRejectsDisabledLegacyEndpoints(t *testing.T) {
	cfg := DefaultStorageConfig()
	cfg.Endpoints = []StorageEndpoint{{ID: "external", Name: "external", Protocol: EndpointProtocolOpenAICompatible, BaseURL: "https://example.com", Enabled: false}}
	require.Error(t, validateStorageConfig(cfg))
	cfg.Endpoints[0].Protocol = EndpointProtocolOpenAIInternal
	cfg.Endpoints[0].BaseURL = cpapolicy.BaseURL
	require.Error(t, validateStorageConfig(cfg))
}
