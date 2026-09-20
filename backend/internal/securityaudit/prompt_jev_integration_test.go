package securityaudit

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRequiredJevIgnoresBypassAndRuntimeCleaning(t *testing.T) {
	req := Request{RequireJev: true, PromptAuditBypass: true, Protocol: "openai_responses", Body: []byte(`{"input":[{"role":"user","content":"<environment_context>UNTRUSTED_TEST_TEXT</environment_context>"}]}`)}
	svc := &PromptService{}
	require.False(t, svc.ShouldBypass(req))
	snapshot, err := buildScopedPromptSnapshot(context.Background(), req, ActiveConfig{}, BlockingAuditModeFastLatest, nil)
	require.NoError(t, err)
	require.Contains(t, snapshot.ScanText, "UNTRUSTED_TEST_TEXT")
	require.Empty(t, snapshot.Redacted().FullPrompt)
	require.Empty(t, snapshot.Redacted().AuditedPrompt)
	require.Empty(t, snapshot.Redacted().ScanText)
}
func TestJevAndCPAOriginsStaySeparated(t *testing.T) {
	_, err := normalizeAuditEndpointURL(JevProtocol, "http://cpa:8317")
	require.Error(t, err)
	_, err = normalizeAuditEndpointURL(EndpointProtocolOpenAICompatible, JevBaseURL)
	require.Error(t, err)
	url, err := normalizeAuditEndpointURL(JevProtocol, JevBaseURL+"/v1")
	require.NoError(t, err)
	require.Equal(t, JevBaseURL, url)
}

func TestJevSupportsEveryConfiguredScanner(t *testing.T) {
	_, ids, err := buildJevPayload(jevTestEndpoint(), "synthetic benign input", AllScannerIDs)
	require.NoError(t, err)
	require.Len(t, ids, len(AllScannerIDs))
}
