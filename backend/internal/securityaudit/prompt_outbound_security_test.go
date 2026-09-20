package securityaudit

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNormalizeBaseURLRestrictsCompatibleDestinations(t *testing.T) {
	allowed := []string{"http://cpa:8317", "http://cpa:8317/v1", "https://opencode.ai/zen/go"}
	for _, raw := range allowed {
		_, err := NormalizeBaseURL(raw)
		require.NoError(t, err, raw)
	}
	blocked := []string{
		"http://127.0.0.1:8080", "https://guard.example.com", "http://169.254.169.254",
		"ftp://guard.example.com", "https://user:pass@guard.example.com",
		"https://guard.example.com?q=secret", "https://guard.example.com/#fragment",
	}
	for _, raw := range blocked {
		_, err := NormalizeBaseURL(raw)
		require.Error(t, err, raw)
	}
	url, err := ChatCompletionsURL("http://cpa:8317/v1")
	require.NoError(t, err)
	require.Equal(t, "http://cpa:8317/v1/chat/completions", url)
}

func TestHTTPClientUsesDirectStandardDialer(t *testing.T) {
	client, err := NewSecureHTTPClient(ActiveEndpoint{BaseURL: "http://cpa:8317", TimeoutMS: 1000})
	require.NoError(t, err)
	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	require.Nil(t, transport.Proxy)
	require.NotNil(t, transport.DialContext)
}

func TestOpenAICompatibleScannerRequestContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/chat/completions", r.URL.Path)
		require.Equal(t, "Bearer token", r.Header.Get("Authorization"))
		var payload map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		require.Equal(t, DefaultGuardModel, payload["model"])
		require.Equal(t, float64(0), payload["temperature"])
		require.Equal(t, float64(64), payload["max_tokens"])
		require.Equal(t, float64(42), payload["seed"])
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"Safety: Safe\nCategories: None"}}]}`))
	}))
	defer server.Close()
	scanner := &mappedCPATestScanner{}
	result, err := scanner.Scan(context.Background(), ActiveEndpoint{ID: "one", BaseURL: server.URL, Model: DefaultGuardModel, Token: "token", TimeoutMS: 1000}, "hello", AllScannerIDs)
	require.NoError(t, err)
	require.Equal(t, EventPass, result.Decision)
}

func TestOpenAICompatibleGenericClassifierContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		require.Equal(t, float64(genericAuditMaxOutputTokens), payload["max_tokens"])
		require.Equal(t, "none", payload["reasoning_effort"])
		require.NotContains(t, payload, "seed")
		messages, ok := payload["messages"].([]any)
		require.True(t, ok)
		system, ok := messages[0].(map[string]any)
		require.True(t, ok)
		require.Equal(t, "system", system["role"])
		require.Contains(t, system["content"], "exactly three non-empty lines")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"Safety: Controversial\nIntent-Categories: politically_sensitive_topics\nContent-Categories: None"}}]}`))
	}))
	defer server.Close()

	result, err := (&mappedCPATestScanner{}).Scan(context.Background(), ActiveEndpoint{
		ID: "generic", Adapter: EndpointAdapterGenericLLM, BaseURL: server.URL,
		Model: "deepseek-v4-flash", TimeoutMS: 1000,
	}, "discuss politics", AllScannerIDs)
	require.NoError(t, err)
	require.Equal(t, ActionWarn, result.Action)
	require.Equal(t, "generic-llm-classifier", result.ScannerBackend)
}

func TestOpenAICompatibleScannerRejectsRedirectAndOversize(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"Safety: Safe\nCategories: None"}}]}`))
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer redirect.Close()
	result, err := (&mappedCPATestScanner{}).Scan(context.Background(), ActiveEndpoint{ID: "redirect", BaseURL: redirect.URL, Model: DefaultGuardModel, TimeoutMS: 1000}, "hello", AllScannerIDs)
	require.Error(t, err)
	require.Nil(t, result)
	oversize := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", int(maxGuardResponseBytes)+1)))
	}))
	defer oversize.Close()
	_, err = (&mappedCPATestScanner{}).Scan(context.Background(), ActiveEndpoint{ID: "large", BaseURL: oversize.URL, Model: DefaultGuardModel, TimeoutMS: 1000}, "hello", AllScannerIDs)
	require.Error(t, err)
}

func TestOpenAICompatibleScannerClassifiesHTTPConnectionAndTimeoutFailures(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		retryable bool
	}{
		{name: "authentication", status: http.StatusUnauthorized, retryable: false},
		{name: "forbidden", status: http.StatusForbidden, retryable: false},
		{name: "rate limited", status: http.StatusTooManyRequests, retryable: true},
		{name: "server failure", status: http.StatusBadGateway, retryable: true},
		{name: "other client error", status: http.StatusBadRequest, retryable: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
			}))
			defer server.Close()
			_, err := (&mappedCPATestScanner{}).Scan(context.Background(), ActiveEndpoint{ID: "status", BaseURL: server.URL, Model: DefaultGuardModel, TimeoutMS: 1000}, "hello", AllScannerIDs)
			var guardErr *GuardError
			require.ErrorAs(t, err, &guardErr)
			require.Equal(t, ErrorCodeUnavailable, guardErr.Code)
			require.Equal(t, tt.status, guardErr.HTTPStatus)
			require.Equal(t, tt.retryable, guardErr.Retryable)
			require.NotContains(t, err.Error(), server.URL)
		})
	}

	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedURL := closed.URL
	closed.Close()
	_, err := (&mappedCPATestScanner{}).Scan(context.Background(), ActiveEndpoint{ID: "closed", BaseURL: closedURL, Model: DefaultGuardModel, TimeoutMS: 100}, "hello", AllScannerIDs)
	var connectionErr *GuardError
	require.ErrorAs(t, err, &connectionErr)
	require.True(t, connectionErr.Retryable)

	timeout := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer timeout.Close()
	_, err = (&mappedCPATestScanner{}).Scan(context.Background(), ActiveEndpoint{ID: "timeout", BaseURL: timeout.URL, Model: DefaultGuardModel, TimeoutMS: 20}, "hello", AllScannerIDs)
	var timeoutErr *GuardError
	require.ErrorAs(t, err, &timeoutErr)
	require.True(t, timeoutErr.Retryable)
	require.True(t, timeoutErr.Timeout)
}

func TestPromptAuditProbeCallsAndValidatesClassifier(t *testing.T) {
	t.Run("model call returns valid classifier output", func(t *testing.T) {
		var chatCalls atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, "Bearer temporary-token", r.Header.Get("Authorization"))
			require.Equal(t, "/v1/chat/completions", r.URL.Path)
			chatCalls.Add(1)
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"Safety: Safe\nCategories: None"}}]}`))
		}))
		defer server.Close()
		result := newProbeTestService(server.URL).Probe(context.Background(), ProbeRequest{Endpoint: probeEndpoint(server.URL, "temporary-token")})
		require.True(t, result.OK)
		require.True(t, result.TokenApplied)
		require.Equal(t, http.StatusOK, result.HTTPStatus)
		require.Equal(t, int64(1), chatCalls.Load())
	})

	t.Run("invalid classifier output fails the probe", func(t *testing.T) {
		var chatCalls atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			chatCalls.Add(1)
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"looks fine"}}]}`))
		}))
		defer server.Close()
		result := newProbeTestService(server.URL).Probe(context.Background(), ProbeRequest{Endpoint: probeEndpoint(server.URL, "temporary-token")})
		require.False(t, result.OK)
		require.Equal(t, ErrorCodeInvalidResponse, result.ErrorCode)
		require.Equal(t, int64(1), chatCalls.Load())
	})

	t.Run("authentication failure is stable", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer server.Close()
		result := newProbeTestService(server.URL).Probe(context.Background(), ProbeRequest{Endpoint: probeEndpoint(server.URL, "temporary-token")})
		require.False(t, result.OK)
		require.Equal(t, ErrorCodeUnavailable, result.ErrorCode)
		require.Equal(t, http.StatusUnauthorized, result.HTTPStatus)
		require.False(t, result.Retryable)
	})

	t.Run("oversized classifier response is rejected", func(t *testing.T) {
		var chatCalls atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			chatCalls.Add(1)
			_, _ = w.Write([]byte(strings.Repeat("x", int(maxGuardResponseBytes)+1)))
		}))
		defer server.Close()
		result := newProbeTestService(server.URL).Probe(context.Background(), ProbeRequest{Endpoint: probeEndpoint(server.URL, "temporary-token")})
		require.False(t, result.OK)
		require.Equal(t, ErrorCodeInvalidResponse, result.ErrorCode)
		require.Equal(t, int64(1), chatCalls.Load())
	})
}

func TestResolveProbeEndpointReusesTokenOnlyForMatchingBaseURL(t *testing.T) {
	manager := &ConfigManager{}
	manager.snapshot.Store(&activeConfigSnapshot{active: ActiveConfig{Endpoints: []ActiveEndpoint{{
		ID: "guard-1", BaseURL: "http://cpa:8317", Token: "STORED_GUARD_TOKEN", TimeoutMS: 1000, InputLimit: 1024, Enabled: true,
	}}}})
	service := &PromptService{config: manager}

	matched, applied, err := service.resolveProbeEndpoint(UpdateEndpoint{
		ID: "guard-1", BaseURL: "http://cpa:8317/v1", TimeoutMS: 1000, InputLimit: 1024,
	})
	require.NoError(t, err)
	require.True(t, applied)
	require.Equal(t, "STORED_GUARD_TOKEN", matched.Token)

	mismatched, applied, err := service.resolveProbeEndpoint(UpdateEndpoint{
		ID: "guard-1", BaseURL: "https://attacker.example.com", TimeoutMS: 1000, InputLimit: 1024,
	})
	require.Error(t, err)
	require.False(t, applied)
	require.Empty(t, mismatched.Token)
}

func newProbeTestService(serverURL string) *PromptService {
	return &PromptService{
		config: &ConfigManager{}, scanner: &mappedCPATestScanner{target: serverURL}, clock: realClock{},
		probes: map[string]ProbeResult{},
	}
}

func probeEndpoint(baseURL, token string) UpdateEndpoint {
	return UpdateEndpoint{
		ID: "probe-one", Name: "Probe One", Protocol: "openai_compatible", BaseURL: "http://cpa:8317",
		Model: DefaultGuardModel, Token: token, TimeoutMS: 1000, InputLimit: 1024, Enabled: true,
	}
}

// Keep the production CPA authority in request URLs while mapping its socket
// to a test-owned loopback server. No production destination policy is relaxed.
type mappedCPATestScanner struct{ target string }

func (s *mappedCPATestScanner) Scan(ctx context.Context, endpoint ActiveEndpoint, chunk string, scanners []string) (*NormalizedResult, error) {
	target := s.target
	if target == "" {
		target = endpoint.BaseURL
	}
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(u.Host, "127.0.0.1:") {
		return nil, fmt.Errorf("fixture must use loopback")
	}
	endpoint.BaseURL = "http://cpa:8317"
	client, err := NewSecureHTTPClient(endpoint)
	if err != nil {
		return nil, err
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("unexpected fixture transport")
	}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, u.Host)
	}
	defer transport.CloseIdleConnections()
	scanner := NewOpenAICompatibleScanner()
	scanner.clients.Store(fmt.Sprintf("%s|%s|%d", endpoint.ID, endpoint.BaseURL, endpoint.TimeoutMS), client)
	return scanner.Scan(ctx, endpoint, chunk, scanners)
}
