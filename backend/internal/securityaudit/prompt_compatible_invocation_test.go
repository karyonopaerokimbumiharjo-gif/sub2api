package securityaudit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/cpapolicy"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

type auditInvocationRecorderStub struct{ values []PromptAuditInvocation }

func (r *auditInvocationRecorderStub) RecordInvocation(ctx context.Context, v PromptAuditInvocation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.values = append(r.values, v)
	return nil
}

type auditCostStub struct {
	tokens service.UsageTokens
	fail   bool
}

func (s *auditCostStub) CalculateCost(_ string, v service.UsageTokens, rate float64) (*service.CostBreakdown, error) {
	s.tokens = v
	if s.fail {
		return nil, errors.New("unknown price")
	}
	return &service.CostBreakdown{TotalCost: (float64(v.InputTokens)*2 + float64(v.CacheReadTokens)*0.2 + float64(v.OutputTokens)*10) / 1e6 * rate}, nil
}

func TestCompatibleAuditUsageStrictParsing(t *testing.T) {
	for _, body := range []string{`{}`, `{"usage":{}}`, `{"usage":{"prompt_tokens":10}}`,
		`{"usage":{"prompt_tokens":-1,"completion_tokens":2}}`,
		`{"usage":{"prompt_tokens":10,"completion_tokens":2,"prompt_cache_hit_tokens":11}}`} {
		require.Nil(t, parseCompatibleAuditUsage([]byte(body)), body)
	}
	usage := parseCompatibleAuditUsage([]byte(`{"model":"deepseek-v4-flash","usage":{"prompt_tokens":100,"completion_tokens":3,"prompt_cache_hit_tokens":90}}`))
	require.NotNil(t, usage)
	require.Equal(t, 90, usage.CacheReadTokens)
	require.Equal(t, 100, usage.InputTokens)
}

func TestCompatibleAuditRecordsUsageIncludingInvalidAnswers(t *testing.T) {
	for _, tc := range []struct {
		name, content, status string
		code                  int
	}{
		{"success", "Safety: Safe\nIntent-Categories: None\nContent-Categories: None", "success", 200},
		{"malformed", "thinking instead of classifying", "invalid", 200},
		{"rate limit", "", "failed", 429},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.code)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"model": "gpt-test", "choices": []any{map[string]any{"message": map[string]any{"content": tc.content}}},
					"usage": map[string]any{"prompt_tokens": 1000, "completion_tokens": 20, "prompt_tokens_details": map[string]int{"cached_tokens": 800}},
				})
			}))
			defer server.Close()
			recorder, billing := &auditInvocationRecorderStub{}, &auditCostStub{}
			scanner := &RoutingPromptScanner{openAI: NewOpenAICompatibleScanner(), accounts: &cpaBudgetSelector{account: &service.Account{ID: 30, Concurrency: 7}}, concurrency: &cpaBudgetSlots{available: true}, invocations: recorder, billing: billing}
			endpoint := ActiveEndpoint{ID: "cpa-audit", Name: "CPA audit", Protocol: EndpointProtocolOpenAICompatible, Adapter: EndpointAdapterGenericLLM, BaseURL: cpapolicy.BaseURL, Model: "gpt-test", TimeoutMS: 1000}
			// Keep the policy-visible destination fixed while serving the CPA
			// fixture through a test-only transport.
			client := server.Client()
			client.Transport = cpaAuditFixtureTransport{target: server.URL, next: client.Transport}
			scanner.openAI.clients.Store(fmt.Sprintf("%s|%s|%d", endpoint.ID, endpoint.BaseURL, endpoint.TimeoutMS), client)
			ctx := withPromptInvocationContext(context.Background(), "audit-usage-test", 132)
			_, err := scanner.Scan(ctx, endpoint, "hello", AllScannerIDs)
			require.Equal(t, tc.status == "success", err == nil)
			require.Len(t, recorder.values, 1)
			value := recorder.values[0]
			require.Equal(t, tc.status, value.Status)
			require.Zero(t, value.AccountID)
			require.Empty(t, value.AccountEmailSnapshot)
			require.Equal(t, "audit-usage-test", value.RequestID)
			if tc.code == 200 {
				require.Equal(t, 1000, value.InputTokens)
				require.Equal(t, 200, billing.tokens.InputTokens)
				require.Equal(t, 800, value.CacheReadTokens)
				require.True(t, value.PricingKnown)
				require.InDelta(t, 0.00076, value.EstimatedCostUSD, 1e-10)
			} else {
				require.False(t, value.PricingKnown)
			}
		})
	}
}

type cpaAuditFixtureTransport struct {
	target string
	next   http.RoundTripper
}

func (t cpaAuditFixtureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	fixture, _ := http.NewRequestWithContext(req.Context(), req.Method, t.target+req.URL.Path, req.Body)
	clone.URL, clone.Host = fixture.URL, fixture.URL.Host
	return t.next.RoundTrip(clone)
}

func TestCompatibleAuditUsageDoesNotInventPricesOrCountProbes(t *testing.T) {
	recorder := &auditInvocationRecorderStub{}
	scanner := &RoutingPromptScanner{invocations: recorder, billing: &auditCostStub{fail: true}}
	endpoint := ActiveEndpoint{ID: "audit", Model: "unknown"}
	scanner.recordCompatibleInvocation(context.Background(), endpoint, nil, nil, time.Millisecond)
	require.Empty(t, recorder.values)
	ctx, cancel := context.WithCancel(withPromptInvocationContext(context.Background(), "canceled", 132))
	cancel()
	scanner.recordCompatibleInvocation(ctx, endpoint, &compatibleAuditUsage{InputTokens: 10}, context.Canceled, time.Millisecond)
	require.Len(t, recorder.values, 1)
	require.False(t, recorder.values[0].PricingKnown)
	require.Equal(t, "failed", recorder.values[0].Status)
}

func TestAuditPromptSeparatesRobustnessBenchmarksFromAbuse(t *testing.T) {
	prompt := GenericAuditSystemPrompt()
	for _, boundary := range []string{"controlled image-classification", "CIFAR-10 or SVHN", "not evidence of unauthorized intrusion", "third party's deployed model", "active jailbreak instruction", "[MODE: UNRESTRICTED]"} {
		require.Contains(t, prompt, boundary)
	}
}
