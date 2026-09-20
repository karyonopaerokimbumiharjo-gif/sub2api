package securityaudit

import (
	"context"
	"fmt"
	"github.com/Wei-Shaw/sub2api/internal/pkg/cpapolicy"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

type cpaBudgetSelector struct{ account *service.Account }

func (s *cpaBudgetSelector) FindCPABridgeForAudit(context.Context, string) (*service.Account, error) {
	return s.account, nil
}

type cpaBudgetSlots struct {
	available       bool
	id              int64
	limit, releases int
}

func (s *cpaBudgetSlots) AcquireAccountSlot(_ context.Context, id int64, limit int) (*service.AcquireResult, error) {
	s.id = id
	s.limit = limit
	return &service.AcquireResult{Acquired: s.available, ReleaseFunc: func() { s.releases++ }}, nil
}
func TestCPAAuditSharesBridgeLimitBeforeSendingAndReleases(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"finish_reason":"stop","message":{"content":"Safety: Safe\nIntent-Categories: None\nContent-Categories: None"}}]}`))
	}))
	defer upstream.Close()
	t.Setenv("OPENAI_QUOTA_BRIDGE_MANAGEMENT_URL", cpapolicy.BaseURL)
	slots := &cpaBudgetSlots{}
	selector := &cpaBudgetSelector{account: &service.Account{ID: 30, Concurrency: 7}}
	scanner := &RoutingPromptScanner{openAI: NewOpenAICompatibleScanner(), accounts: selector, concurrency: slots}
	endpoint := ActiveEndpoint{ID: "cpa-test", Protocol: EndpointProtocolOpenAICompatible, Adapter: EndpointAdapterGenericLLM, BaseURL: cpapolicy.BaseURL, Model: "test", TimeoutMS: 60}
	client := upstream.Client()
	client.Transport = cpaAuditFixtureTransport{target: upstream.URL, next: client.Transport}
	scanner.openAI.clients.Store(fmt.Sprintf("%s|%s|%d", endpoint.ID, endpoint.BaseURL, endpoint.TimeoutMS), client)
	_, err := scanner.Scan(context.Background(), endpoint, "hello", AllScannerIDs)
	require.Error(t, err)
	require.Zero(t, calls.Load())
	require.Equal(t, int64(30), slots.id)
	require.Equal(t, 7, slots.limit)
	require.Zero(t, slots.releases)
	slots.available = true
	endpoint.TimeoutMS = 1000
	scanner.openAI.clients.Store(fmt.Sprintf("%s|%s|%d", endpoint.ID, endpoint.BaseURL, endpoint.TimeoutMS), client)
	result, err := scanner.Scan(context.Background(), endpoint, "hello", AllScannerIDs)
	require.NoError(t, err)
	require.Equal(t, ActionAllow, result.Action)
	require.Equal(t, int32(1), calls.Load())
	require.Equal(t, 1, slots.releases)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = scanner.Scan(cancelled, endpoint, "hello", AllScannerIDs)
	require.Error(t, err)
	require.Equal(t, 2, slots.releases)
}
