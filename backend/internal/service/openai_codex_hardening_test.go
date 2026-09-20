package service

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

func TestCodexStatePolicyRejectsExpiredFutureAndWrongPlan(t *testing.T) {
	now := time.Now()
	account := ticketTestAccount(1)
	for _, tc := range []struct {
		name, plan string
		size       int
		age        time.Duration
		accepted   bool
	}{
		{"personal", "plus", 292, -time.Minute, true},
		{"team", "team", 332, -time.Minute, true},
		{"team short", "team", 292, -time.Minute, false},
		{"personal 312 rejected", "plus", 312, -time.Minute, false},
		{"team 356 rejected", "team", 356, -time.Minute, false},
		{"personal long", "plus", 332, -time.Minute, false},
		{"expired", "plus", 292, -2 * time.Hour, false},
		{"future", "plus", 292, time.Minute, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account.Credentials["plan_type"] = tc.plan
			raw, err := base64.URLEncoding.DecodeString(fakeCodexTicketState(tc.size))
			require.NoError(t, err)
			binary.BigEndian.PutUint64(raw[1:9], uint64(now.Add(tc.age).Unix()))
			shape, err := parseOpenAICodexStateShape(base64.URLEncoding.EncodeToString(raw))
			require.NoError(t, err)
			require.Equal(t, tc.accepted, openAICodexStateAccepted(shape, openAICodexPolicyForAccount(account, config.OpenAICodexTicketConfig{}), now))
		})
	}
}

func TestCodexHarvestTeamStateAndCredentialRotation(t *testing.T) {
	upstream := &codexTicketFuncUpstream{do: func(*http.Request) (*http.Response, error) {
		response := codexTicketResponse()
		response.Header.Set(openAICodexTurnStateHeader, fakeCodexTicketState(332))
		return response, nil
	}}
	svc := ticketTestService(t, config.OpenAICodexTicketConfig{Enabled: true, FailClosed: true, HarvestProxyURLs: []string{"http://pool.example:8080"}}, upstream)
	account := ticketTestAccount(1)
	account.Credentials["plan_type"] = "team"
	svc.probeOnceOpenAICodexTicket(context.Background(), account, "gpt-6-astra")
	ticket := svc.lookupOpenAICodexTicket(account, "gpt-6-astra")
	require.NotNil(t, ticket)
	require.Equal(t, 12, ticket.Blocks)
	require.Equal(t, "team", ticket.PlanClass)
	require.NotEmpty(t, ticket.RouteFingerprint)
	require.False(t, svc.openAICodexTicketBlocksAccount(account, "gpt-6-astra"))
	account.Credentials["access_token"] = "rotated"
	require.True(t, svc.openAICodexTicketBlocksAccount(account, "gpt-6-astra"))
}

func TestCodexHarvestConcurrencyBoundAndCancellation(t *testing.T) {
	var active, peak, calls atomic.Int64
	upstream := &codexTicketFuncUpstream{do: func(req *http.Request) (*http.Response, error) {
		n := active.Add(1)
		defer active.Add(-1)
		calls.Add(1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		<-req.Context().Done()
		return nil, req.Context().Err()
	}}
	svc := ticketTestService(t, config.OpenAICodexTicketConfig{Enabled: true, HarvestProxyURL: "http://pool.example:8080", HarvestMaxConcurrency: 3, Models: []string{"gpt-6-astra"}}, upstream)
	accounts := make([]Account, 100)
	for i := range accounts {
		accounts[i] = *ticketTestAccount(int64(i + 1))
		accounts[i].Status = StatusActive
	}
	svc.accountRepo = &codexTicketLifecycleRepo{list: func(context.Context) ([]Account, error) { return accounts, nil }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); svc.refreshOpenAICodexTickets(ctx) }()
	require.Eventually(t, func() bool { return calls.Load() >= 3 }, time.Second, time.Millisecond)
	require.Equal(t, int64(3), peak.Load())
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("workers did not stop")
	}
	require.Equal(t, int64(0), active.Load())
}
