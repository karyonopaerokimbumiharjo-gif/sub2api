package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQueryUsageCodexCredits(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"decimal balance", `{"credits":{"has_credits":true,"unlimited":false,"balance":"12345678901234567890.0123"}}`, `{"has_credits":true,"unlimited":false,"balance":"12345678901234567890.0123"}`},
		{"numeric balance exact", `{"credits":{"has_credits":true,"balance":12345678901234567890.0123}}`, `{"has_credits":true,"unlimited":false,"balance":"12345678901234567890.0123"}`},
		{"string remaining", `{"credits":{"remaining":"35.10","balance":"100"}}`, `{"has_credits":false,"unlimited":false,"balance":"100","remaining":"35.10"}`},
		{"numeric remaining exact", `{"credits":{"remaining":9007199254740993.01}}`, `{"has_credits":false,"unlimited":false,"balance":null,"remaining":"9007199254740993.01"}`},
		{"zero remaining", `{"credits":{"has_credits":true,"remaining":0,"balance":100}}`, `{"has_credits":true,"unlimited":false,"balance":"100","remaining":"0"}`},
		{"null remaining", `{"credits":{"remaining":null,"balance":12.5}}`, `{"has_credits":false,"unlimited":false,"balance":"12.5"}`},
		{"zero", `{"credits":{"has_credits":false,"unlimited":false,"balance":"0"}}`, `{"has_credits":false,"unlimited":false,"balance":"0"}`},
		{"unlimited", `{"credits":{"has_credits":false,"unlimited":true,"balance":null}}`, `{"has_credits":false,"unlimited":true,"balance":null}`},
		{"hidden balance", `{"credits":{"has_credits":true,"unlimited":false}}`, `{"has_credits":true,"unlimited":false,"balance":null}`},
		{"absent", `{}`, `null`},
		{"null", `{"credits":null}`, `null`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := &Account{ID: 100, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Status: StatusActive,
				Credentials: map[string]any{"chatgpt_account_id": "test-workspace"}}
			repo := &stubQuotaAccountRepo{accounts: map[int64]*Account{100: account}}
			tokens := &stubQuotaTokenCache{tokens: map[string]string{OpenAITokenCacheKey(account): "test-token"}}
			var paths []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.URL.Path)
				require.Equal(t, http.MethodGet, r.Method)
				require.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
				require.Equal(t, "test-workspace", r.Header.Get("ChatGPT-Account-ID"))
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/backend-api/wham/usage" {
					_, _ = w.Write([]byte(tc.body))
					return
				}
				// Reset-card details may be unavailable without losing points.
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
			}))
			defer srv.Close()
			svc := NewOpenAIQuotaService(repo, nil, NewOpenAITokenProvider(repo, tokens, nil), newQuotaRedirectingFactory(srv), nil)
			usage, err := svc.QueryUsage(context.Background(), 100)
			require.NoError(t, err)
			require.Positive(t, usage.FetchedAt)
			encoded, err := json.Marshal(usage.Credits)
			require.NoError(t, err)
			require.JSONEq(t, tc.want, string(encoded))
			require.Equal(t, []string{"/backend-api/wham/usage", "/backend-api/wham/rate-limit-reset-credits"}, paths)
			require.Zero(t, repo.extraUpdateCalls, "read-only query must not write account state")
		})
	}
}

func TestCacheCodexCreditsSnapshot(t *testing.T) {
	ctx := context.Background()
	repo := &stubQuotaAccountRepo{}
	svc := &OpenAIQuotaService{accountRepo: repo}
	balance := "1200.50"
	usage := &OpenAIQuotaUsage{FetchedAt: 123, Credits: &OpenAICredits{HasCredits: true, Balance: &balance}}

	// No reset-card details are required to persist the balance on the queried row.
	require.NoError(t, svc.CacheCreditsSnapshot(ctx, 200, usage))
	encoded, err := json.Marshal(repo.extraUpdates[200][openaiQuotaCreditsKey])
	require.NoError(t, err)
	require.JSONEq(t, `{"credits":{"has_credits":true,"unlimited":false,"balance":"1200.50"},"fetched_at":123}`, string(encoded))
	require.NotContains(t, repo.extraUpdates, int64(100), "a shadow row must not overwrite its parent")
	require.NotContains(t, repo.extraUpdates[200], openaiQuotaResetCreditsKey)

	// Missing credits from a successful read invalidate the previous balance.
	require.NoError(t, svc.CacheCreditsSnapshot(ctx, 200, &OpenAIQuotaUsage{FetchedAt: 456}))
	encoded, err = json.Marshal(repo.extraUpdates[200][openaiQuotaCreditsKey])
	require.NoError(t, err)
	require.JSONEq(t, `{"credits":null,"fetched_at":456}`, string(encoded))

	require.Error(t, svc.CacheCreditsSnapshot(ctx, 200, nil))
	require.Equal(t, 2, repo.extraUpdateCalls)
	repo.extraUpdateErr = errors.New("database unavailable")
	require.ErrorContains(t, svc.CacheCreditsSnapshot(ctx, 200, usage), "database unavailable")
}

func TestQueryAndCacheCodexSpendControl(t *testing.T) {
	const body = `{"credits":{"has_credits":true,"unlimited":false,"balance":"150.25"},"rate_limit":{"allowed":true,"limit_reached":false},"spend_control":{"reached":false,"individual_limit":{"source":"member","limit":"9007199254740993.01","used":"48.98","remaining":"9007199254740944.03","used_percent":0,"remaining_percent":100,"reset_at":2000000000,"reset_after_seconds":300}},"rate_limit_reached_type":null}`
	account := &Account{ID: 102, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Status: StatusActive,
		Credentials: map[string]any{
			"chatgpt_account_id": "test-spend-control-workspace",
			"access_token":       "test-token",
			"refresh_token":      "test-refresh-token",
		},
	}
	repo := &stubQuotaAccountRepo{accounts: map[int64]*Account{102: account}}
	tokens := &stubQuotaTokenCache{tokens: map[string]string{OpenAITokenCacheKey(account): "test-token"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "test-spend-control-workspace", r.Header.Get("ChatGPT-Account-ID"))
		require.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/backend-api/wham/usage" {
			_, _ = w.Write([]byte(body))
			return
		}
		_, _ = w.Write([]byte(`{"available_count":0}`))
	}))
	defer srv.Close()
	svc := NewOpenAIQuotaService(repo, nil, NewOpenAITokenProvider(repo, tokens, nil), newQuotaRedirectingFactory(srv), nil)
	usage, err := svc.QueryUsage(context.Background(), account.ID)
	require.NoError(t, err)
	require.NotNil(t, usage.SpendControl)
	require.Equal(t, "9007199254740993.01", *usage.SpendControl.IndividualLimit.Limit)
	require.Equal(t, "48.98", *usage.SpendControl.IndividualLimit.Used)
	require.Equal(t, "150.25", *usage.Credits.Balance, "credit balance remains separate from the personal limit")
	require.Zero(t, repo.extraUpdateCalls, "query is read-only")
	require.NoError(t, svc.CacheCreditsSnapshot(context.Background(), account.ID, usage))
	snapshot := readCodexCreditsSnapshot(repo.extraUpdates[account.ID])
	require.NotNil(t, snapshot)
	require.Equal(t, usage.SpendControl, snapshot.SpendControl)
	require.Equal(t, usage.RateLimit, snapshot.RateLimit)
	require.Equal(t, usage.FetchedAt, snapshot.FetchedAt)
	encoded, err := json.Marshal(usage)
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"limit":"9007199254740993.01"`)
	require.NotContains(t, string(encoded), "test-token")
	// A successful full read with omitted fields invalidates both old units.
	require.NoError(t, svc.CacheCreditsSnapshot(context.Background(), account.ID, &OpenAIQuotaUsage{FetchedAt: usage.FetchedAt + 1}))
	snapshot = readCodexCreditsSnapshot(repo.extraUpdates[account.ID])
	require.Nil(t, snapshot.SpendControl)
	require.Nil(t, snapshot.Credits)
}

func TestCodexSpendControlNumberCompatibility(t *testing.T) {
	var usage OpenAIQuotaUsage
	require.NoError(t, json.Unmarshal([]byte(`{"spend_control":{"individual_limit":{"limit":9007199254740993.01,"used":48.98,"remaining":9007199254740944.03}}}`), &usage))
	require.Equal(t, "9007199254740993.01", *usage.SpendControl.IndividualLimit.Limit)
	for _, value := range []string{`true`, `[]`, `{}`} {
		require.Error(t, json.Unmarshal([]byte(`{"spend_control":{"individual_limit":{"limit":`+value+`}}}`), &usage))
	}
}
