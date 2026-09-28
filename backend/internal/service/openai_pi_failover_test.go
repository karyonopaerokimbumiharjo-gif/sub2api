package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type nativePiQuotaRepo struct {
	AccountRepository
	rateLimitedID int64
	account       *Account
}

func (r *nativePiQuotaRepo) SetRateLimited(_ context.Context, id int64, resetAt time.Time) error {
	r.rateLimitedID = id
	if r.account != nil && r.account.ID == id {
		r.account.RateLimitResetAt = &resetAt
	}
	return nil
}

func (r *nativePiQuotaRepo) UpdateExtra(context.Context, int64, map[string]any) error { return nil }

func TestNativePiTransient429KeepsOriginalBoundedRetryPolicy(t *testing.T) {
	account := nativePiAccount()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/v1/responses", nil)
	svc := &OpenAIGatewayService{}
	resp := &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": []string{"1"}}, Body: io.NopCloser(strings.NewReader(`{"error":"pi_upstream_rate_limited","message":"private provider content"}`))}
	err := svc.nativePiRateLimitFailover(context.Background(), c, account, resp, "gpt-6-astra")
	var failover *UpstreamFailoverError
	require.ErrorAs(t, err, &failover)
	require.True(t, failover.RetryableOnSameAccount)
	require.True(t, failover.SameAccountRetryDeadline.After(time.Now()))
	require.False(t, svc.isOpenAIAccountRuntimeBlocked(account))
	require.False(t, c.Writer.Written())
	require.NotContains(t, string(failover.ResponseBody), "private provider content")
}

func TestNativePiQuotaFailureReachesSchedulerWithoutCommittingResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, endpoint := range []string{"responses", "responses/compact", "chat/completions", "messages"} {
		for _, signal := range []string{"headers", "body"} {
			t.Run(endpoint+"/"+signal, func(t *testing.T) {
				secret := strings.Repeat("s", 40)
				var attempts []string
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var payload struct {
						AccessToken string `json:"access_token"`
					}
					_ = json.NewDecoder(r.Body).Decode(&payload)
					attempts = append(attempts, payload.AccessToken)
					if payload.AccessToken == "fixture-fallback" {
						response := `{"id":"resp_fallback","object":"response","status":"completed","model":"gpt-6-astra","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"FALLBACK_OK"}]}],"usage":{"input_tokens":3,"output_tokens":2}}`
						if r.URL.Path == "/compact" {
							w.Header().Set("Content-Type", "application/json")
							_, _ = w.Write([]byte(response))
						} else {
							w.Header().Set("Content-Type", "text/event-stream")
							_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":" + response + "}\n\n"))
						}
						return
					}
					w.Header().Set("X-Request-Id", "quota-fixture")
					w.Header().Set("Retry-After", "3600")
					if signal == "headers" {
						w.Header().Set("x-codex-primary-used-percent", "100")
						w.Header().Set("x-codex-primary-window-minutes", "300")
						w.Header().Set("x-codex-primary-reset-after-seconds", "3600")
					}
					w.WriteHeader(http.StatusTooManyRequests)
					if signal == "body" {
						_, _ = w.Write([]byte(`{"error":"pi_upstream_rate_limited","rate_limit":{"type":"usage_limit_reached","resets_in_seconds":3600}}`))
					} else {
						_, _ = w.Write([]byte(`{"error":"pi_upstream_rate_limited"}`))
					}
				}))
				defer server.Close()
				file := filepath.Join(t.TempDir(), "secret")
				require.NoError(t, os.WriteFile(file, []byte(secret), 0600))
				t.Setenv("PI_RUNTIME_URL", server.URL)
				t.Setenv("PI_RUNTIME_SECRET_FILE", file)
				account := nativePiAccount()
				account.Status, account.Schedulable, account.Concurrency = StatusActive, true, 4
				account.Credentials["expires_at"] = time.Now().Add(time.Hour).Format(time.RFC3339)
				repo := &nativePiQuotaRepo{account: account}
				svc := &OpenAIGatewayService{cfg: &config.Config{}, rateLimitService: NewRateLimitService(repo, nil, nil, nil, nil), toolCorrector: NewCodexToolCorrector(), openAITokenProvider: NewOpenAITokenProvider(nil, nil, nil)}
				svc.rateLimitService.SetAccountRuntimeBlocker(svc)
				w := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(w)
				c.Request = httptest.NewRequest("POST", "/v1/"+endpoint, nil)
				c.Set("api_key", nativePiTestKey(42))
				body, _ := json.Marshal(map[string]any{"model": "gpt-6-astra", "input": "fixture", "messages": []map[string]any{{"role": "user", "content": "fixture"}}, "max_tokens": 32, "stream": true})
				var err error
				switch endpoint {
				case "chat/completions":
					_, err = svc.ForwardAsChatCompletions(context.Background(), c, account, body, "", "")
				case "messages":
					_, err = svc.ForwardAsAnthropic(context.Background(), c, account, body, "", "")
				default:
					_, err = svc.Forward(context.Background(), c, account, body)
				}
				var failover *UpstreamFailoverError
				require.ErrorAs(t, err, &failover, "PI must return control to the existing account-switch loop")
				require.False(t, c.Writer.Written(), "a 429 must not commit the client response before failover")
				require.Equal(t, 429, failover.StatusCode)
				require.False(t, failover.RetryableOnSameAccount, "exhausted quota must switch immediately")
				require.Equal(t, "3600", failover.ResponseHeaders.Get("Retry-After"))
				require.Equal(t, account.ID, repo.rateLimitedID)
				require.True(t, svc.isOpenAIAccountRuntimeBlocked(account))
				require.True(t, account.Schedulable, "temporary cooldown must not change the administrator's scheduling switch")
				// Even a sticky session must escape the exhausted account.
				fallback := nativePiAccount()
				fallback.ID, fallback.Status, fallback.Schedulable, fallback.Concurrency = 8, StatusActive, true, 4
				fallback.Credentials["access_token"] = "fixture-fallback"
				fallback.Credentials["expires_at"] = time.Now().Add(time.Hour).Format(time.RFC3339)
				svc.accountRepo = schedulerTestOpenAIAccountRepo{accounts: []Account{*account, *fallback}}
				svc.cache = &schedulerTestGatewayCache{sessionBindings: map[string]int64{"sticky-fixture": account.ID}}
				svc.concurrencyService = NewConcurrencyService(schedulerTestConcurrencyCache{})
				groupID := int64(9)
				selection, _, selectErr := svc.SelectAccountWithSchedulerForCapability(context.Background(), &groupID, "", "sticky-fixture", "gpt-6-astra", nil, OpenAIUpstreamTransportAny, OpenAIEndpointCapabilityChatCompletions, false, false, true, PlatformOpenAI)
				require.NoError(t, selectErr)
				require.Equal(t, fallback.ID, selection.Account.ID)
				if selection.ReleaseFunc != nil {
					selection.ReleaseFunc()
				}
				var result *OpenAIForwardResult
				switch endpoint {
				case "chat/completions":
					result, err = svc.ForwardAsChatCompletions(context.Background(), c, selection.Account, body, "", "")
				case "messages":
					result, err = svc.ForwardAsAnthropic(context.Background(), c, selection.Account, body, "", "")
				default:
					result, err = svc.Forward(context.Background(), c, selection.Account, body)
				}
				require.NoError(t, err)
				require.Contains(t, w.Body.String(), "FALLBACK_OK")
				require.Equal(t, "gpt-6-astra", result.UpstreamResponseModel)
				require.Equal(t, 3, result.Usage.InputTokens)
				require.Equal(t, []string{"fixture-access", "fixture-fallback"}, attempts)
			})
		}
	}
}
