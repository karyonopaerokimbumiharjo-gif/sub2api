package service

import (
	"context"
	"encoding/json"
	"errors"
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
	"github.com/tidwall/gjson"
)

type nativePiCompatRepo struct {
	AccountRepository
	accounts map[int64]*Account
}

func (r *nativePiCompatRepo) GetByID(_ context.Context, id int64) (*Account, error) {
	return r.accounts[id], nil
}

func TestNativePiCompatibilityAccountCanBeScheduled(t *testing.T) {
	resetOpenAIAdvancedSchedulerSettingCacheForTest()
	t.Cleanup(resetOpenAIAdvancedSchedulerSettingCacheForTest)
	account := nativePiAccount()
	account.Status = StatusActive
	account.Schedulable = true
	account.Concurrency = 1
	groupID := int64(9)
	svc := &OpenAIGatewayService{
		accountRepo:        schedulerTestOpenAIAccountRepo{accounts: []Account{*account}},
		cache:              &schedulerTestGatewayCache{},
		cfg:                &config.Config{},
		concurrencyService: NewConcurrencyService(schedulerTestConcurrencyCache{}),
	}
	// Both public Chat Completions and Messages handlers request this
	// capability before their protocol adapter is called.
	selection, _, err := svc.SelectAccountWithSchedulerForCapability(
		context.Background(), &groupID, "", "", "gpt-6-astra", nil,
		OpenAIUpstreamTransportAny, OpenAIEndpointCapabilityChatCompletions,
		false, false, true, PlatformOpenAI,
	)
	require.NoError(t, err)
	require.NotNil(t, selection)
	require.Equal(t, account.ID, selection.Account.ID)
	if selection.ReleaseFunc != nil {
		selection.ReleaseFunc()
	}
	for _, unsupported := range []OpenAIEndpointCapability{
		OpenAIEndpointCapabilityLive, OpenAIEndpointCapabilityAlphaSearch, OpenAIEndpointCapabilityEmbeddings,
	} {
		require.False(t, account.SupportsOpenAIEndpointCapability(unsupported))
	}
}

func TestNativePiCompatibilityRoutesUsePrivateRuntime(t *testing.T) {
	gin.SetMode(gin.TestMode)
	const terminal = `data: {"type":"response.created","response":{"id":"resp_pi_compat","object":"response","status":"in_progress","model":"gpt-6-astra","output":[]}}

data: {"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"PI_COMPAT_OK"}

data: {"type":"response.completed","response":{"id":"resp_pi_compat","object":"response","status":"completed","model":"gpt-6-astra","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"PI_COMPAT_OK"}]}],"usage":{"input_tokens":3,"output_tokens":2}}}

`
	secret := strings.Repeat("s", 40)
	runtimeCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		runtimeCalls++
		require.Equal(t, "/responses", r.URL.Path)
		require.Equal(t, "Bearer "+secret, r.Header.Get("Authorization"))
		var payload struct {
			OwnerID      int64          `json:"owner_id"`
			CredentialID int64          `json:"credential_id"`
			AccountID    string         `json:"account_id"`
			AccessToken  string         `json:"access_token"`
			SessionID    string         `json:"session_id"`
			Request      map[string]any `json:"request"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		require.Equal(t, int64(42), payload.OwnerID)
		require.Equal(t, int64(7), payload.CredentialID)
		require.Equal(t, "fixture-account", payload.AccountID)
		require.Equal(t, "fixture-access", payload.AccessToken)
		require.Equal(t, "43:11:compat-session", payload.SessionID)
		require.Equal(t, "gpt-6-astra", payload.Request["model"])
		require.NotContains(t, payload.Request, "client_metadata")
		require.NotContains(t, payload.Request, "previous_response_id")
		require.Contains(t, payload.Request, "input")
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(terminal))
	}))
	defer server.Close()
	secretPath := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(secretPath, []byte(secret), 0600))
	t.Setenv("PI_RUNTIME_URL", server.URL)
	t.Setenv("PI_RUNTIME_SECRET_FILE", secretPath)
	for _, endpoint := range []string{"chat/completions", "messages"} {
		for _, streaming := range []bool{false, true} {
			for _, authorized := range []bool{true, false} {
				t.Run(endpoint+"/"+map[bool]string{true: "stream", false: "json"}[streaming]+"/"+map[bool]string{true: "allowed", false: "denied"}[authorized], func(t *testing.T) {
					owner := nativePiAccount()
					owner.Credentials["expires_at"] = time.Now().Add(time.Hour).Format(time.RFC3339)
					alias := nativePiAccount()
					alias.ID = 8
					alias.Credentials["harness_kind"] = PiSharedHarnessKind
					alias.Credentials[PiRuntimeAccountIDCredential] = "7"
					delete(alias.Credentials, "access_token")
					delete(alias.Credentials, "refresh_token")
					repo := &nativePiCompatRepo{accounts: map[int64]*Account{7: owner}}
					direct := &httpUpstreamRecorder{err: errors.New("Pi request escaped private runtime")}
					svc := &OpenAIGatewayService{cfg: &config.Config{}, accountRepo: repo, httpUpstream: direct, toolCorrector: NewCodexToolCorrector(), openAITokenProvider: NewOpenAITokenProvider(repo, nil, nil)}
					w := httptest.NewRecorder()
					c, _ := gin.CreateTestContext(w)
					c.Request = httptest.NewRequest("POST", "/v1/"+endpoint, nil)
					c.Request.Header.Set("session-id", "compat-session")
					key := nativePiTestKey(43)
					if !authorized {
						key.User.AllowedGroups = nil
					}
					c.Set("api_key", key)
					body, _ := json.Marshal(map[string]any{"model": "gpt-6-astra", "messages": []map[string]any{{"role": "user", "content": "hello"}}, "max_tokens": 64, "stream": streaming})
					before := runtimeCalls
					var result *OpenAIForwardResult
					var err error
					if endpoint == "messages" {
						result, err = svc.ForwardAsAnthropic(context.Background(), c, alias, body, "", "")
					} else {
						result, err = svc.ForwardAsChatCompletions(context.Background(), c, alias, body, "", "")
					}
					require.Empty(t, direct.requests, "Pi must never use the direct Codex transport")
					if !authorized {
						require.Error(t, err)
						require.Equal(t, http.StatusForbidden, w.Code)
						require.Equal(t, before, runtimeCalls)
						return
					}
					require.NoError(t, err)
					require.Equal(t, before+1, runtimeCalls)
					require.Equal(t, http.StatusOK, w.Code)
					require.Contains(t, w.Body.String(), "PI_COMPAT_OK")
					require.Equal(t, 3, result.Usage.InputTokens)
					require.Equal(t, "gpt-6-astra", result.UpstreamResponseModel)
					require.Equal(t, "/backend-api/codex/responses", result.UpstreamEndpoint)
					if !streaming {
						require.Contains(t, w.Header().Get("Content-Type"), "application/json")
						if endpoint == "messages" {
							require.Equal(t, "message", gjson.GetBytes(w.Body.Bytes(), "type").String())
						} else {
							require.Equal(t, "chat.completion", gjson.GetBytes(w.Body.Bytes(), "object").String())
						}
					}
				})
			}
		}
	}
}
