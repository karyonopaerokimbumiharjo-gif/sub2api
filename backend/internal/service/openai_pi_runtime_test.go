package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
)

func nativePiAccount() *Account {
	return &Account{ID: 7, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Credentials: map[string]any{"harness_kind": "pi", "pi_owner_user_id": "42", "chatgpt_account_id": "fixture-account", "refresh_token": "fixture-refresh"}}
}

func TestNativePiStableSessionIgnoresPerRequestTraceID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, requestID := range []string{"request-one", "request-two"} {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest("POST", "/v1/responses", nil)
		c.Request.Header.Set("x-client-request-id", requestID)
		if got := nativePiSession(c, map[string]any{"prompt_cache_key": " stable-session "}); got != "stable-session" {
			t.Fatalf("request tracing split stable cache session: %q", got)
		}
		oneShot := nativePiSession(c, map[string]any{})
		if !strings.HasPrefix(oneShot, "one-shot:") || oneShot == nativePiSession(c, map[string]any{}) {
			t.Fatalf("sessionless calls must get distinct one-shot sessions: %q", oneShot)
		}
		c.Request.Header.Set("session_id", "explicit-session")
		if got := nativePiSession(c, map[string]any{"prompt_cache_key": "cache-session"}); got != "explicit-session" {
			t.Fatalf("explicit session lost precedence: %q", got)
		}
	}
}
func TestNativePiSessionIsIsolatedPerAPIKey(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set("api_key", &APIKey{ID: 11, UserID: 42})
	first, err := scopedNativePiSession(c, "same-client-session")
	if err != nil {
		t.Fatal(err)
	}
	c.Set("api_key", &APIKey{ID: 12, UserID: 42})
	second, err := scopedNativePiSession(c, "same-client-session")
	if err != nil || first == second {
		t.Fatalf("Pi sessions from separate API keys must differ: first=%q second=%q err=%v", first, second, err)
	}
}
func TestNativePiOwnerAndIngress(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name                    string
		user                    int64
		body, metadata, session string
		status                  int
	}{
		{"wrong owner", 43, `{"model":"gpt-6-astra","input":"test"}`, "", "session", 403},
		{"missing key", 0, `{}`, "", "", 403},
		{"codex header", 42, `{}`, `{"turn_id":"fixture"}`, "", 400},
		{"codex body", 42, `{"client_metadata":{}}`, "", "", 400},
		{"foreign continuation", 42, `{"previous_response_id":"foreign"}`, "", "session", 400},
		{"unsupported output limit", 42, `{"model":"gpt-6-astra","input":"test","max_output_tokens":12}`, "", "session", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("POST", "/v1/responses", nil)
			if tc.user > 0 {
				c.Set("api_key", &APIKey{ID: 11, UserID: tc.user})
			}
			if tc.metadata != "" {
				c.Request.Header.Set("x-codex-turn-metadata", tc.metadata)
			}
			c.Request.Header.Set("session-id", tc.session)
			_, err := (&OpenAIGatewayService{}).forwardNativePi(context.Background(), c, nativePiAccount(), []byte(tc.body))
			if err == nil || w.Code != tc.status {
				t.Fatalf("status=%d err=%v", w.Code, err)
			}
		})
	}
}
func TestNativePiRefreshPreservesBinding(t *testing.T) {
	var wrongAccount bool
	calls := 0
	secret := strings.Repeat("x", 40)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/oauth/refresh" || r.Header.Get("Authorization") != "Bearer "+secret {
			t.Error("wrong native refresh route")
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["owner_id"] != float64(42) || body["account_id"] != "fixture-account" || body["refresh_token"] != "fixture-refresh" {
			t.Error("binding lost")
		}
		account := "fixture-account"
		if wrongAccount {
			account = "different-account"
		}
		_ = json.NewEncoder(w).Encode(OpenAITokenInfo{AccessToken: "fixture-access", RefreshToken: "new-refresh", ExpiresAt: time.Now().Add(time.Hour).Unix(), HarnessKind: "pi", PiOwnerUserID: "42", ChatGPTAccountID: account})
	}))
	defer server.Close()
	file := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(file, []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PI_RUNTIME_URL", server.URL)
	t.Setenv("PI_RUNTIME_SECRET_FILE", file)
	service := &OpenAIOAuthService{}
	info, err := service.RefreshAccountToken(context.Background(), nativePiAccount())
	if err != nil {
		t.Fatal(err)
	}
	creds := service.BuildAccountCredentials(info)
	if creds["harness_kind"] != "pi" || creds["pi_owner_user_id"] != "42" || creds["refresh_token"] != "new-refresh" {
		t.Fatal("refresh binding not persisted")
	}
	wrongAccount = true
	if _, err := service.RefreshAccountToken(context.Background(), nativePiAccount()); err == nil {
		t.Fatal("accepted account mismatch")
	}
	if calls != 2 {
		t.Fatal("native refresh not used")
	}
}

func TestNativePiForwardThroughPrivateRuntime(t *testing.T) {
	const events = "data: {\"type\":\"response.output_text.delta\",\"delta\":\"PI_OK\"}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"object\":\"response\",\"id\":\"resp_fixture\",\"status\":\"completed\",\"model\":\"gpt-6-astra\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"PI_OK\"}]}],\"usage\":{\"input_tokens\":3,\"output_tokens\":2}}}\n\n"
	const toolEvents = `data: {"type":"response.completed","response":{"object":"response","id":"resp_tool_fixture","status":"completed","model":"gpt-6-astra","output":[{"type":"function_call","call_id":"call_1","name":"echo","arguments":"{\"value\":\"PI_OK\"}"}],"usage":{"input_tokens":3,"output_tokens":2}}}

`
	secret := strings.Repeat("s", 40)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/responses" || r.Header.Get("Authorization") != "Bearer "+secret {
			t.Error("wrong private runtime route")
		}
		var payload struct {
			OwnerID      int64          `json:"owner_id"`
			CredentialID int64          `json:"credential_id"`
			AccessToken  string         `json:"access_token"`
			SessionID    string         `json:"session_id"`
			Request      map[string]any `json:"request"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if payload.OwnerID != 42 || payload.CredentialID != 7 || payload.AccessToken != "fixture-access" || payload.Request["model"] != "gpt-6-astra" {
			t.Error("binding not forwarded")
		}
		if payload.SessionID != "11:fixture-session" && !strings.HasPrefix(payload.SessionID, "11:one-shot:") {
			t.Errorf("unexpected Pi session binding: %q", payload.SessionID)
		}
		for _, field := range []string{"previous_response_id", "max_output_tokens", "client_metadata"} {
			if _, present := payload.Request[field]; present {
				t.Errorf("null %s must not reach Pi runtime", field)
			}
		}
		w.Header().Set("Content-Type", "text/event-stream")
		if _, hasTools := payload.Request["tools"]; hasTools {
			_, _ = w.Write([]byte(toolEvents))
		} else {
			_, _ = w.Write([]byte(events))
		}
	}))
	defer server.Close()
	file := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(file, []byte(secret), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PI_RUNTIME_URL", server.URL)
	t.Setenv("PI_RUNTIME_SECRET_FILE", file)
	for _, streaming := range []bool{true, false} {
		account := nativePiAccount()
		account.Credentials["access_token"] = "fixture-access"
		account.Credentials["expires_at"] = time.Now().Add(time.Hour).Format(time.RFC3339)
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/v1/responses", nil)
		c.Set("api_key", &APIKey{ID: 11, UserID: 42})
		if streaming {
			c.Request.Header.Set("session-id", "fixture-session")
		}
		svc := &OpenAIGatewayService{cfg: &config.Config{}, toolCorrector: NewCodexToolCorrector(), openAITokenProvider: NewOpenAITokenProvider(nil, nil, nil)}
		request := map[string]any{"model": "gpt-6-astra", "input": "test", "stream": streaming}
		if !streaming {
			request["previous_response_id"] = nil
			request["max_output_tokens"] = nil
			request["client_metadata"] = nil
			request["tools"] = []map[string]any{{"type": "function", "name": "echo", "parameters": map[string]any{"type": "object", "properties": map[string]any{"value": map[string]any{"type": "string"}}}}}
		}
		body, _ := json.Marshal(request)
		result, err := svc.Forward(context.Background(), c, account, body)
		if err != nil {
			t.Fatal(err)
		}
		if w.Code != 200 || !strings.Contains(w.Body.String(), "PI_OK") || result.Usage.InputTokens != 3 || result.UpstreamResponseModel != "gpt-6-astra" {
			t.Fatalf("stream=%v status=%d usage=%+v model=%s", streaming, w.Code, result.Usage, result.UpstreamResponseModel)
		}
		if !streaming && (!json.Valid(w.Body.Bytes()) || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json")) {
			t.Fatalf("stream=false must return a JSON Responses object, content-type=%q", w.Header().Get("Content-Type"))
		}
		if !streaming {
			var response struct {
				Output []struct {
					Type string `json:"type"`
					Name string `json:"name"`
				} `json:"output"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || len(response.Output) != 1 || response.Output[0].Type != "function_call" || response.Output[0].Name != "echo" {
				t.Fatalf("stream=false lost the function tool call: %v", err)
			}
		}
	}
}
