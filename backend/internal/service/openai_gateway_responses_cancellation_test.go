package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/tlsfingerprint"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// This upstream waits for the request context, just as net/http does while
// waiting for response headers. A release channel keeps a broken test from
// leaking its forwarding goroutine.
type cancelAwareResponsesUpstream struct {
	started chan context.Context
	release chan struct{}
	once    sync.Once
}

func (u *cancelAwareResponsesUpstream) Do(req *http.Request, _ string, _ int64, _ int) (*http.Response, error) {
	u.started <- req.Context()
	select {
	case <-req.Context().Done():
		return nil, req.Context().Err()
	case <-u.release:
		return nil, errors.New("test upstream released")
	}
}

func (u *cancelAwareResponsesUpstream) DoWithTLS(req *http.Request, proxyURL string, accountID int64, accountConcurrency int, _ *tlsfingerprint.Profile) (*http.Response, error) {
	return u.Do(req, proxyURL, accountID, accountConcurrency)
}

func (u *cancelAwareResponsesUpstream) unblock() {
	u.once.Do(func() { close(u.release) })
}

func TestOpenAIResponsesNonStreamingCancelsUpstreamOnClientDisconnect(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, gpt6j := range []bool{true, false} {
		name := "gpt6j_transformed"
		if !gpt6j {
			name = "ordinary_passthrough"
		}
		t.Run(name, func(t *testing.T) {
			upstream := &cancelAwareResponsesUpstream{
				started: make(chan context.Context, 1),
				release: make(chan struct{}),
			}
			t.Cleanup(upstream.unblock)
			cfg := &config.Config{}
			cfg.Security.URLAllowlist.Enabled = false
			svc := &OpenAIGatewayService{cfg: cfg, httpUpstream: upstream}
			account := &Account{
				ID: 11, Name: "openai-apikey", Platform: PlatformOpenAI,
				Type: AccountTypeAPIKey, Concurrency: 1,
				Credentials: map[string]any{"api_key": "sk-test", "base_url": "https://example.com"},
				Extra:       map[string]any{"openai_passthrough": true},
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil).WithContext(ctx)
			SetOpenAIClientTransport(c, OpenAIClientTransportHTTP)
			// GPT-6J uses the transformed branch even when this account is
			// configured for passthrough; the other subtest covers that path.
			if gpt6j {
				c.Set(OpenAIGPT6JContextKey, true)
			}
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				_, _ = svc.Forward(ctx, c, account, []byte(`{"model":"gpt-6-astra","stream":false,"input":"hello"}`))
			}()
			var upstreamCtx context.Context
			select {
			case upstreamCtx = <-upstream.started:
			case <-time.After(3 * time.Second):
				t.Fatal("upstream request did not start")
			}
			cancel()
			select {
			case <-upstreamCtx.Done():
				require.ErrorIs(t, upstreamCtx.Err(), context.Canceled)
			case <-time.After(time.Second):
				t.Fatal("non-streaming upstream continued after client cancellation")
			}
			select {
			case <-finished:
			case <-time.After(3 * time.Second):
				t.Fatal("forwarding did not finish after cancellation")
			}
		})
	}
}
