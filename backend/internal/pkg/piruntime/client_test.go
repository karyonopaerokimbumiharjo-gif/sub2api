package piruntime

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRuntimeErrorsExposeOnlyKnownCodes(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "runtime.secret")
	if err := os.WriteFile(secret, []byte(strings.Repeat("s", 40)), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PI_RUNTIME_SECRET_FILE", secret)
	for _, tc := range []struct{ body, code string }{
		{`{"error":"oauth_session_mismatch"}`, "oauth_session_mismatch"},
		{`{"error":"oauth_exchange_timeout"}`, "oauth_exchange_timeout"},
		{`{"error":"pi_upstream_busy"}`, "pi_upstream_busy"},
		{`{"error":"pi_upstream_rate_limited"}`, "pi_upstream_rate_limited"},
		{`{"error":"token=secret-provider-body"}`, "pi_runtime_unavailable"},
		{`<html>secret-provider-body</html>`, "pi_runtime_unavailable"},
	} {
		t.Run(tc.code+tc.body[:1], func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(400); _, _ = w.Write([]byte(tc.body)) }))
			defer srv.Close()
			t.Setenv("PI_RUNTIME_URL", srv.URL)
			err := JSON(context.Background(), "/oauth/complete", map[string]string{}, &struct{}{})
			var failure *Error
			if !errors.As(err, &failure) || failure.Code != tc.code {
				t.Fatalf("unexpected error type/code: %v", err)
			}
			if strings.Contains(err.Error()+PublicMessage(err), "secret-provider-body") {
				t.Fatal("provider error leaked")
			}
		})
	}
}

func TestStreamingResponseHasNoTotalTimeoutAndHonorsCallerCancellation(t *testing.T) {
	if streamingClient.Timeout != 0 {
		t.Fatalf("streaming response has a total timeout: %v", streamingClient.Timeout)
	}
	if client.Timeout != 130*time.Second {
		t.Fatalf("non-streaming operations lost their bounded timeout: %v", client.Timeout)
	}
	secret := filepath.Join(t.TempDir(), "runtime.secret")
	if err := os.WriteFile(secret, []byte(strings.Repeat("s", 40)), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PI_RUNTIME_SECRET_FILE", secret)
	upstreamCancelled := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"type\":\"response.created\"}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(upstreamCancelled)
	}))
	defer srv.Close()
	t.Setenv("PI_RUNTIME_URL", srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resp, err := Do(ctx, "/responses", map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	first := make([]byte, 5)
	if _, err := io.ReadFull(resp.Body, first); err != nil || string(first) != "data:" {
		t.Fatalf("stream did not start: %q, %v", first, err)
	}
	cancel()
	if _, err := io.ReadAll(resp.Body); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation did not terminate the stream: %v", err)
	}
	select {
	case <-upstreamCancelled:
	case <-time.After(time.Second):
		t.Fatal("caller cancellation did not reach runtime")
	}
}
