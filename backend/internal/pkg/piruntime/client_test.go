package piruntime

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
