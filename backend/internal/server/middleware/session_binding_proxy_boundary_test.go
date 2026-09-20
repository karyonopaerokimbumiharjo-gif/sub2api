package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ip"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestSessionBindingForwardedHeadersRequireTrustedPeer(t *testing.T) {
	for _, tc := range []struct {
		name, peer, want string
		legacy           bool
	}{
		{"direct cannot spoof even with compatibility enabled", "203.0.113.8:1234", "203.0.113.8", true},
		{"trusted proxy uses sanitized forwarded chain", "172.19.0.5:1234", "203.0.113.9", false},
		{"custom headers only from trusted proxy", "172.19.0.5:1234", "198.51.100.42", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Server.TrustedProxies = []string{"172.19.0.5/32"}
			cfg.Security.TrustForwardedIPForAPIKeyACL = tc.legacy
			r := gin.New()
			require.NoError(t, r.SetTrustedProxies(cfg.Server.TrustedProxies))
			r.Use(SessionBindingContext(cfg))
			r.GET("/", func(c *gin.Context) { c.String(200, ip.GetSecurityClientIP(c, true)) })
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.peer
			req.Header.Set("CF-Connecting-IP", "198.51.100.42")
			req.Header.Set("X-Forwarded-For", "203.0.113.9")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			require.Equal(t, tc.want, w.Body.String())
		})
	}
}
