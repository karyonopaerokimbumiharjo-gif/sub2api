package service

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

func TestCPAAccountTestDefaultsToSupportedModel(t *testing.T) {
	for _, test := range []struct {
		name    string
		mapping map[string]any
		want    string
	}{
		{name: "current CPA default", want: "gpt-6-astra"},
		{name: "explicit whitelist", mapping: map[string]any{"public-alias": "supported-private-model"}, want: "supported-private-model"},
	} {
		t.Run(test.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = httptest.NewRequest(http.MethodPost, "/test", nil)
			upstream := &httpUpstreamRecorder{resp: &http.Response{StatusCode: http.StatusOK,
				Body: io.NopCloser(strings.NewReader("data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n"))}}
			cfg := upstreamModelSyncTestConfig()
			cfg.Security.URLAllowlist.AllowInsecureHTTP = true
			svc := &AccountTestService{httpUpstream: upstream, cfg: cfg}
			account := &Account{ID: 30, Platform: PlatformOpenAI, Type: AccountTypeAPIKey,
				Credentials: map[string]any{"base_url": "http://cpa:8317", "api_key": "test-key", "model_mapping": test.mapping}}
			require.NoError(t, svc.testOpenAIAccountConnection(c, account, "", "", ""))
			require.Equal(t, test.want, gjson.GetBytes(upstream.lastBody, "model").String())
		})
	}
}
