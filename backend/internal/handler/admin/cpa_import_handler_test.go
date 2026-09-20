package admin

import (
	"context"
	"encoding/json"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type cpaImportOnlyStub struct {
	calls         int
	withoutBridge bool
}

func (s *cpaImportOnlyStub) ImportOAuthCredentialsToCPA(_ context.Context, credentials map[string]any) (*service.OpenAICPAImportResult, error) {
	s.calls++
	if s.withoutBridge {
		return &service.OpenAICPAImportResult{Email: "canary@example.invalid", AuthName: "canary.json"}, nil
	}
	return &service.OpenAICPAImportResult{BridgeAccountID: 30, Email: "canary@example.invalid", AuthName: "canary.json"}, nil
}
func (s *cpaImportOnlyStub) ImportCPAAuthFile(ctx context.Context, credentials map[string]any) (*service.OpenAICPAImportResult, error) {
	return s.ImportOAuthCredentialsToCPA(ctx, credentials)
}

func TestCPAOnlyImportNeverCreatesSub2Account(t *testing.T) {
	gin.SetMode(gin.TestMode)
	stub := &cpaImportOnlyStub{}
	handler := &OpenAIOAuthHandler{cpaImportService: stub} // deliberately no Sub2 admin service
	router := gin.New()
	router.POST("/import", handler.ImportCPAAccounts)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/import", strings.NewReader(`{"contents":["{\"access_token\":\"test-access\",\"refresh_token\":\"test-refresh\",\"id_token\":\"test-id\",\"email\":\"canary@example.invalid\",\"chatgpt_account_id\":\"test\",\"expires_at\":\"2100-01-01T00:00:00Z\"}"]}`))
	r.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, r)
	require.Equal(t, 200, w.Code)
	require.Equal(t, 1, stub.calls)
	require.Contains(t, w.Body.String(), "imported_cpa")
	require.NotContains(t, w.Body.String(), "test-access")
	require.NotContains(t, w.Body.String(), "test-refresh")
}

func TestCPAOnlyRemovedRouteFailsExplicitly(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	DirectAccountBackendRemoved(c)
	require.Equal(t, 400, w.Code)
	require.Contains(t, w.Body.String(), "CPA_BACKEND_REQUIRED")
}

func TestCPAOnlyImportCodexAuthFileAndPastedJSONWithoutBridge(t *testing.T) {
	gin.SetMode(gin.TestMode)
	jwt := buildCodexImportTestJWT(t, time.Now().Add(time.Hour), map[string]any{
		"email":                       "canary@example.invalid",
		"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": "synthetic-account"},
	})
	auth, err := json.Marshal(map[string]any{"auth_mode": "chatgpt", "tokens": map[string]any{
		"access_token": jwt, "id_token": jwt, "refresh_token": "synthetic-refresh", "account_id": "synthetic-account",
	}})
	require.NoError(t, err)
	for _, field := range []string{"content", "contents"} {
		t.Run(field, func(t *testing.T) {
			stub := &cpaImportOnlyStub{withoutBridge: true}
			handler := &OpenAIOAuthHandler{cpaImportService: stub}
			router := gin.New()
			router.POST("/import", handler.ImportCPAAccounts)
			var input any = string(auth)
			if field == "contents" {
				input = []string{string(auth)}
			}
			body, err := json.Marshal(map[string]any{field: input})
			require.NoError(t, err)
			r := httptest.NewRequest("POST", "/import", strings.NewReader(string(body)))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			require.Equal(t, 200, w.Code)
			require.Equal(t, 1, stub.calls)
			require.Contains(t, w.Body.String(), `"created":1`)
			require.Contains(t, w.Body.String(), `"action":"imported_cpa"`)
			require.NotContains(t, w.Body.String(), `"account_id"`)
			require.NotContains(t, w.Body.String(), jwt)
			require.NotContains(t, w.Body.String(), "synthetic-refresh")
		})
	}
}
