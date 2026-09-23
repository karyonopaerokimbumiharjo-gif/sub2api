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

	"github.com/stretchr/testify/require"
)

func TestNativePiModelsUseBoundRuntimeCatalogWithoutStaticImages(t *testing.T) {
	account := nativePiAccount()
	account.Credentials["access_token"] = "private-fixture-access"
	account.Credentials["expires_at"] = time.Now().Add(time.Hour).Format(time.RFC3339)
	calls := 0
	runtime := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		require.Equal(t, "/models", r.URL.Path)
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, account.GetCredential("chatgpt_account_id"), body["account_id"])
		require.Equal(t, "private-fixture-access", body["access_token"])
		if calls == 1 {
			_, _ = w.Write([]byte(`{"models":[{"slug":"gpt-5.6-sol","display_name":"Sol"}]}`))
		} else {
			_, _ = w.Write([]byte(`{"models":[]}`))
		}
	}))
	defer runtime.Close()
	secret := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(secret, []byte(strings.Repeat("s", 40)), 0600))
	t.Setenv("PI_RUNTIME_URL", runtime.URL)
	t.Setenv("PI_RUNTIME_SECRET_FILE", secret)
	gateway := &OpenAIGatewayService{openAITokenProvider: NewOpenAITokenProvider(nil, nil, nil)}
	svc := &AccountTestService{openaiGatewayService: gateway}
	models, err := svc.FetchOpenAIAccountModels(context.Background(), account)
	require.NoError(t, err)
	require.Len(t, models, 1)
	require.Equal(t, "gpt-5.6-sol", models[0].ID)
	require.Equal(t, "Sol", models[0].DisplayName)
	models, err = svc.FetchOpenAIAccountModels(context.Background(), account)
	require.NoError(t, err)
	require.Empty(t, models, "empty upstream catalogs must remain empty")
}
