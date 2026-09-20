package service

import (
	"context"
	"github.com/Wei-Shaw/sub2api/internal/pkg/cpapolicy"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCPAOnlyImportRejectedCredentialNeverOverwritesPool(t *testing.T) {
	uploads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v0/management/auth-files" {
			uploads++
		}
		_, _ = w.Write([]byte(`{"status_code":401,"body":"invalid token"}`))
	}))
	defer server.Close()
	secret := filepath.Join(t.TempDir(), "management-secret")
	require.NoError(t, os.WriteFile(secret, []byte("test-secret"), 0600))
	t.Setenv(openAIQuotaBridgeManagementURLKey, server.URL)
	t.Setenv(openAIQuotaBridgeManagementPasswordFileKey, secret)
	bridge := newOpenAIQuotaBridgeTestAccount(30, server.URL, "bound.json", "bound@example.invalid")
	svc := &OpenAIQuotaService{accountRepo: &stubQuotaAccountRepo{accounts: map[int64]*Account{30: bridge}}}
	_, err := svc.ImportOAuthCredentialsToCPA(context.Background(), map[string]any{
		"access_token": "revoked", "refresh_token": "refresh", "id_token": "id", "email": "bound@example.invalid", "chatgpt_account_id": "bound", "expires_at": "2100-01-01T00:00:00Z",
	})
	require.Error(t, err)
	require.Zero(t, uploads)
	_, err = svc.ImportOAuthCredentialsToCPA(context.Background(), map[string]any{
		"access_token": "expired", "refresh_token": "refresh", "id_token": "id", "email": "bound@example.invalid", "chatgpt_account_id": "bound", "expires_at": "2000-01-01T00:00:00Z",
	})
	require.Error(t, err)
	require.Zero(t, uploads)
}

func TestCPAOnlyModerationAndWebsocketCannotDialExternal(t *testing.T) {
	svc := &ContentModerationService{}
	_, err := svc.callModerationOnceWithInput(context.Background(), &ContentModerationConfig{BaseURL: "https://api.openai.com"}, "synthetic", "safe", new(int))
	require.Error(t, err)
	client, err := svc.moderationHTTPClient(context.Background(), &ContentModerationConfig{BaseURL: cpapolicy.BaseURL})
	require.NoError(t, err)
	require.Equal(t, http.ErrUseLastResponse, client.CheckRedirect(nil, nil))
	dialer := newDefaultOpenAIWSClientDialer()
	_, _, _, err = dialer.Dial(context.Background(), "wss://api.openai.com/v1/responses", nil, "")
	require.Error(t, err)
	_, _, _, err = dialer.Dial(context.Background(), "ws://cpa:8317/v1/responses", nil, "http://proxy.example")
	require.Error(t, err)
}

func TestCPAOnlySchedulingRejectsStaleDirectAccounts(t *testing.T) {
	a := &Account{Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Credentials: map[string]any{"base_url": cpapolicy.BaseURL}, Status: StatusActive, Schedulable: true}
	require.True(t, a.IsSchedulable())
	a.Type = AccountTypeOAuth
	require.False(t, a.IsSchedulable())
	require.False(t, a.IsCredentialUsableForShadow())
	a.Type = AccountTypeAPIKey
	a.Credentials["base_url"] = "https://api.openai.com"
	require.False(t, a.IsSchedulable())
	a.Credentials["base_url"] = cpapolicy.BaseURL
	proxy := int64(1)
	a.ProxyID = &proxy
	require.False(t, a.IsSchedulable())
}

func TestCPAAuthSelectionFromMultipleCredentials(t *testing.T) {
	files := []openAIQuotaBridgeAuthFile{{Name: "unrelated.json"}, {Name: "expected.json", AuthIndex: "correct"}}
	got, err := matchingCPAAuth(files, "expected.json")
	require.NoError(t, err)
	require.Equal(t, "correct", got.AuthIndex)
	_, err = matchingCPAAuth(files, "missing.json")
	require.Error(t, err)
	files = append(files, files[1])
	_, err = matchingCPAAuth(files, "expected.json")
	require.Error(t, err)
}
