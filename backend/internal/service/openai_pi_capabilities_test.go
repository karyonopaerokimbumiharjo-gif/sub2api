//go:build unit

package service

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPiSchedulerHonorsNativeCapabilities(t *testing.T) {
	a := nativePiAccount()
	a.Extra = map[string]any{"openai_compact_mode": "force_on"}
	require.False(t, a.AllowsOpenAICompact())
	require.True(t, a.SupportsOpenAIEndpointCapability(OpenAIEndpointCapabilityResponses))
	require.True(t, a.SupportsOpenAIEndpointCapability(OpenAIEndpointCapabilityResponsesText))
	require.True(t, a.SupportsOpenAIEndpointCapability(OpenAIEndpointCapabilityChatCompletions))
	for _, endpoint := range []OpenAIEndpointCapability{OpenAIEndpointCapabilityLive, OpenAIEndpointCapabilityAlphaSearch, OpenAIEndpointCapabilityEmbeddings} {
		require.False(t, a.SupportsOpenAIEndpointCapability(endpoint), string(endpoint))
	}
	require.False(t, a.SupportsOpenAIImageCapability(OpenAIImagesCapabilityBasic))
	require.False(t, a.SupportsOpenAIImageCapability(OpenAIImagesCapabilityNative))
}

func TestManualPiRefreshDoesNotRotateAChangedCredential(t *testing.T) {
	a := nativePiAccount()
	r := &manualPiRefresh{access: a.GetOpenAIAccessToken(), refresh: a.GetOpenAIRefreshToken()}
	require.True(t, r.NeedsRefresh(a, 0))
	a.Credentials["access_token"] = "rotated-access"
	require.False(t, r.NeedsRefresh(a, 0))
}

func TestManualPiRefreshPersistsBeforeReturningAndReusesRotation(t *testing.T) {
	account := nativePiAccount()
	account.Status = StatusActive
	repo := &refreshAPIAccountRepo{account: account}
	svc := &OpenAIOAuthService{refreshAPI: NewOAuthRefreshAPI(repo, nil)}
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		require.Equal(t, "/oauth/refresh", r.URL.Path)
		_ = json.NewEncoder(w).Encode(OpenAITokenInfo{HarnessKind: "pi", PiOwnerUserID: "42", ChatGPTAccountID: "fixture-account", AccessToken: "rotated", RefreshToken: "rotated-refresh", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	}))
	defer server.Close()
	file := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(file, []byte(strings.Repeat("x", 40)), 0600))
	t.Setenv("PI_RUNTIME_URL", server.URL)
	t.Setenv("PI_RUNTIME_SECRET_FILE", file)
	original := snapshotOAuthRefreshAccount(account)
	updated, err := svc.RefreshPiAccount(context.Background(), original)
	require.NoError(t, err)
	require.Equal(t, "rotated", updated.GetOpenAIAccessToken())
	require.Equal(t, 1, repo.updateCredentialsCalls)
	again, err := svc.RefreshPiAccount(context.Background(), original)
	require.NoError(t, err)
	require.Equal(t, "rotated-refresh", again.GetOpenAIRefreshToken())
	require.Equal(t, 1, calls, "a stale duplicate click must reuse the durable rotation")
	require.Equal(t, 1, repo.updateCredentialsCalls)
}
