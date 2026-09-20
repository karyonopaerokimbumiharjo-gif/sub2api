package service

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCPABridgeCandidatesExplicitAuth(t *testing.T) {
	ready := openAIQuotaBridgeAuthFile{Name: "chosen.json", Email: "chosen@example.invalid", Provider: "codex", Status: "active", AuthIndex: "idx"}
	ready.IDToken.ChatGPTAccountID = "account-id"
	stopped := ready
	stopped.Name = "disabled.json"
	stopped.Disabled = true
	require.True(t, cpaBridgeCandidate(ready).CanBridge)
	require.False(t, cpaBridgeCandidate(stopped).CanBridge)
	incomplete := ready
	incomplete.AuthIndex = ""
	require.False(t, cpaBridgeCandidate(incomplete).CanBridge)
	wrongProvider := ready
	wrongProvider.Provider = "claude"
	require.False(t, cpaBridgeCandidate(wrongProvider).CanBridge)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v0/management/auth-files":
			_ = json.NewEncoder(w).Encode(openAIQuotaBridgeAuthFilesResponse{Files: []openAIQuotaBridgeAuthFile{stopped, ready}})
		case "/v0/management/api-keys":
			_ = json.NewEncoder(w).Encode(openAIQuotaBridgeAPIKeysResponse{Keys: []string{"synthetic-key"}})
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	secret := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(secret, []byte("synthetic-management"), 0600))
	t.Setenv(openAIQuotaBridgeManagementURLKey, server.URL)
	t.Setenv(openAIQuotaBridgeManagementPasswordFileKey, secret)
	s := &OpenAIQuotaService{}
	for _, name := range []string{"", "missing.json", "disabled.json"} {
		_, err := s.PrepareCPABridgeProvisioning(context.Background(), name)
		require.Error(t, err)
	}
	result, err := s.PrepareCPABridgeProvisioning(context.Background(), "chosen.json")
	require.NoError(t, err)
	require.Equal(t, "chosen.json", result.AuthName)
	require.Equal(t, "synthetic-key", result.APIKey)
	candidates, err := s.ListCPABridgeCandidates(context.Background())
	require.NoError(t, err)
	require.Len(t, candidates, 2)
	raw, err := json.Marshal(candidates)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "synthetic-key")
}
