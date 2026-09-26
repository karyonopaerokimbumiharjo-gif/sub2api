package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

type cpaLifecycleReferences struct{ accounts []Account }

func (r cpaLifecycleReferences) FindByExtraField(_ context.Context, key string, value any) ([]Account, error) {
	var found []Account
	for _, account := range r.accounts {
		if account.Extra[key] == value {
			found = append(found, account)
		}
	}
	return found, nil
}

func TestCPAAccountLifecycleUsesExactBoundAuth(t *testing.T) {
	ctx := context.Background()
	disabled := false
	deleted := false
	statusWrites := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v0/management/auth-files":
			files := []any{map[string]any{"id": "other-id", "auth_index": "other-index", "name": "other.json", "provider": "codex", "email": "other@example.com", "disabled": false}}
			if !deleted {
				files = append(files, map[string]any{"id": "bound-id", "auth_index": "bound-index", "name": "bound.json", "provider": "codex", "email": "bound@example.com", "disabled": disabled})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"files": files})
		case r.Method == http.MethodPatch && r.URL.Path == "/v0/management/auth-files/status":
			var body struct {
				Name      string `json:"name"`
				AuthIndex string `json:"auth_index"`
				Disabled  bool   `json:"disabled"`
			}
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			require.Equal(t, "bound.json", body.Name)
			require.Equal(t, "bound-index", body.AuthIndex)
			disabled = body.Disabled
			statusWrites++
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/v0/management/auth-files":
			require.Equal(t, "bound.json", r.URL.Query().Get("name"))
			deleted = true
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	secret := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(secret, []byte("test-secret"), 0600))
	t.Setenv(openAIQuotaBridgeManagementURLKey, server.URL)
	t.Setenv(openAIQuotaBridgeManagementPasswordFileKey, secret)

	account := &Account{ID: 41, Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Extra: map[string]any{"cpa_auth_id": "bound-id"}}
	require.NoError(t, setCPAAccountEnabled(ctx, account, false))
	require.True(t, disabled)
	require.Equal(t, 1, statusWrites)
	require.NoError(t, setCPAAccountEnabled(ctx, account, false))
	require.Equal(t, 1, statusWrites)
	references := cpaLifecycleReferences{accounts: []Account{*account, {ID: 42, Extra: map[string]any{"cpa_auth_id": "bound-id"}}}}
	require.NoError(t, deleteCPAAccountAuthorizations(ctx, account, references))
	require.False(t, deleted)
	references.accounts = references.accounts[:1]
	require.NoError(t, deleteCPAAccountAuthorizations(ctx, account, references))
	require.True(t, deleted)
	require.NoError(t, deleteCPAAccountAuthorizations(ctx, account, references))
}

func TestCPAAccountLifecycleIgnoresUnboundSharedBridge(t *testing.T) {
	account := &Account{ID: 1, Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Extra: map[string]any{OpenAIQuotaBridgeAuthNameExtraKey: "bound.json"}}
	require.NoError(t, setCPAAccountEnabled(context.Background(), account, false))
	require.NoError(t, deleteCPAAccountAuthorizations(context.Background(), account, nil))
}
