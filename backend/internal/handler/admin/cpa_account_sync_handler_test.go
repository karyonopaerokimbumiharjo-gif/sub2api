package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type cpaSyncHandlerAccountRepo struct {
	service.AccountRepository
	account *service.Account
}

func (r *cpaSyncHandlerAccountRepo) FindByExtraField(context.Context, string, any) ([]service.Account, error) {
	return nil, nil
}

func (r *cpaSyncHandlerAccountRepo) Create(_ context.Context, account *service.Account) error {
	r.account = account
	account.ID = 91
	return nil
}

func TestSyncCPAAccountsHandlerCreatesVisibleButInactiveBusinessAccount(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v0/management/auth-files":
			_, _ = w.Write([]byte(`{"files":[{"id":"auth-91","name":"one.json","provider":"codex","email":"one@example.com","id_token":{"chatgpt_account_id":"workspace-91"}}]}`))
		case "/v0/management/auth-files/download":
			_, _ = w.Write([]byte(`{"account_id":"workspace-91"}`))
		case "/v0/management/api-keys":
			_, _ = w.Write([]byte(`{"api-keys":["private-test-key"]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	secret := filepath.Join(t.TempDir(), "management-secret")
	require.NoError(t, os.WriteFile(secret, []byte("test-secret"), 0o600))
	t.Setenv("OPENAI_QUOTA_BRIDGE_MANAGEMENT_URL", server.URL)
	t.Setenv("OPENAI_QUOTA_BRIDGE_MANAGEMENT_PASSWORD_FILE", secret)

	repo := &cpaSyncHandlerAccountRepo{}
	handler := &OpenAIOAuthHandler{cpaRuntimeService: service.NewOpenAIQuotaService(repo, nil, nil, nil)}
	router := gin.New()
	router.POST("/admin/openai/cpa/sync-accounts", handler.SyncCPAAccounts)
	request := httptest.NewRequest(http.MethodPost, "/admin/openai/cpa/sync-accounts", strings.NewReader(`{"auth_names":["one.json"]}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), `"created":1`)
	require.NotContains(t, response.Body.String(), "private-test-key")
	require.NotNil(t, repo.account)
	require.Equal(t, service.StatusDisabled, repo.account.Status)
	require.False(t, repo.account.Schedulable)
	require.Empty(t, repo.account.GroupIDs)
	require.Equal(t, "auth-91", repo.account.GetExtraString("cpa_auth_id"))
}
