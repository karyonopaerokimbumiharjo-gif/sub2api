package admin

import (
	"context"
	"errors"
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

type completeImportAdmin struct {
	service.AdminService
	repo                       *cpaSyncHandlerAccountRepo
	groupInvalid, scheduleFail bool
}

func (s *completeImportAdmin) GetGroup(context.Context, int64) (*service.Group, error) {
	if s.groupInvalid {
		return nil, errors.New("invalid group")
	}
	return &service.Group{ID: 42, Platform: service.PlatformOpenAI, Status: service.StatusActive}, nil
}
func (s *completeImportAdmin) GetAccount(context.Context, int64) (*service.Account, error) {
	return s.repo.account, nil
}
func (s *completeImportAdmin) UpdateAccount(_ context.Context, _ int64, input *service.UpdateAccountInput) (*service.Account, error) {
	s.repo.account.GroupIDs = append([]int64(nil), (*input.GroupIDs)...)
	s.repo.account.Status = input.Status
	return s.repo.account, nil
}
func (s *completeImportAdmin) SetAccountSchedulable(_ context.Context, _ int64, enabled bool) (*service.Account, error) {
	if s.scheduleFail {
		return nil, errors.New("scheduling unavailable")
	}
	s.repo.account.Schedulable = enabled
	return s.repo.account, nil
}

func TestAccountImportCompletesBeforeSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v0/management/auth-files":
			_, _ = w.Write([]byte(`{"files":[{"id":"auth-91","name":"canary.json","provider":"codex","email":"canary@example.invalid","id_token":{"chatgpt_account_id":"workspace-91"}}]}`))
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
	for _, tc := range []struct {
		name                       string
		invalidGroup, failSchedule bool
		status                     int
	}{
		{"complete", false, false, http.StatusOK},
		{"invalid group before import", true, false, http.StatusBadRequest},
		{"no success before scheduling", false, true, http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &cpaSyncHandlerAccountRepo{}
			importer := &cpaImportOnlyStub{}
			admin := &completeImportAdmin{repo: repo, groupInvalid: tc.invalidGroup, scheduleFail: tc.failSchedule}
			h := &OpenAIOAuthHandler{cpaImportService: importer, adminService: admin, cpaRuntimeService: service.NewOpenAIQuotaService(repo, nil, nil, nil, nil)}
			router := gin.New()
			router.POST("/import", h.ImportOAuthToCPA)
			req := httptest.NewRequest(http.MethodPost, "/import", strings.NewReader(`{"credentials":{"access_token":"synthetic-access"},"group_ids":[42]}`))
			req.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)
			require.Equal(t, tc.status, response.Code, response.Body.String())
			require.NotContains(t, response.Body.String(), "private-test-key")
			if tc.invalidGroup {
				require.Zero(t, importer.calls)
				require.Nil(t, repo.account)
				return
			}
			require.Equal(t, 1, importer.calls)
			if tc.failSchedule {
				require.NotContains(t, response.Body.String(), "account_ids")
				return
			}
			require.Contains(t, response.Body.String(), `"account_ids":[91]`)
			require.Equal(t, []int64{42}, repo.account.GroupIDs)
			require.True(t, repo.account.Schedulable)
			require.Equal(t, service.StatusActive, repo.account.Status)
		})
	}
}
