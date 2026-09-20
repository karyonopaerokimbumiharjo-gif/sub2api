package admin

import (
	"context"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"strings"
	"testing"
)

type bridgeAdminStub struct {
	service.AdminService
	accounts []service.Account
	creates  int
	updates  int
}

func (s *bridgeAdminStub) ListAccountsForSchedulerScoreFilter(context.Context, string, string, string, string, int64, string) ([]service.Account, error) {
	return s.accounts, nil
}
func (s *bridgeAdminStub) GetGroup(context.Context, int64) (*service.Group, error) {
	return &service.Group{ID: 2, Name: "pro", Platform: "openai", Status: "active"}, nil
}
func (s *bridgeAdminStub) GetAllGroupsByPlatform(context.Context, string) ([]service.Group, error) {
	return []service.Group{{ID: 2, Name: "pro", Platform: "openai", Status: "active"}}, nil
}
func (s *bridgeAdminStub) CreateAccount(_ context.Context, in *service.CreateAccountInput) (*service.Account, error) {
	s.creates++
	a := service.Account{ID: 32, Name: in.Name, Platform: in.Platform, Type: in.Type, Credentials: in.Credentials, Extra: in.Extra, GroupIDs: in.GroupIDs}
	s.accounts = []service.Account{a}
	return &a, nil
}
func (s *bridgeAdminStub) UpdateAccount(_ context.Context, id int64, in *service.UpdateAccountInput) (*service.Account, error) {
	s.updates++
	a := &s.accounts[0]
	a.Extra = in.Extra
	a.GroupIDs = *in.GroupIDs
	return a, nil
}

type bridgeProvisionStub struct{ selected string }

func (s *bridgeProvisionStub) ListCPABridgeCandidates(context.Context) ([]service.CPABridgeCandidate, error) {
	return []service.CPABridgeCandidate{{Name: "selected.json", Email: "chosen@example.invalid", CanBridge: true}}, nil
}
func (s *bridgeProvisionStub) PrepareCPABridgeProvisioning(_ context.Context, n string) (*service.CPABridgeProvisioning, error) {
	s.selected = n
	return &service.CPABridgeProvisioning{AuthName: n, Email: "chosen@example.invalid", APIKey: "synthetic-private-key"}, nil
}
func TestCPABridgeExplicitSelectionAndGroups(t *testing.T) {
	gin.SetMode(gin.TestMode)
	a := &bridgeAdminStub{}
	p := &bridgeProvisionStub{}
	h := &OpenAIOAuthHandler{adminService: a, cpaBridgeService: p}
	call := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("POST", "/", strings.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		h.EnsureCPAQuotaBridge(c)
		return w
	}
	for _, body := range []string{`{}`, `{"auth_name":"selected.json"}`, `{"group_ids":[2]}`} {
		require.Equal(t, 400, call(body).Code)
	}
	require.Zero(t, a.creates)
	for i := 0; i < 2; i++ {
		w := call(`{"auth_name":"selected.json","group_ids":[2]}`)
		require.Equal(t, 200, w.Code, w.Body.String())
		require.NotContains(t, w.Body.String(), "synthetic-private-key")
	}
	require.Equal(t, "selected.json", p.selected)
	require.Equal(t, 1, a.creates)
	require.Equal(t, 1, a.updates)
	require.Equal(t, []int64{2}, a.accounts[0].GroupIDs)
	a.accounts[0].Extra["unrelated_setting"] = true
	require.Equal(t, 200, call(`{"auth_name":"other.json","group_ids":[2]}`).Code)
	require.Equal(t, true, a.accounts[0].Extra["unrelated_setting"])
	require.Equal(t, "other.json", a.accounts[0].GetExtraString(service.OpenAIQuotaBridgeAuthNameExtraKey))
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)
	h.CPABridgeOptions(c)
	require.Equal(t, 200, w.Code)
	require.Contains(t, w.Body.String(), "chosen@example.invalid")
	require.NotContains(t, w.Body.String(), "synthetic-private-key")
}
