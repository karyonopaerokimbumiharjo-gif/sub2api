package admin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

type piImportAdminStub struct {
	service.AdminService
	owner       service.User
	group       service.Group
	accounts    []service.Account
	created     *service.CreateAccountInput
	listMembers []service.Account
	createErr   error
}

func (s *piImportAdminStub) GetUser(context.Context, int64) (*service.User, error) {
	return &s.owner, nil
}
func (s *piImportAdminStub) GetGroup(context.Context, int64) (*service.Group, error) {
	return &s.group, nil
}
func (s *piImportAdminStub) ListAccountsForSchedulerScoreFilter(_ context.Context, _, _, _, _ string, groupID int64, _ string) ([]service.Account, error) {
	if groupID != 0 {
		return s.listMembers, nil
	}
	return s.accounts, nil
}
func (s *piImportAdminStub) CreateAccount(_ context.Context, input *service.CreateAccountInput) (*service.Account, error) {
	s.created = input
	if s.createErr != nil {
		return nil, s.createErr
	}
	return &service.Account{ID: 81, Name: input.Name, Platform: input.Platform, Type: input.Type, Credentials: input.Credentials, Status: service.StatusActive, Schedulable: true, Concurrency: input.Concurrency}, nil
}

func piImportJWT(accountID, email string) string {
	claims, _ := json.Marshal(map[string]any{
		"email":                       email,
		"exp":                         time.Now().Add(time.Hour).Unix(),
		"https://api.openai.com/auth": map[string]any{"chatgpt_account_id": accountID},
	})
	return "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".test"
}

func piImportBody(accountID string) []byte {
	auth, _ := json.Marshal(map[string]any{
		"auth_mode": "chatgpt",
		"tokens": map[string]any{
			"access_token":  piImportJWT(accountID, "person@example.com"),
			"id_token":      piImportJWT(accountID, "person@example.com"),
			"refresh_token": "synthetic-refresh-secret",
			"account_id":    accountID,
		},
	})
	body, _ := json.Marshal(piAuthImportRequest{Content: string(auth), OwnerUserID: 7, GroupIDs: []int64{42}})
	return body
}

func piImportRequest(t *testing.T, stub *piImportAdminStub, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	h := &OpenAIOAuthHandler{adminService: stub, openaiOAuthService: &service.OpenAIOAuthService{}}
	router.POST("/import-pi-auth", h.ImportPiAuth)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/import-pi-auth", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, req)
	return recorder
}

func TestImportPiAuthVerifiesWithRuntimeAndCreatesEnabledAccountInExistingGroup(t *testing.T) {
	const accountID = "account-fixture"
	calls := 0
	runtime := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/oauth/validate" || r.Header.Get("Authorization") == "" {
			t.Errorf("unexpected Pi runtime request")
		}
		var request struct {
			OwnerID     int64  `json:"owner_id"`
			AccountID   string `json:"account_id"`
			AccessToken string `json:"access_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.OwnerID != 7 || request.AccountID != accountID || request.AccessToken == "" {
			t.Errorf("runtime received wrong binding")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"harness_kind": "pi", "pi_owner_user_id": "7", "chatgpt_account_id": accountID})
	}))
	defer runtime.Close()
	secretPath := filepath.Join(t.TempDir(), "pi-secret")
	if err := os.WriteFile(secretPath, []byte(strings.Repeat("s", 40)), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PI_RUNTIME_URL", runtime.URL)
	t.Setenv("PI_RUNTIME_SECRET_FILE", secretPath)
	stub := &piImportAdminStub{
		owner:       service.User{ID: 7, Status: service.StatusActive},
		group:       service.Group{ID: 42, Platform: service.PlatformOpenAI, Status: service.StatusActive},
		accounts:    []service.Account{{ID: 1, Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey, AccountGroups: []service.AccountGroup{{GroupID: 42}}}},
		listMembers: []service.Account{{ID: 1, Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey}},
	}
	recorder := piImportRequest(t, stub, piImportBody(accountID))
	if recorder.Code != http.StatusOK || calls != 1 || stub.created == nil {
		t.Fatalf("expected verified Pi account, status=%d calls=%d body=%s", recorder.Code, calls, recorder.Body.String())
	}
	if stub.created.InitiallyDisabled || stub.created.InitiallyUnschedulable || stub.created.Concurrency != 10 || !stub.created.SkipDefaultGroupBind || len(stub.created.GroupIDs) != 1 || stub.created.GroupIDs[0] != 42 {
		t.Fatalf("unsafe initial Pi account options: %#v", stub.created)
	}
	if stub.created.Credentials["refresh_token"] != "synthetic-refresh-secret" || stub.created.Credentials["pi_owner_user_id"] != "7" {
		t.Fatal("original credential or owner was not stored")
	}
	if strings.Contains(recorder.Body.String(), "synthetic-refresh-secret") || strings.Contains(recorder.Body.String(), piImportJWT(accountID, "person@example.com")) {
		t.Fatal("response disclosed an OAuth secret")
	}
}

func TestImportPiAuthRejectsMismatchedIdentity(t *testing.T) {
	stub := &piImportAdminStub{owner: service.User{ID: 7, Status: service.StatusActive, AllowedGroups: []int64{42}}, group: service.Group{ID: 42, Platform: service.PlatformOpenAI, Status: service.StatusActive, IsExclusive: true}}
	body := piImportBody("different")
	var request piAuthImportRequest
	if err := json.Unmarshal(body, &request); err != nil {
		t.Fatal(err)
	}
	var auth map[string]any
	if err := json.Unmarshal([]byte(request.Content), &auth); err != nil {
		t.Fatal(err)
	}
	auth["tokens"].(map[string]any)["account_id"] = "mismatch"
	bad, _ := json.Marshal(auth)
	request.Content = string(bad)
	body, _ = json.Marshal(request)
	if got := piImportRequest(t, stub, body); got.Code != http.StatusBadRequest || stub.created != nil {
		t.Fatalf("mismatched identity accepted: %d", got.Code)
	}
}

func TestImportPiAuthRejectsDuplicateIdentityBeforeRefresh(t *testing.T) {
	stub := &piImportAdminStub{
		owner: service.User{ID: 7, Status: service.StatusActive, AllowedGroups: []int64{42}}, group: service.Group{ID: 42, Platform: service.PlatformOpenAI, Status: service.StatusActive, IsExclusive: true},
		accounts: []service.Account{{Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth, Credentials: map[string]any{"harness_kind": "pi", "pi_owner_user_id": "7", "chatgpt_account_id": "account-fixture"}}},
	}
	if got := piImportRequest(t, stub, piImportBody("account-fixture")); got.Code != http.StatusConflict || stub.created != nil {
		t.Fatalf("duplicate Pi identity accepted: %d", got.Code)
	}
}

func TestCreatePiAccountOAuthPathAllowsExistingGroupsAndDefaultsToTenConcurrent(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "pi-secret")
	if err := os.WriteFile(secretPath, []byte(strings.Repeat("s", 40)), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PI_RUNTIME_SECRET_FILE", secretPath)
	calls, acks := 0, 0
	runtime := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/ack" {
			acks++
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "saved"})
			return
		}
		calls++
		if r.URL.Path != "/oauth/complete" {
			t.Errorf("unexpected runtime path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(service.OpenAITokenInfo{
			AccessToken: piImportJWT("account-oauth", ""), RefreshToken: "oauth-refresh-secret",
			ChatGPTAccountID: "account-oauth", ExpiresAt: time.Now().Add(time.Hour).Unix(),
		})
	}))
	defer runtime.Close()
	t.Setenv("PI_RUNTIME_URL", runtime.URL)
	stub := &piImportAdminStub{owner: service.User{ID: 7, Status: service.StatusActive, AllowedGroups: []int64{42}}, group: service.Group{ID: 42, Platform: service.PlatformOpenAI, Status: service.StatusActive, IsExclusive: true}}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	h := &OpenAIOAuthHandler{adminService: stub, openaiOAuthService: &service.OpenAIOAuthService{}}
	router.POST("/create-pi-account", h.CreatePiAccount)
	requestBody := `{"session_id":"fixture-session","code":"fixture-code","state":"fixture-state","pi_owner_user_id":7,"group_ids":[42]}`
	request := func() *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/create-pi-account", strings.NewReader(requestBody))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(recorder, req)
		return recorder
	}
	stub.group.Status = service.StatusDisabled
	if got := request(); got.Code != http.StatusBadRequest || calls != 0 || stub.created != nil {
		t.Fatalf("inactive group accepted by OAuth path: %d", got.Code)
	}
	stub.group.Status = service.StatusActive
	stub.group.IsExclusive = false
	stub.owner.AllowedGroups = nil
	stub.listMembers = []service.Account{{Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey}}
	stub.createErr = errors.New("synthetic database failure")
	failed := request()
	if failed.Code != http.StatusInternalServerError || acks != 0 || !strings.Contains(failed.Body.String(), "PI_ACCOUNT_SAVE_FAILED") {
		t.Fatalf("failed save must retain OAuth session and explain recovery: %d", failed.Code)
	}
	if strings.Contains(failed.Body.String(), "synthetic database failure") {
		t.Fatal("internal error leaked")
	}
	stub.createErr = nil
	calls = 0
	got := request()
	if acks != 1 {
		t.Fatal("saved account must acknowledge runtime session")
	}
	if got.Code != http.StatusOK || calls != 1 || stub.created == nil || stub.created.InitiallyDisabled || stub.created.InitiallyUnschedulable || stub.created.Concurrency != 10 {
		t.Fatalf("OAuth Pi account was not created safely: status=%d calls=%d", got.Code, calls)
	}
	if strings.Contains(got.Body.String(), "oauth-refresh-secret") {
		t.Fatal("OAuth Pi response disclosed a refresh token")
	}
}
