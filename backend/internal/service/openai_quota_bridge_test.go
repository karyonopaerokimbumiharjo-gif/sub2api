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

	"github.com/stretchr/testify/require"
)

func TestOpenAIQuotaBridgeQueryAndResetUseBoundCPAAuth(t *testing.T) {
	const (
		managementSecret = "test-management-secret"
		authName         = "codex-bound-account.json"
		authEmail        = "bound@example.com"
		authIndex        = "stable-auth-index"
		chatGPTAccountID = "chatgpt-account-bound"
	)

	var upstreamCalls []openAIQuotaBridgeAPICallRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer "+managementSecret, r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v0/management/auth-files":
			require.Equal(t, authName, r.URL.Query().Get("name"))
			_, _ = w.Write([]byte(`{"files":[{"id":"auth-id","auth_index":"` + authIndex + `","name":"` + authName + `","provider":"codex","email":"` + authEmail + `","status":"active","disabled":false,"unavailable":false,"id_token":{"chatgpt_account_id":"` + chatGPTAccountID + `"}}]}`))
		case "/v0/management/api-call":
			var request openAIQuotaBridgeAPICallRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
			require.Equal(t, authIndex, request.AuthIndex)
			require.Equal(t, "Bearer $TOKEN$", request.Header["authorization"])
			require.Equal(t, chatGPTAccountID, request.Header["chatgpt-account-id"])
			upstreamCalls = append(upstreamCalls, request)

			var body string
			switch request.URL {
			case chatGPTUsageURL:
				body = `{"account_id":"` + chatGPTAccountID + `","plan_type":"pro","rate_limit":{"allowed":true,"limit_reached":false,"primary_window":{"used_percent":12,"limit_window_seconds":18000,"reset_after_seconds":300}}}`
			case chatGPTRateLimitCreditsURL:
				body = `{"available_count":2,"credits":[{"reset_type":"codex_rate_limits","status":"available","expires_at":"2099-09-01T01:00:00Z"},{"reset_type":"codex_rate_limits","status":"available","expires_at":"2099-09-02T01:00:00Z"}]}`
			case chatGPTRateLimitResetURL:
				require.Equal(t, http.MethodPost, request.Method)
				require.Contains(t, request.Data, "redeem_request_id")
				body = `{"code":"ok","windows_reset":2,"credit":{"status":"redeemed"}}`
			default:
				t.Fatalf("unexpected upstream URL %q", request.URL)
			}
			encodedBody, err := json.Marshal(body)
			require.NoError(t, err)
			_, _ = w.Write([]byte(`{"status_code":200,"header":{},"body":` + string(encodedBody) + `}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	secretFile := filepath.Join(t.TempDir(), "management-password")
	require.NoError(t, os.WriteFile(secretFile, []byte(managementSecret+"\n"), 0o600))
	t.Setenv(openAIQuotaBridgeManagementURLKey, server.URL)
	t.Setenv(openAIQuotaBridgeManagementPasswordFileKey, secretFile)

	account := newOpenAIQuotaBridgeTestAccount(301, server.URL, authName, authEmail)
	repo := &stubQuotaAccountRepo{accounts: map[int64]*Account{account.ID: account}}
	service := &OpenAIQuotaService{accountRepo: repo}

	usage, err := service.QueryUsage(context.Background(), account.ID)
	require.NoError(t, err)
	require.Equal(t, chatGPTAccountID, usage.AccountID)
	require.Equal(t, "pro", usage.PlanType)
	require.NotNil(t, usage.RateLimitResetCredits)
	require.Equal(t, 2, usage.RateLimitResetCredits.AvailableCount)
	require.Len(t, usage.RateLimitResetCredits.Credits, 2)
	require.NotZero(t, usage.FetchedAt)

	reset, err := service.ResetCredit(context.Background(), account.ID)
	require.NoError(t, err)
	require.Equal(t, "ok", reset.Code)
	require.Equal(t, 2, reset.WindowsReset)
	require.Len(t, upstreamCalls, 3)
	require.Equal(t, []string{chatGPTUsageURL, chatGPTRateLimitCreditsURL, chatGPTRateLimitResetURL}, []string{
		upstreamCalls[0].URL,
		upstreamCalls[1].URL,
		upstreamCalls[2].URL,
	})
}

func TestOpenAIQuotaBridgeRejectsMismatchedEmail(t *testing.T) {
	const managementSecret = "test-management-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v0/management/auth-files", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"files":[{"id":"auth-id","auth_index":"auth-index","name":"bound.json","provider":"codex","email":"other@example.com","status":"active","id_token":{"chatgpt_account_id":"account-id"}}]}`))
	}))
	defer server.Close()

	secretFile := filepath.Join(t.TempDir(), "management-password")
	require.NoError(t, os.WriteFile(secretFile, []byte(managementSecret), 0o600))
	t.Setenv(openAIQuotaBridgeManagementURLKey, server.URL)
	t.Setenv(openAIQuotaBridgeManagementPasswordFileKey, secretFile)

	account := newOpenAIQuotaBridgeTestAccount(302, server.URL, "bound.json", "expected@example.com")
	service := &OpenAIQuotaService{accountRepo: &stubQuotaAccountRepo{accounts: map[int64]*Account{account.ID: account}}}

	_, err := service.QueryUsage(context.Background(), account.ID)
	require.Error(t, err)
	require.Contains(t, err.Error(), "email does not match")
}

func TestOpenAIQuotaBridgeRejectsManagementOriginMismatch(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "management-password")
	require.NoError(t, os.WriteFile(secretFile, []byte("secret"), 0o600))
	t.Setenv(openAIQuotaBridgeManagementURLKey, "http://cpa.internal:8317")
	t.Setenv(openAIQuotaBridgeManagementPasswordFileKey, secretFile)

	account := newOpenAIQuotaBridgeTestAccount(303, "http://different.internal:8317", "bound.json", "bound@example.com")
	service := &OpenAIQuotaService{accountRepo: &stubQuotaAccountRepo{accounts: map[int64]*Account{account.ID: account}}}

	_, err := service.QueryUsage(context.Background(), account.ID)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match")
}

func TestReadOpenAIQuotaBridgeManagementSecretRejectsBroadPermissions(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "management-password")
	require.NoError(t, os.WriteFile(secretFile, []byte("secret"), 0o644))

	_, err := readOpenAIQuotaBridgeManagementSecret(secretFile)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "permissions"))
}

func TestImportOAuthCredentialsToCPAReplacesMatchingBoundAuth(t *testing.T) {
	const (
		managementSecret = "test-management-secret"
		authName         = "codex-bound-account.json"
		authEmail        = "bound@example.com"
		chatGPTAccountID = "chatgpt-account-bound"
	)

	var uploaded map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer "+managementSecret, r.Header.Get("Authorization"))
		if r.URL.Path == "/v0/management/api-call" {
			_, _ = w.Write([]byte(`{"status_code":200,"body":"{}"}`))
			return
		}
		require.Equal(t, authName, r.URL.Query().Get("name"))
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodPost:
			require.NoError(t, json.NewDecoder(r.Body).Decode(&uploaded))
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case http.MethodGet:
			if r.URL.Path == "/v0/management/auth-files/download" {
				_, _ = w.Write([]byte(`{"priority":7,"weight":2,"request_retry":1,"proxy_url":"http://test-proxy:8080","sub2_proxy_id":9,"disabled":false}`))
				return
			}
			_, _ = w.Write([]byte(`{"files":[{"name":"unrelated.json"},{"id":"auth-id","auth_index":"stable-auth-index","name":"` + authName + `","provider":"codex","email":"` + authEmail + `","status":"active","disabled":false,"unavailable":false,"id_token":{"chatgpt_account_id":"` + chatGPTAccountID + `"}}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	secretFile := filepath.Join(t.TempDir(), "management-password")
	require.NoError(t, os.WriteFile(secretFile, []byte(managementSecret), 0o600))
	t.Setenv(openAIQuotaBridgeManagementURLKey, server.URL)
	t.Setenv(openAIQuotaBridgeManagementPasswordFileKey, secretFile)

	bridge := newOpenAIQuotaBridgeTestAccount(304, server.URL, authName, authEmail)
	quotaService := &OpenAIQuotaService{accountRepo: &stubQuotaAccountRepo{accounts: map[int64]*Account{bridge.ID: bridge}}}
	result, err := quotaService.ImportOAuthCredentialsToCPA(context.Background(), map[string]any{
		"access_token":       "access-token",
		"refresh_token":      "refresh-token",
		"id_token":           "id-token",
		"email":              authEmail,
		"chatgpt_account_id": chatGPTAccountID,
		"plan_type":          "pro",
		"expires_at":         float64(4_102_444_800),
	})

	require.NoError(t, err)
	require.Equal(t, authName, result.AuthName)
	require.Equal(t, bridge.ID, result.BridgeAccountID)
	require.True(t, result.ReplacedBoundAuth)
	require.Equal(t, "codex", uploaded["type"])
	require.Equal(t, "oauth", uploaded["auth_kind"])
	require.Equal(t, "access-token", uploaded["access_token"])
	require.Equal(t, float64(7), uploaded["priority"])
	require.Equal(t, float64(2), uploaded["weight"])
	require.Equal(t, float64(1), uploaded["request_retry"])
	require.Equal(t, "http://test-proxy:8080", uploaded["proxy_url"])
	require.Equal(t, float64(9), uploaded["sub2_proxy_id"])
	require.Equal(t, "refresh-token", uploaded["refresh_token"])
	require.Equal(t, "2100-01-01T00:00:00Z", uploaded["expired"])
}

func TestImportOAuthCredentialsToCPARejectsIncompleteCredentials(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "management-password")
	require.NoError(t, os.WriteFile(secretFile, []byte("secret"), 0o600))
	t.Setenv(openAIQuotaBridgeManagementURLKey, "http://cpa.internal:8317")
	t.Setenv(openAIQuotaBridgeManagementPasswordFileKey, secretFile)

	bridge := newOpenAIQuotaBridgeTestAccount(305, "http://cpa.internal:8317", "bound.json", "bound@example.com")
	quotaService := &OpenAIQuotaService{accountRepo: &stubQuotaAccountRepo{accounts: map[int64]*Account{bridge.ID: bridge}}}
	_, err := quotaService.ImportOAuthCredentialsToCPA(context.Background(), map[string]any{
		"access_token":       "access-token",
		"email":              "bound@example.com",
		"chatgpt_account_id": "chatgpt-account-bound",
		"expires_at":         float64(4_102_444_800),
	})

	require.Error(t, err)
	require.Contains(t, err.Error(), "incomplete")
}

func newOpenAIQuotaBridgeTestAccount(id int64, baseURL, authName, authEmail string) *Account {
	return &Account{
		ID:       id,
		Platform: PlatformOpenAI,
		Type:     AccountTypeAPIKey,
		Status:   StatusActive,
		Credentials: map[string]any{
			"base_url": baseURL,
			"api_key":  "bridge-api-key",
		},
		Extra: map[string]any{
			OpenAIQuotaViaCompatibleUpstreamExtraKey: true,
			OpenAIQuotaBridgeAuthNameExtraKey:        authName,
			OpenAIQuotaBridgeAuthEmailExtraKey:       authEmail,
		},
	}
}
