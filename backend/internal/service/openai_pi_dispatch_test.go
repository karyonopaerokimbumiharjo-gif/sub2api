package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type nativePiDispatchRepo struct {
	schedulerTestOpenAIAccountRepo
	owner *Account
}

func (r *nativePiDispatchRepo) GetByID(ctx context.Context, id int64) (*Account, error) {
	if r.owner != nil && r.owner.ID == id {
		return r.owner, nil
	}
	return r.schedulerTestOpenAIAccountRepo.GetByID(ctx, id)
}

func (r *nativePiDispatchRepo) SetTempUnschedulable(_ context.Context, id int64, until time.Time, reason string) error {
	if r.owner == nil || r.owner.ID != id {
		return errors.New("unexpected credential owner")
	}
	r.owner.TempUnschedulableUntil = &until
	r.owner.TempUnschedulableReason = reason
	return nil
}

func nativePiDispatchFixture() (*Account, *Account) {
	owner := nativePiAccount()
	owner.Status, owner.Schedulable, owner.Concurrency = StatusActive, true, 4
	owner.Credentials["expires_at"] = time.Now().Add(time.Hour).Format(time.RFC3339)
	alias := nativePiAccount()
	alias.ID, alias.Status, alias.Schedulable, alias.Concurrency = 8, StatusActive, true, 4
	alias.Credentials["harness_kind"] = PiSharedHarnessKind
	alias.Credentials[PiRuntimeAccountIDCredential] = "7"
	delete(alias.Credentials, "access_token")
	delete(alias.Credentials, "refresh_token")
	return owner, alias
}

func TestNativePiSharedDispatchHealthDoesNotBlockManagementRepair(t *testing.T) {
	for _, state := range []string{"healthy", "expired_refreshable", "cooldown", "error", "disabled", "paused", "runtime_blocked", "missing", "identity_mismatch"} {
		t.Run(state, func(t *testing.T) {
			owner, alias := nativePiDispatchFixture()
			repo := &nativePiDispatchRepo{owner: owner}
			svc := &OpenAIGatewayService{accountRepo: repo}
			switch state {
			case "expired_refreshable":
				owner.Credentials["expires_at"] = time.Now().Add(-time.Hour).Format(time.RFC3339)
			case "cooldown":
				until := time.Now().Add(time.Hour)
				owner.TempUnschedulableUntil = &until
			case "error":
				owner.Status = StatusError
			case "disabled":
				owner.Status = StatusDisabled
			case "paused":
				owner.Schedulable = false
			case "runtime_blocked":
				svc.BlockAccountScheduling(owner, time.Now().Add(time.Hour), "oauth_401")
			case "missing":
				repo.owner = nil
			case "identity_mismatch":
				alias.Credentials["chatgpt_account_id"] = "another-account"
			}
			resolved, err := svc.resolveNativePiDispatchAccount(context.Background(), alias)
			if state == "healthy" || state == "expired_refreshable" {
				require.NoError(t, err)
				require.Same(t, owner, resolved)
			} else {
				require.ErrorIs(t, err, errNativePiDispatchUnavailable)
				require.Nil(t, resolved)
				require.True(t, svc.isOpenAIAccountRequestRuntimeBlocked(alias, "gpt-6-astra", false))
			}
			// Reading a disabled/cooling credential for repair must still work.
			managed, managementErr := ResolveNativePiRuntimeAccount(context.Background(), repo, alias)
			if state == "missing" || state == "identity_mismatch" {
				require.Error(t, managementErr)
			} else {
				require.NoError(t, managementErr)
				require.Same(t, owner, managed)
			}
			require.Equal(t, StatusActive, alias.Status)
			require.True(t, alias.Schedulable)
		})
	}
}

func TestNativePiSharedOwner401EscapesStickyAndDispatchesHealthyCredential(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, advanced := range []bool{false, true} {
		name := "legacy"
		if advanced {
			name = "advanced"
		}
		t.Run(name, func(t *testing.T) {
			resetOpenAIAdvancedSchedulerSettingCacheForTest()
			t.Cleanup(resetOpenAIAdvancedSchedulerSettingCacheForTest)
			owner, alias := nativePiDispatchFixture()
			fallback := nativePiAccount()
			fallback.ID, fallback.Status, fallback.Schedulable, fallback.Concurrency, fallback.Priority = 11, StatusActive, true, 4, 1
			fallback.Credentials["chatgpt_account_id"] = "fallback-account"
			fallback.Credentials["access_token"] = "fallback-access"
			fallback.Credentials["expires_at"] = time.Now().Add(time.Hour).Format(time.RFC3339)
			repo := &nativePiDispatchRepo{owner: owner, schedulerTestOpenAIAccountRepo: schedulerTestOpenAIAccountRepo{accounts: []Account{*alias, *fallback}}}
			cfg := &config.Config{}
			rateLimits := NewRateLimitService(repo, nil, cfg, nil, nil)
			rateLimits.settingService = newOpenAIAdvancedSchedulerRateLimitService(map[bool]string{false: "false", true: "true"}[advanced]).settingService
			cache := &schedulerTestGatewayCache{}
			svc := &OpenAIGatewayService{cfg: cfg, accountRepo: repo, cache: cache, rateLimitService: rateLimits, concurrencyService: NewConcurrencyService(schedulerTestConcurrencyCache{}), toolCorrector: NewCodexToolCorrector(), openAITokenProvider: NewOpenAITokenProvider(repo, nil, nil)}
			rateLimits.SetAccountRuntimeBlocker(svc)
			groupID := int64(9)
			require.NoError(t, svc.BindStickySession(context.Background(), &groupID, "shared-sticky", alias.ID))
			var lastStickyHit bool
			selectAccount := func() *AccountSelectionResult {
				selection, decision, err := svc.SelectAccountWithSchedulerForCapability(context.Background(), &groupID, "", "shared-sticky", "gpt-6-astra", nil, OpenAIUpstreamTransportAny, OpenAIEndpointCapabilityChatCompletions, false, false, true, PlatformOpenAI)
				require.NoError(t, err)
				require.NotNil(t, selection)
				lastStickyHit = decision.StickySessionHit
				t.Cleanup(func() {
					if selection.ReleaseFunc != nil {
						selection.ReleaseFunc()
					}
				})
				return selection
			}
			require.Equal(t, alias.ID, selectAccount().Account.ID)
			require.True(t, lastStickyHit, "the fixture must exercise actual sticky selection")
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
			c.Set("api_key", nativePiTestKey(42))
			resp := &http.Response{StatusCode: http.StatusUnauthorized, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"error":"pi_upstream_authorization_rejected"}`))}
			err := svc.nativePiAuthorizationFailover(context.Background(), c, alias, resp, "gpt-6-astra")
			var failed *UpstreamFailoverError
			require.ErrorAs(t, err, &failed)
			require.NotNil(t, owner.TempUnschedulableUntil)
			require.False(t, c.Writer.Written())
			selection := selectAccount()
			require.Equal(t, fallback.ID, selection.Account.ID, "sticky alias must not bypass its credential owner's 401 cooldown")
			require.NotEqual(t, alias.ID, cache.sessionBindings[svc.openAISessionCacheKey("shared-sticky")])
			_, err = svc.resolveNativePiDispatchAccount(context.Background(), alias)
			require.ErrorIs(t, err, errNativePiDispatchUnavailable)

			var mu sync.Mutex
			var dispatched []int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var payload struct {
					CredentialID int64 `json:"credential_id"`
				}
				_ = json.NewDecoder(r.Body).Decode(&payload)
				mu.Lock()
				dispatched = append(dispatched, payload.CredentialID)
				mu.Unlock()
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: "+`{"type":"response.completed","response":{"id":"resp_shared_fallback","object":"response","status":"completed","model":"gpt-6-astra","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"HEALTHY_OWNER_OK"}]}],"usage":{"input_tokens":3,"output_tokens":2}}}`+"\n\n")
			}))
			defer server.Close()
			secret := filepath.Join(t.TempDir(), "secret")
			require.NoError(t, os.WriteFile(secret, []byte(strings.Repeat("s", 40)), 0600))
			t.Setenv("PI_RUNTIME_URL", server.URL)
			t.Setenv("PI_RUNTIME_SECRET_FILE", secret)
			_, err = svc.Forward(context.Background(), c, selection.Account, []byte(`{"model":"gpt-6-astra","input":"benign fixture","stream":true}`))
			require.NoError(t, err)
			require.Contains(t, w.Body.String(), "HEALTHY_OWNER_OK")
			mu.Lock()
			got := append([]int64(nil), dispatched...)
			mu.Unlock()
			require.Equal(t, []int64{fallback.ID}, got, "the failed owner must receive no follow-up request")

			owner.TempUnschedulableUntil = nil
			svc.ClearAccountSchedulingBlock(owner.ID)
			require.NoError(t, svc.BindStickySession(context.Background(), &groupID, "shared-sticky", alias.ID))
			require.Equal(t, alias.ID, selectAccount().Account.ID, "repaired owner must make its alias available again")
			require.True(t, lastStickyHit)
		})
	}
}
