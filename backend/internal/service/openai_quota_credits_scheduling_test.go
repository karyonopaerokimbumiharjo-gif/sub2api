package service

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func creditSchedulingAccount(t *testing.T, now time.Time, body string) *Account {
	t.Helper()
	var usage OpenAIQuotaUsage
	require.NoError(t, json.Unmarshal([]byte(body), &usage))
	usage.FetchedAt = now.Unix()
	return &Account{ID: 19, Platform: PlatformOpenAI, Type: AccountTypeOAuth,
		Credentials: map[string]any{"harness_kind": PiNativeHarnessKind, "pi_owner_user_id": "1", "chatgpt_account_id": "credit-test-account", "access_token": "test-access", "refresh_token": "test-refresh"},
		Status:      StatusActive, Schedulable: true, Extra: map[string]any{
			openaiQuotaCreditsKey:   codexCreditsSnapshotFromUsage(&usage),
			"codex_5h_used_percent": 100.0, "codex_7d_used_percent": 100.0,
			"codex_usage_updated_at": now.Format(time.RFC3339),
		}}
}

func TestOpenAICreditsAllowExhaustedWindow(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name, fields string
		want         bool
	}{
		{"positive decimal", `"credits":{"has_credits":true,"balance":"0.00000000000000000001"}`, true},
		{"numeric balance", `"credits":{"balance":12.5}`, true},
		{"string remaining takes precedence", `"credits":{"remaining":"12.5","balance":"0"}`, true},
		{"numeric remaining takes precedence", `"credits":{"remaining":12.5,"balance":0}`, true},
		{"null remaining falls back to balance", `"credits":{"remaining":null,"balance":"12.5"}`, true},
		{"zero remaining does not fall back", `"credits":{"remaining":"0","balance":"12.5","has_credits":true}`, false},
		{"numeric zero remaining does not fall back", `"credits":{"remaining":0,"balance":12.5,"has_credits":true}`, false},
		{"zero remaining wins over cap", `"credits":{"remaining":"0","balance":"12.5","has_credits":true},"spend_control":{"individual_limit":{"remaining":"100"}}`, false},
		{"malformed remaining does not fall back", `"credits":{"remaining":"NaN","balance":"12.5","has_credits":true}`, false},
		{"negative remaining does not fall back", `"credits":{"remaining":-1,"balance":12.5,"has_credits":true}`, false},
		{"unlimited allows zero remaining placeholder", `"credits":{"remaining":"0","has_credits":true,"unlimited":true}`, true},
		{"unlimited allows zero balance placeholder", `"credits":{"balance":"0","unlimited":true}`, true},
		{"unlimited cannot bypass spend reached", `"credits":{"remaining":"0","unlimited":true},"spend_control":{"reached":true}`, false},
		{"unlimited cannot bypass invalid amount", `"credits":{"remaining":"NaN","unlimited":true}`, false},
		{"unlimited cannot bypass negative amount", `"credits":{"remaining":"-1","unlimited":true}`, false},
		{"unlimited", `"credits":{"unlimited":true,"balance":null}`, true},
		{"available flag without balance", `"credits":{"has_credits":true}`, true},
		{"unknown balance without availability", `"credits":{}`, false},
		{"zero", `"credits":{"balance":"0"}`, false},
		{"zero wins over available flag", `"credits":{"has_credits":true,"balance":"0"}`, false},
		{"zero wins over flag and cap", `"credits":{"has_credits":true,"balance":"0"},"spend_control":{"individual_limit":{"remaining":"100"}}`, false},
		{"positive explicit balance wins over flag", `"credits":{"has_credits":false,"balance":"1"}`, true},
		{"malformed balance wins over available flag", `"credits":{"has_credits":true,"balance":"NaN"}`, false},
		{"negative", `"credits":{"balance":"-1"}`, false},
		{"NaN", `"credits":{"balance":"NaN"}`, false},
		{"infinity", `"credits":{"balance":"Infinity"}`, false},
		{"malformed", `"credits":{"balance":"a lot"}`, false},
		{"fraction rejected", `"credits":{"balance":"1/2"}`, false},
		{"empty", `"credits":{"balance":""}`, false},
		{"huge exponent", `"credits":{"balance":"1e-999999999"}`, false},
		{"monthly remaining", `"spend_control":{"reached":false,"individual_limit":{"remaining":"351.02"}}`, true},
		{"numeric bridge amounts", `"spend_control":{"individual_limit":{"limit":400,"used":48.98,"remaining":351.02}}`, true},
		{"exact difference", `"spend_control":{"individual_limit":{"limit":"9007199254740993.01","used":"9007199254740993.00"}}`, true},
		{"remaining percent alone insufficient", `"spend_control":{"individual_limit":{"remaining_percent":1}}`, false},
		{"monthly empty", `"spend_control":{"individual_limit":{}}`, false},
		{"monthly negative", `"spend_control":{"individual_limit":{"remaining":"-1"}}`, false},
		{"monthly malformed", `"spend_control":{"individual_limit":{"remaining":"NaN"}}`, false},
		{"negative used", `"spend_control":{"individual_limit":{"limit":"5","used":"-1"}}`, false},
		{"negative total", `"spend_control":{"individual_limit":{"limit":"-5","used":"0"}}`, false},
		{"over budget", `"spend_control":{"individual_limit":{"limit":"5","used":"6","remaining":"1"}}`, false},
		{"monthly reached wins", `"credits":{"balance":"100"},"spend_control":{"reached":true}`, false},
		{"monthly zero wins", `"credits":{"unlimited":true},"spend_control":{"individual_limit":{"remaining":"0"}}`, false},
		{"monthly limit zero wins", `"credits":{"balance":"100"},"spend_control":{"individual_limit":{"limit":"0","used":"0"}}`, false},
		{"monthly invalid percent", `"credits":{"balance":"100"},"spend_control":{"individual_limit":{"remaining_percent":-1}}`, false},
		{"monthly percent exhausted", `"credits":{"balance":"100"},"spend_control":{"individual_limit":{"remaining_percent":0}}`, false},
		{"rounded zero percent", `"spend_control":{"individual_limit":{"remaining":"0.01","remaining_percent":0}}`, true},
		{"balance empty despite positive cap", `"credits":{"balance":"0"},"spend_control":{"individual_limit":{"remaining":"100"}}`, false},
		{"expired budget cycle", `"credits":{"balance":"100"},"spend_control":{"individual_limit":{"reset_at":1,"remaining":"1"}}`, false},
		{"expired relative cycle", `"credits":{"balance":"100"},"spend_control":{"individual_limit":{"reset_after_seconds":0,"remaining":"1"}}`, false},
		{"organization denial wins", `"credits":{"balance":"100"},"rate_limit_reached_type":{"type":"workspace_owner_usage_limit_reached"}`, false},
		{"member usage denial wins", `"credits":{"has_credits":true},"rate_limit_reached_type":{"type":"workspace_member_usage_limit_reached"}`, false},
		{"owner credits denial wins", `"credits":{"balance":"100"},"rate_limit_reached_type":{"type":"workspace_owner_credits_depleted"}`, false},
		{"member credits denial wins", `"credits":{"unlimited":true},"rate_limit_reached_type":{"type":"workspace_member_credits_depleted"}`, false},
		{"subscription exhaustion allows credits", `"credits":{"balance":"100"},"rate_limit_reached_type":{"type":"rate_limit_reached"}`, true},
		{"unknown denial is conservative", `"credits":{"balance":"100"},"rate_limit_reached_type":{"type":"future_denial"}`, false},
		{"malformed denial is conservative", `"credits":{"balance":"100"},"rate_limit_reached_type":{}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account := creditSchedulingAccount(t, now, `{"rate_limit":{"allowed":true,"limit_reached":false},`+tc.fields+`}`)
			require.Equal(t, tc.want, openAICreditsAllowExhaustedWindow(account, now))
		})
	}
	for _, body := range []string{
		`{"credits":{"balance":"1"}}`,
		`{"credits":{"has_credits":true}}`,
		`{"credits":{"balance":"1"},"rate_limit":{}}`,
		`{"credits":{"balance":"1"},"rate_limit":{"allowed":false}}`,
		`{"credits":{"balance":"1"},"rate_limit":{"allowed":true,"limit_reached":true}}`,
		`{"credits":{"balance":"1"},"rate_limit":{"allowed":false,"limit_reached":true}}`,
	} {
		require.True(t, openAICreditsAllowExhaustedWindow(creditSchedulingAccount(t, now, body), now), "window flags must not veto fresh usable credits")
	}
	for _, body := range []string{
		`{}`,
		`{"rate_limit":{"allowed":false,"limit_reached":true}}`,
		`{"rate_limit":{"allowed":true},"credits":{"balance":"0"}}`,
	} {
		require.False(t, openAICreditsAllowExhaustedWindow(creditSchedulingAccount(t, now, body), now), "window state alone cannot prove usable credits")
	}
	const body = `{"credits":{"balance":"1"},"rate_limit":{"allowed":true}}`
	for _, observed := range []time.Time{now.Add(-5 * time.Minute), now.Add(-time.Hour), now.Add(time.Minute), time.Unix(0, 0)} {
		require.False(t, openAICreditsAllowExhaustedWindow(creditSchedulingAccount(t, observed, body), now))
	}
	account := creditSchedulingAccount(t, now, body)
	account.Type = AccountTypeAPIKey
	require.False(t, openAICreditsAllowExhaustedWindow(account, now), "arbitrary API-key accounts cannot use OAuth credits")
}

func TestOpenAICreditsSchedulingRespectsAdministratorAndHardGates(t *testing.T) {
	now := time.Now()
	const body = `{"credits":{"balance":"100"},"rate_limit":{"allowed":false,"limit_reached":true},"rate_limit_reached_type":{"type":"rate_limit_reached"}}`
	ctx := withOpenAIQuotaAutoPauseSettings(context.Background(), OpsOpenAIAccountQuotaAutoPauseSettings{DefaultThreshold5h: 1, DefaultThreshold7d: 1})
	account := creditSchedulingAccount(t, now, body)
	paused, _ := shouldAutoPauseOpenAIAccountByQuota(ctx, account)
	require.False(t, paused, "fresh credits permit attempting normal requests after subscription-window exhaustion")
	require.Empty(t, openAICompatibleAccountEligibilityFailureReasonBeforeProfit(ctx, account, PlatformOpenAI, "", false, ""))

	for _, window := range []string{"5h", "7d"} {
		for _, threshold := range []float64{0.9, 1} {
			account := creditSchedulingAccount(t, now, body)
			account.Extra["auto_pause_"+window+"_threshold"] = threshold
			paused, _ := shouldAutoPauseOpenAIAccountByQuota(ctx, account)
			require.True(t, paused, "explicit account pause policy wins")
		}
	}
	earlyCtx := withOpenAIQuotaAutoPauseSettings(context.Background(), OpsOpenAIAccountQuotaAutoPauseSettings{DefaultThreshold5h: 0.9})
	paused, _ = shouldAutoPauseOpenAIAccountByQuota(earlyCtx, account)
	require.True(t, paused, "global early pause policy wins")
	for _, change := range []func(*Account){
		func(a *Account) { a.Schedulable = false },
		func(a *Account) { a.Status = StatusDisabled },
		func(a *Account) { a.Status = StatusError },
		func(a *Account) { until := now.Add(time.Hour); a.RateLimitResetAt = &until },
	} {
		account := creditSchedulingAccount(t, now, body)
		change(account)
		require.NotEmpty(t, openAICompatibleAccountEligibilityFailureReasonBeforeProfit(ctx, account, PlatformOpenAI, "", false, ""))
	}
	limited := creditSchedulingAccount(t, now, body)
	until := now.Add(time.Hour)
	limited.RateLimitResetAt = &until
	require.True(t, openAICreditsAllowExhaustedWindow(limited, now), "a credit snapshot is only one part of eligibility")
	require.NotEmpty(t, openAICompatibleAccountEligibilityFailureReasonBeforeProfit(ctx, limited, PlatformOpenAI, "", false, ""), "real HTTP 429 cooldown must still block selection")
	require.Equal(t, until, *limited.RateLimitResetAt, "credit eligibility must never clear a hard cooldown")
	shadow := creditSchedulingAccount(t, now, body)
	parentID := int64(20)
	shadow.ParentAccountID = &parentID
	require.False(t, openAICreditsAllowExhaustedWindow(shadow, now), "general credits must not bypass Spark-specific limits")
}
