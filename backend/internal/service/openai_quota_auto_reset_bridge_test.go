package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type autoResetAccountRepo struct {
	AccountRepository
	accounts map[int64]*Account
}

func (r *autoResetAccountRepo) GetByID(_ context.Context, id int64) (*Account, error) {
	return r.accounts[id], nil
}

func (r *autoResetAccountRepo) FindByExtraField(_ context.Context, key string, value any) ([]Account, error) {
	out := make([]Account, 0)
	for _, account := range r.accounts {
		if key == openAIQuotaAutoResetEnabledKey && value == true &&
			resolveAccountExtraBool(account.Extra, openAIQuotaAutoResetEnabledKey) {
			out = append(out, *account)
		}
	}
	return out, nil
}

func (r *autoResetAccountRepo) UpdateExtra(_ context.Context, id int64, updates map[string]any) error {
	account := r.accounts[id]
	if account.Extra == nil {
		account.Extra = make(map[string]any)
	}
	for key, value := range updates {
		account.Extra[key] = value
	}
	return nil
}

func TestOpenAIQuotaAutoResetSetEnabled(t *testing.T) {
	account := &Account{
		ID:       41,
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
		Extra:    map[string]any{},
	}
	repo := &autoResetAccountRepo{accounts: map[int64]*Account{account.ID: account}}
	service := &OpenAIQuotaService{accountRepo: repo}

	settings, err := service.SetAutoReset(context.Background(), account.ID, true)
	require.NoError(t, err)
	require.True(t, settings.Enabled)
	require.Equal(t, true, account.Extra[openAIQuotaAutoResetEnabledKey])
	require.Equal(t, "enabled", account.Extra[openAIQuotaAutoResetLastStatusKey])
}

func TestOpenAIQuotaAutoResetSetEnabledForCompatibleBridge(t *testing.T) {
	account := newOpenAIQuotaBridgeTestAccount(43, "http://cpa:8317", "bound.json", "bound@example.com")
	repo := &autoResetAccountRepo{accounts: map[int64]*Account{account.ID: account}}
	service := &OpenAIQuotaService{accountRepo: repo}

	settings, err := service.SetAutoReset(context.Background(), account.ID, true)
	require.NoError(t, err)
	require.True(t, settings.Enabled)
	require.Equal(t, true, account.Extra[openAIQuotaAutoResetEnabledKey])
}

func TestOpenAIQuotaAutoResetCycleConsumesOneCreditAndDoesNotRepeat(t *testing.T) {
	now := time.Date(2026, 7, 25, 3, 0, 0, 0, time.UTC)
	account := &Account{
		ID:       42,
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
		Status:   StatusActive,
		Extra: map[string]any{
			openAIQuotaAutoResetEnabledKey: true,
			"codex_7d_used_percent":        100.0,
		},
	}
	repo := &autoResetAccountRepo{accounts: map[int64]*Account{account.ID: account}}
	queryCalls := 0
	resetCalls := 0
	service := &OpenAIQuotaService{
		accountRepo: repo,
		autoResetQueryUsage: func(_ context.Context, id int64) (*OpenAIQuotaUsage, error) {
			require.Equal(t, account.ID, id)
			queryCalls++
			used := 100.0
			if queryCalls > 1 {
				used = 0
			}
			return &OpenAIQuotaUsage{
				RateLimit: &OpenAIRateLimit{
					PrimaryWindow: &OpenAIRateLimitWindow{
						UsedPercent:        0,
						LimitWindowSeconds: 5 * 60 * 60,
						ResetAt:            now.Add(5 * time.Hour).Unix(),
					},
					SecondaryWindow: &OpenAIRateLimitWindow{
						UsedPercent:        used,
						LimitWindowSeconds: 7 * 24 * 60 * 60,
						ResetAt:            now.Add(7 * 24 * time.Hour).Unix(),
					},
				},
				RateLimitResetCredits: &OpenAIRateLimitResetCredits{AvailableCount: 2},
			}, nil
		},
		autoResetResetCredit: func(_ context.Context, id int64) (*OpenAIQuotaResetResult, error) {
			require.Equal(t, account.ID, id)
			resetCalls++
			return &OpenAIQuotaResetResult{Code: "ok", WindowsReset: 2}, nil
		},
	}

	service.runAutoResetCycle(context.Background(), now)
	require.Equal(t, 1, resetCalls)
	require.Equal(t, "success", account.Extra[openAIQuotaAutoResetLastStatusKey])
	require.NotEmpty(t, account.Extra[openAIQuotaAutoResetLastWindowKey])
	require.Equal(t, 0.0, account.Extra["codex_7d_used_percent"])

	service.runAutoResetCycle(context.Background(), now.Add(10*time.Minute))
	require.Equal(t, 1, resetCalls)
}

func TestExhaustedOpenAIWindowKeyStableWithoutResetAt(t *testing.T) {
	now := time.Date(2026, 7, 25, 3, 0, 15, 0, time.UTC)
	rateLimit := &OpenAIRateLimit{
		SecondaryWindow: &OpenAIRateLimitWindow{
			UsedPercent:        100,
			LimitWindowSeconds: 7 * 24 * 60 * 60,
			ResetAfterSeconds:  3600,
		},
	}
	first := exhaustedOpenAIWindowKey(rateLimit, now)
	rateLimit.SecondaryWindow.ResetAfterSeconds -= 30
	second := exhaustedOpenAIWindowKey(rateLimit, now.Add(30*time.Second))
	require.Equal(t, first, second)
	require.NotEmpty(t, first)
}
