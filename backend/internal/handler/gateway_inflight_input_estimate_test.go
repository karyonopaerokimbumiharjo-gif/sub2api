package handler

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func inflightScreenshotFixture(t *testing.T) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"model": "gpt-6-sol",
		"input": []any{map[string]any{
			"role": "user",
			"content": []any{
				map[string]any{"type": "input_text", "text": strings.Repeat("word", 3500)},
				map[string]any{"type": "input_image", "image_url": "data:image/png;base64," + strings.Repeat("A", 9*1024*1024)},
			},
		}},
	})
	require.NoError(t, err)
	return body
}

func TestSemanticInflightInputEstimate_InlineScreenshotHasVisionBudget(t *testing.T) {
	body := inflightScreenshotFixture(t)
	require.Greater(t, len(body), 9*1024*1024)
	req := tokenInflightEstimate("gpt-6-sol", body)
	require.NotNil(t, req.InputTokens)
	require.GreaterOrEqual(t, *req.InputTokens, 3500+inflightVisionInputTokens)
	require.Less(t, *req.InputTokens, 7000, "transport base64 must not consume the 200k input cap")

	remote := []byte(`{"input":[{"type":"input_image","image_url":"https://example.com/screenshot.png"}]}`)
	require.GreaterOrEqual(t, semanticInflightInputTokens(remote), inflightVisionInputTokens, "remote images still reserve vision input")
}

func TestSemanticInflightInputEstimate_CountsToolTextAndSkipsOpaqueState(t *testing.T) {
	baseline := semanticInflightInputTokens([]byte(`{"input":"hello"}`))
	body, err := json.Marshal(map[string]any{
		"input": []any{
			map[string]any{"type": "function_call", "arguments": `{"query":"` + strings.Repeat("word", 1000) + `"}`},
			map[string]any{"type": "function_call_output", "output": strings.Repeat("result", 1000)},
			map[string]any{"type": "reasoning", "encrypted_content": strings.Repeat("opaque", 2*1024*1024)},
		},
	})
	require.NoError(t, err)
	got := semanticInflightInputTokens(body)
	require.Greater(t, got-baseline, 2500, "arguments and tool results remain billable input")
	require.Less(t, got, 2600, "encrypted state must not be estimated as prompt text")

	toolImage, err := json.Marshal(map[string]any{"input": []any{map[string]any{
		"type": "function_call_output", "output": `[{"type":"input_text","text":"tool result"},{"type":"image","source":{"type":"base64","data":"` + strings.Repeat("A", 9*1024*1024) + `"}}]`,
	}}})
	require.NoError(t, err)
	require.InDelta(t, inflightVisionInputTokens, semanticInflightInputTokens(toolImage), 50)

	file := []byte(`{"input":[{"type":"input_file","file_data":"data:application/pdf;base64,` + strings.Repeat("A", 4096) + `"}]}`)
	require.GreaterOrEqual(t, semanticInflightInputTokens(file), 768, "non-image binary input keeps a conservative decoded-size budget")
}

func TestSemanticInflightInputEstimate_LowBalanceConcurrencyAndRelease(t *testing.T) {
	for _, tc := range []struct {
		name          string
		balance       float64
		secondAllowed bool
	}{{"two screenshot requests", 0.25, true}, {"genuinely insufficient balance", 0.12, false}} {
		t.Run(tc.name, func(t *testing.T) {
			cache := newHandlerInflightCache(tc.balance)
			cfg := &config.Config{}
			cfg.Billing.InflightReservation = config.InflightReservationConfig{Enabled: true, TTLSeconds: 60, DefaultMaxTokens: 8192, MaxInputTokens: 200000, MaxOutputTokens: 128000}
			billingCache := service.NewBillingCacheService(cache, nil, nil, nil, nil, nil, cfg, nil)
			t.Cleanup(billingCache.Stop)
			billing := service.NewBillingService(cfg, nil)
			gw := service.NewGatewayService(nil, nil, nil, nil, nil, nil, nil, nil, cfg, nil, nil, billing, nil, nil,
				nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, service.NewModelPricingResolver(nil, billing), nil, nil, nil)
			key := &service.APIKey{User: &service.User{ID: 1, Balance: tc.balance}}
			req := tokenInflightEstimate("gpt-6-sol", inflightScreenshotFixture(t))
			first := newInflightTestGinContext()
			done, err := reserveInflightBalance(first, billingCache, gw, key, nil, req)
			require.NoError(t, err)
			secondDone, secondErr := reserveInflightBalance(newInflightTestGinContext(), billingCache, gw, key, nil, req)
			if tc.secondAllowed {
				require.NoError(t, secondErr)
				secondDone() // Failed forwarding: no billing task is submitted.
			} else {
				require.ErrorIs(t, secondErr, service.ErrInsufficientBalance)
			}
			require.Equal(t, 1, cache.count())
			// Cancellation never abandons the pending usage task's reservation.
			ctx, cancel := context.WithCancel(first.Request.Context())
			task, _ := wrapUsageRecordTaskContext(ctx, func(context.Context) {
				cache.mu.Lock()
				cache.balance -= 0.01
				cache.mu.Unlock()
			})
			cancel()
			done()
			require.Equal(t, 1, cache.count(), "retain until asynchronous billing completes")
			task(context.Background())
			require.Equal(t, 0, cache.count(), "billing completion releases exactly once")
		})
	}
}
