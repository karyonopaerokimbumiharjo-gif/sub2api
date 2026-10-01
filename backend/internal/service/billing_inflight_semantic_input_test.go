//go:build unit

package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInflightEstimate_SemanticInputOverridesEncodedBytesAndRetainsCap(t *testing.T) {
	svc := newInflightEstimateGateway(t, nil)
	key := &APIKey{User: &User{ID: 1}}
	input := 3500
	req := InflightEstimateRequest{Model: "gpt-6-sol", BodyBytes: 9 * 1024 * 1024, InputTokens: &input, MaxTokens: 1000}
	got, priced := svc.EstimateInflightReservation(context.Background(), key, req)
	require.True(t, priced)
	pricing, err := svc.billingService.GetModelPricing(req.Model)
	require.NoError(t, err)
	require.InDelta(t, 3500*pricing.InputPricePerToken+1000*pricing.OutputPricePerToken, got, 1e-12)

	input = 300000
	got, priced = svc.EstimateInflightReservation(context.Background(), key, req)
	require.True(t, priced)
	require.InDelta(t, 200000*pricing.InputPricePerToken+1000*pricing.OutputPricePerToken, got, 1e-12)
}
