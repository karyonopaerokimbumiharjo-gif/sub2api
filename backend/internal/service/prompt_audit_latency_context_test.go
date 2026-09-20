package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPromptAuditLatencyContextPreservesMissingAndMeasuredValues(t *testing.T) {
	require.Nil(t, PromptAuditLatencyFromContext(context.Background()))

	ctx := WithPromptAuditLatency(context.Background(), 321)
	latency := PromptAuditLatencyFromContext(ctx)
	require.NotNil(t, latency)
	require.Equal(t, 321, *latency)

	negative := PromptAuditLatencyFromContext(WithPromptAuditLatency(context.Background(), -1))
	require.NotNil(t, negative)
	require.Zero(t, *negative)
}
