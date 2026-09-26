package service

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"testing"
)

func TestVPSLatencyFirstDispatchAndMissing(t *testing.T) {
	require.Nil(t, VPSLatencyFromContext(context.Background()))
	require.Nil(t, VPSLatencyFromContext(WithVPSLatency(context.Background(), -1)))
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/v1/responses", nil)
	SetOpsLatencyMs(c, OpsAuthLatencyMsKey, 31)
	SetOpsLatencyMs(c, OpsRoutingLatencyMsKey, 44)
	require.Equal(t, 75, *VPSLatencyFromContext(c.Request.Context()))
	SetOpsLatencyMs(c, OpsRoutingLatencyMsKey, 500)
	require.Equal(t, 75, *VPSLatencyFromContext(c.Request.Context()), "do not count retries as VPS latency")
}
