package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/executiontrace"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestUsageExecutionTraceReturnsBoundedMetadata(t *testing.T) {
	previous := executiontrace.Default
	executiontrace.Default = executiontrace.NewStore(8, time.Hour)
	t.Cleanup(func() { executiontrace.Default = previous })
	executiontrace.Default.Append(executiontrace.Event{RequestID: "request-a", Stage: "request", Model: "gpt-6j"})
	executiontrace.Default.Append(executiontrace.Event{RequestID: "request-b", Stage: "request", Model: "gpt-6j"})

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/admin/usage/execution-traces", (&UsageHandler{}).ExecutionTrace)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/usage/execution-traces?request_id=request-a&limit=1", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var envelope struct {
		Data []executiontrace.Event `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))
	require.Len(t, envelope.Data, 1)
	require.Equal(t, "request-a", envelope.Data[0].RequestID)

	bad := httptest.NewRecorder()
	router.ServeHTTP(bad, httptest.NewRequest(http.MethodGet, "/admin/usage/execution-traces?limit=201", nil))
	require.Equal(t, http.StatusBadRequest, bad.Code)
}
