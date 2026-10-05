package service

import (
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestNativePiRequestErrorsSeparateValidationFromConcurrency(t *testing.T) {
	for _, tc := range []struct {
		body               string
		status, wantStatus int
		message            string
	}{
		{`{"error":"unsupported_pi_tool_type"}`, 400, 400, "tool type"},
		{`{"error":"invalid_pi_tools"}`, 400, 400, "array"},
		{`{"error":"unsupported_pi_field"}`, 400, 400, "unsupported"},
		{`{"error":"input_required"}`, 400, 400, "input"},
		{`{"error":"model_required"}`, 400, 400, "Model is required"},
		{`{"error":"request_too_large"}`, 413, 413, "size limit"},
		{`{"error":"oauth_account_mismatch"}`, 400, 502, "binding mismatch"},
		{`{"error":"private-token-and-request"}`, 400, 400, "request format"},
		{`not-json-private-token`, 400, 400, "request format"},
		{`{"error":"private-token"}`, 409, 409, "session is busy"},
	} {
		d := nativePiClientRequestError(&http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body))})
		require.Equal(t, tc.wantStatus, d.status)
		require.Contains(t, d.message, tc.message)
		require.NotContains(t, d.message, "Pi")
		require.NotContains(t, d.message, "private-token")
		require.NotContains(t, d.message, "Invalid or concurrent")
	}
}

func TestNativePiPublicErrorTypeHidesExecutionBackend(t *testing.T) {
	require.Equal(t, "invalid_request_error", nativePiPublicErrorType(http.StatusBadRequest))
	require.Equal(t, "invalid_request_error", nativePiPublicErrorType(http.StatusForbidden))
	require.Equal(t, "api_error", nativePiPublicErrorType(http.StatusBadGateway))
	require.Equal(t, "api_error", nativePiPublicErrorType(http.StatusGatewayTimeout))
}
