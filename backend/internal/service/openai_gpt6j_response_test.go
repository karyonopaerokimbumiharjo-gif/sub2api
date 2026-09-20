package service

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func gpt6JResponseTestContext() *gin.Context {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Set(OpenAIGPT6JContextKey, true)
	return c
}

func TestGPT6JRejectsActualResponseModelBeforeForwarding(t *testing.T) {
	for _, model := range []string{"gpt-5.6-luna", "gpt-reserve", ""} {
		t.Run(model, func(t *testing.T) {
			body := `{"model":"` + model + `","status":"completed","output":[]}`
			response := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
			require.ErrorIs(t, guardGPT6JHTTPResponse(gpt6JResponseTestContext(), response), errGPT6JResponseModel)
		})
	}
}

func TestGPT6JMatchingJSONResponseIsPreserved(t *testing.T) {
	body := `{"model":"gpt-6-astra","status":"completed","output":[]}`
	response := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
	require.NoError(t, guardGPT6JHTTPResponse(gpt6JResponseTestContext(), response))
	got, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Equal(t, body, string(got))
}

func TestGPT6JStreamModelValidation(t *testing.T) {
	created := "data: {\"type\":\"response.created\",\"response\":{\"model\":\"gpt-6-astra\"}}\n\n"
	text := "data: {\"type\":\"response.output_text.delta\",\"delta\":\"verified output\"}\n\n"
	complete := "data: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-6-astra\",\"status\":\"completed\"}}\n\n"
	for _, tc := range []struct {
		name, wire        string
		primeErr, readErr bool
	}{
		{"valid", created + text + complete + "data: [DONE]\n\n", false, false},
		{"wrong first model", strings.ReplaceAll(created, "gpt-6-astra", "gpt-5.6-luna") + text, true, false},
		{"text before identity", text + complete, true, false},
		{"wrong terminal model", created + text + strings.ReplaceAll(complete, "gpt-6-astra", "gpt-5.6-luna"), false, true},
		{"missing terminal model", created + strings.ReplaceAll(complete, `"model":"gpt-6-astra",`, ""), false, true},
		{"truncated", created + text, false, true},
		{"done without terminal", created + "data: [DONE]\n\n", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/event-stream"}}, Body: io.NopCloser(strings.NewReader(tc.wire))}
			err := guardGPT6JHTTPResponse(gpt6JResponseTestContext(), response)
			if tc.primeErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			got, err := io.ReadAll(response.Body)
			if tc.readErr {
				require.Error(t, err)
				require.NotContains(t, string(got), "response.completed")
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wire, string(got))
		})
	}
}

func TestGPT6JWebSocketModelValidation(t *testing.T) {
	guard := &gpt6JResponseGuard{}
	require.NoError(t, guard.event([]byte(`{"type":"response.created","response":{"model":"gpt-6-astra"}}`)))
	require.ErrorIs(t, guard.event([]byte(`{"type":"response.completed","response":{"model":"gpt-5.6-luna"}}`)), errGPT6JResponseModel)
	freshTurn := &gpt6JResponseGuard{}
	require.ErrorIs(t, freshTurn.event([]byte(`{"type":"response.output_text.delta","delta":"not verified"}`)), errGPT6JResponseModel)
}

func TestGPT6JResponseGuardLeavesOrdinaryAndCompactRequestsUntouched(t *testing.T) {
	for _, compact := range []bool{false, true} {
		c := gpt6JResponseTestContext()
		if compact {
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses/compact", nil)
		} else {
			c.Set(OpenAIGPT6JContextKey, false)
		}
		original := io.NopCloser(strings.NewReader(`{"model":"gpt-5.6-luna"}`))
		response := &http.Response{StatusCode: 200, Header: http.Header{}, Body: original}
		require.NoError(t, guardGPT6JHTTPResponse(c, response))
		require.True(t, original == response.Body)
	}
}
