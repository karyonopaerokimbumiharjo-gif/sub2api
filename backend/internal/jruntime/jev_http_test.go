package jruntime

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"strings"
	"testing"
)

type decisionTransport func(*http.Request) (*http.Response, error)

func (f decisionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestJevDecisionUsesBoundedContractAndCalibratedChoice(t *testing.T) {
	candidates := FiniteCandidates([]Tool{fixtureTool}, 64)
	for _, tc := range []struct {
		name, answer string
		confidence   float64
		invalid      bool
	}{
		{"choice", `{"model":"jev-1.13.0","answers":{"next":{"type":"choice","choice":"tool_0","confidence":0.96,"probabilities":{"tool_0":0.98,"base":0.02}}},"usage":{"input_tokens":10,"output_tokens":3}}`, 0.96, false},
		{"low_probability", `{"model":"jev-1.13.0","answers":{"next":{"type":"choice","choice":"tool_0","confidence":0.99,"probabilities":{"tool_0":0.6,"base":0.4}}}}`, 0.6, false},
		{"wrong_model", `{"model":"other","answers":{}}`, 0, true},
		{"duplicate", `{"model":"other","model":"jev-1.13.0","answers":{}}`, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: decisionTransport(func(r *http.Request) (*http.Response, error) {
				raw, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				require.NotContains(t, string(raw), "secret-canary")
				require.Contains(t, string(raw), "immediate next")
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(tc.answer)), Header: make(http.Header)}, nil
			})}
			choice, err := (JevClient{Token: "private-token", HTTP: client}).Choose(context.Background(), fixtureBinding("gpt-5.6-sol"), json.RawMessage(`{"api_key":"secret-canary","input":"read a job"}`), candidates[:1])
			if tc.invalid {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.confidence, choice.Confidence)
			}
		})
	}
}
