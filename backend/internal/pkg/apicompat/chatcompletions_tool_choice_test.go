package apicompat

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestChatCompletionsToResponses_NamedToolChoice(t *testing.T) {
	const body = `{
		"model":"gpt-6-astra",
		"messages":[{"role":"user","content":"Calculate 19 + 23."}],
		"tools":[{"type":"function","function":{
			"name":"add_integers","description":"Add two integers.","strict":true,
			"parameters":{"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"}},"required":["a","b"],"additionalProperties":false}
		}}],
		"tool_choice":{"type":"function","function":{"name":"add_integers"}}
	}`
	var req ChatCompletionsRequest
	require.NoError(t, json.Unmarshal([]byte(body), &req))
	before, err := json.Marshal(req)
	require.NoError(t, err)

	out, err := ChatCompletionsToResponses(&req)
	require.NoError(t, err)
	require.JSONEq(t, `{"type":"function","name":"add_integers"}`, string(out.ToolChoice))
	require.Len(t, out.Tools, 1)
	require.Equal(t, "function", out.Tools[0].Type)
	require.Equal(t, "add_integers", out.Tools[0].Name)
	require.Equal(t, "Add two integers.", out.Tools[0].Description)
	require.NotNil(t, out.Tools[0].Strict)
	require.True(t, *out.Tools[0].Strict)
	require.JSONEq(t, string(req.Tools[0].Function.Parameters), string(out.Tools[0].Parameters))
	// Reusing a parsed request for retries must not mutate its Chat shape.
	after, err := json.Marshal(req)
	require.NoError(t, err)
	require.JSONEq(t, string(before), string(after))
}

func TestChatCompletionsToResponses_ToolChoicePreservesCompatibleForms(t *testing.T) {
	for _, choice := range []string{
		`"auto"`, `"none"`, `"required"`,
		`{"type":"function","name":"add_integers"}`,
		`{"type":"custom","name":"custom_tool"}`,
		`{"type":"x_search"}`,
	} {
		t.Run(choice, func(t *testing.T) {
			out, err := ChatCompletionsToResponses(&ChatCompletionsRequest{
				Model: "gpt-6-astra", ToolChoice: json.RawMessage(choice),
				Messages: []ChatMessage{{Role: "user", Content: json.RawMessage(`"Hello"`)}},
			})
			require.NoError(t, err)
			require.JSONEq(t, choice, string(out.ToolChoice))
		})
	}
}

func TestChatCompletionsToResponses_RejectsInvalidNamedToolChoice(t *testing.T) {
	for _, choice := range []string{
		`{"type":"function","function":{}}`,
		`{"type":"function","function":{"name":""}}`,
		`{"type":"function","function":{"name":12}}`,
	} {
		t.Run(choice, func(t *testing.T) {
			_, err := ChatCompletionsToResponses(&ChatCompletionsRequest{
				ToolChoice: json.RawMessage(choice),
				Messages:   []ChatMessage{{Role: "user", Content: json.RawMessage(`"Hello"`)}},
			})
			require.ErrorContains(t, err, "convert tool_choice")
		})
	}
}
