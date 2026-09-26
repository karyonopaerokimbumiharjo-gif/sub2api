package apicompat

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Consume serialized chunks the way OpenAI SDK clients do: concatenate text,
// tool identity and argument fragments, then observe the finish and usage.
type recoveredChat struct {
	text, reasoning, finish string
	tools                   map[int]ChatToolCall
	usage                   *ChatUsage
	finishes                int
}

func collectRecoveredChat(t *testing.T, events ...string) recoveredChat {
	t.Helper()
	state := NewResponsesEventToChatState()
	state.Model = "client-model"
	state.IncludeUsage = true
	out := recoveredChat{tools: make(map[int]ChatToolCall)}
	for _, raw := range events {
		var event ResponsesStreamEvent
		require.NoError(t, json.Unmarshal([]byte(raw), &event))
		for _, chunk := range ResponsesEventToChatChunks(&event, state) {
			sse, err := ChatChunkToSSE(chunk)
			require.NoError(t, err)
			var decoded ChatCompletionsChunk
			require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(sse, "data: "))), &decoded))
			require.Equal(t, "client-model", decoded.Model)
			for _, choice := range decoded.Choices {
				if choice.Delta.Content != nil {
					out.text += *choice.Delta.Content
				}
				if choice.Delta.ReasoningContent != nil {
					out.reasoning += *choice.Delta.ReasoningContent
				}
				for _, fragment := range choice.Delta.ToolCalls {
					require.NotNil(t, fragment.Index)
					tool := out.tools[*fragment.Index]
					tool.ID += fragment.ID
					tool.Function.Name += fragment.Function.Name
					tool.Function.Arguments += fragment.Function.Arguments
					out.tools[*fragment.Index] = tool
				}
				if choice.FinishReason != nil {
					out.finish = *choice.FinishReason
					out.finishes++
				}
			}
			if decoded.Usage != nil {
				out.usage = decoded.Usage
			}
		}
	}
	return out
}

const recoveryCreated = `{"type":"response.created","response":{"id":"resp_recovery","status":"in_progress","model":"upstream-model","output":[]}}`

func TestResponsesChatRecoveryTextSnapshots(t *testing.T) {
	const item = `{"id":"msg_one","type":"message","role":"assistant","content":[{"type":"output_text","text":"你好🌏，答案是 29。"}]}`
	const terminal = `{"type":"response.completed","response":{"id":"resp_recovery","status":"completed","output":[` + item + `],"usage":{"input_tokens":2984,"output_tokens":604}}}`
	for _, boundary := range []string{"text_done", "item_done", "completed"} {
		t.Run(boundary, func(t *testing.T) {
			events := []string{recoveryCreated}
			if boundary == "text_done" {
				events = append(events, `{"type":"response.output_text.done","item_id":"msg_one","output_index":0,"content_index":0,"text":"你好🌏，答案是 29。"}`)
			}
			if boundary == "item_done" {
				events = append(events, `{"type":"response.output_item.done","output_index":0,"item":`+item+`}`)
			}
			events = append(events, terminal)
			got := collectRecoveredChat(t, events...)
			require.Equal(t, "你好🌏，答案是 29。", got.text)
			require.Empty(t, got.tools)
			require.Equal(t, "stop", got.finish)
			require.Equal(t, 1, got.finishes)
			require.NotNil(t, got.usage)
			require.Equal(t, 604, got.usage.CompletionTokens)
		})
	}
}

func TestResponsesChatRecoveryPartialPrefixesAndIndependentContentParts(t *testing.T) {
	got := collectRecoveredChat(t, recoveryCreated,
		`{"type":"response.reasoning_summary_text.delta","output_index":0,"delta":"思考"}`,
		`{"type":"response.output_text.delta","output_index":1,"content_index":0,"delta":"你好🌏"}`,
		`{"type":"response.output_text.done","output_index":1,"content_index":0,"text":"你好🌏！"}`,
		`{"type":"response.output_text.delta","output_index":1,"content_index":1,"delta":"第二"}`,
		`{"type":"response.output_item.done","output_index":1,"item":{"id":"msg_one","type":"message","content":[{"type":"output_text","text":"你好🌏！"},{"type":"output_text","text":"第二段。"}]}}`,
		`{"type":"response.completed","response":{"status":"completed","output":[{"type":"reasoning","summary":[{"type":"summary_text","text":"private summary must not become answer"}]},{"id":"msg_one","type":"message","content":[{"type":"output_text","text":"你好🌏！"},{"type":"output_text","text":"第二段。"}]},{"id":"msg_two","type":"message","content":[{"type":"output_text","text":"第三段。"}]}]}}`,
		`{"type":"response.output_text.delta","output_index":2,"delta":"late duplicate"}`,
		`{"type":"response.completed","response":{"status":"completed"}}`,
	)
	require.Equal(t, "你好🌏！第二段。第三段。", got.text)
	require.Equal(t, "思考", got.reasoning)
	require.Equal(t, 1, got.finishes)
}

func TestResponsesChatRecoveryDoesNotAppendConflictingSnapshots(t *testing.T) {
	got := collectRecoveredChat(t, recoveryCreated,
		`{"type":"response.output_text.delta","output_index":0,"delta":"original"}`,
		`{"type":"response.output_text.done","output_index":0,"text":"different answer"}`,
		`{"type":"response.output_text.done","output_index":0,"text":"orig"}`,
		`{"type":"response.completed","response":{"status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"original answer"}]}]}}`,
	)
	require.Equal(t, "original answer", got.text)
}

func TestResponsesChatRecoveryToolSnapshots(t *testing.T) {
	const item = `{"id":"fc_one","type":"function_call","call_id":"call_one","name":"attempt_completion","arguments":"{\"result\":\"你好🌏\"}"}`
	const terminal = `{"type":"response.completed","response":{"status":"completed","output":[` + item + `],"usage":{"input_tokens":10,"output_tokens":12}}}`
	for _, boundary := range []string{"arguments_done", "item_done", "completed"} {
		t.Run(boundary, func(t *testing.T) {
			events := []string{recoveryCreated}
			if boundary == "arguments_done" {
				// Some adapters omit item.added but retain identity on args.done.
				events = append(events, `{"type":"response.function_call_arguments.done","output_index":0,"call_id":"call_one","name":"attempt_completion","arguments":"{\"result\":\"你好🌏\"}"}`)
			}
			if boundary == "item_done" {
				events = append(events, `{"type":"response.output_item.done","output_index":0,"item":`+item+`}`)
			}
			events = append(events, terminal)
			got := collectRecoveredChat(t, events...)
			require.Empty(t, got.text)
			require.Len(t, got.tools, 1)
			require.Equal(t, "call_one", got.tools[0].ID)
			require.Equal(t, "attempt_completion", got.tools[0].Function.Name)
			require.Equal(t, `{"result":"你好🌏"}`, got.tools[0].Function.Arguments)
			require.Equal(t, "tool_calls", got.finish)
		})
	}
}

func TestResponsesChatRecoveryParallelToolsKeepIdentityAndArgumentPrefixes(t *testing.T) {
	got := collectRecoveredChat(t, recoveryCreated,
		`{"type":"response.output_item.added","output_index":1,"item":{"id":"fc_one","type":"function_call","call_id":"call_one","name":"lookup"}}`,
		`{"type":"response.function_call_arguments.delta","output_index":1,"delta":"{\"city\":\"北"}`,
		`{"type":"response.output_item.added","output_index":2,"item":{"id":"fc_two","type":"function_call","call_id":"call_two","name":"clock"}}`,
		`{"type":"response.function_call_arguments.delta","output_index":2,"delta":"{}"}`,
		`{"type":"response.function_call_arguments.done","output_index":1,"arguments":"{\"city\":\"北京\"}"}`,
		`{"type":"response.output_item.done","output_index":1,"item":{"id":"fc_one","type":"function_call","call_id":"call_one","name":"lookup","arguments":"{\"city\":\"北京\"}"}}`,
		`{"type":"response.completed","response":{"status":"completed","output":[{"type":"reasoning","summary":[]},{"id":"fc_one","type":"function_call","call_id":"call_one","name":"lookup","arguments":"{\"city\":\"北京\"}"},{"id":"fc_two","type":"function_call","call_id":"call_two","name":"clock","arguments":"{}"},{"id":"fc_three","type":"custom_tool_call","call_id":"call_three","name":"apply_patch","input":"patch text"}]}}`,
	)
	require.Len(t, got.tools, 3)
	require.Equal(t, "call_one", got.tools[0].ID)
	require.Equal(t, "lookup", got.tools[0].Function.Name)
	require.Equal(t, `{"city":"北京"}`, got.tools[0].Function.Arguments)
	require.Equal(t, "call_two", got.tools[1].ID)
	require.Equal(t, "clock", got.tools[1].Function.Name)
	require.Equal(t, "{}", got.tools[1].Function.Arguments)
	require.Equal(t, "call_three", got.tools[2].ID)
	require.Equal(t, "apply_patch", got.tools[2].Function.Name)
	require.Equal(t, "patch text", got.tools[2].Function.Arguments)
	require.Equal(t, "tool_calls", got.finish)
}

func TestResponsesChatRecoveryEmptyOrFilteredOutputDoesNotInventAnswer(t *testing.T) {
	for _, raw := range []string{
		`{"type":"response.completed","response":{"status":"completed","output":[]}}`,
		`{"type":"response.completed","response":{"status":"completed","output":[{"type":"function_call","arguments":""}]}}`,
		`{"type":"response.completed","response":{"status":"completed","output":[{"type":"reasoning","summary":[{"type":"summary_text","text":"thinking only"}]},{"type":"message","content":[]}]}}`,
		`{"type":"response.failed","response":{"status":"failed","output":[{"type":"message","content":[{"type":"output_text","text":"must not recover failed output"}]}]}}`,
		`{"type":"response.incomplete","response":{"status":"incomplete","incomplete_details":{"reason":"content_filter"},"output":[{"type":"message","content":[{"type":"output_text","text":"must not recover filtered output"}]}]}}`,
	} {
		got := collectRecoveredChat(t, recoveryCreated, raw)
		require.Empty(t, got.text)
		require.Empty(t, got.tools)
		require.Empty(t, got.reasoning)
		require.Equal(t, 1, got.finishes)
	}
}

func TestResponsesChatRecoveryToolIdentityCompletedOnce(t *testing.T) {
	got := collectRecoveredChat(t, recoveryCreated,
		`{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call"}}`,
		`{"type":"response.function_call_arguments.delta","output_index":0,"delta":"{"}`,
		`{"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","call_id":"call_one","name":"clock","arguments":"{}"}}`,
		`{"type":"response.completed","response":{"status":"completed","output":[{"type":"function_call","call_id":"call_one","name":"clock","arguments":"{}"}]}}`,
	)
	require.Len(t, got.tools, 1)
	require.Equal(t, "call_one", got.tools[0].ID)
	require.Equal(t, "clock", got.tools[0].Function.Name)
	require.Equal(t, "{}", got.tools[0].Function.Arguments)
	// A conflicting final item must not attach another tool's arguments to an
	// already announced call, even if those arguments share the same prefix.
	got = collectRecoveredChat(t, recoveryCreated,
		`{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","call_id":"call_one","name":"clock"}}`,
		`{"type":"response.function_call_arguments.delta","output_index":0,"delta":"{"}`,
		`{"type":"response.function_call_arguments.done","output_index":0,"call_id":"call_two","name":"clock","arguments":"{\"other\":true}"}`,
		`{"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","call_id":"call_one","name":"different","arguments":"{\"other\":true}"}}`,
		`{"type":"response.completed","response":{"status":"completed","output":[{"type":"function_call","call_id":"call_two","name":"clock","arguments":"{\"other\":true}"}]}}`,
	)
	require.Len(t, got.tools, 1)
	require.Equal(t, "call_one", got.tools[0].ID)
	require.Equal(t, "clock", got.tools[0].Function.Name)
	require.Equal(t, "{", got.tools[0].Function.Arguments)
}

func TestResponsesChatRecoveryIncompleteRetainsFinishReason(t *testing.T) {
	got := collectRecoveredChat(t, recoveryCreated,
		`{"type":"response.incomplete","response":{"status":"incomplete","incomplete_details":{"reason":"max_output_tokens"},"output":[{"type":"message","content":[{"type":"output_text","text":"partial answer"}]}],"usage":{"input_tokens":5,"output_tokens":10}}}`,
	)
	require.Equal(t, "partial answer", got.text)
	require.Equal(t, "length", got.finish)
	require.Equal(t, 10, got.usage.CompletionTokens)
}
