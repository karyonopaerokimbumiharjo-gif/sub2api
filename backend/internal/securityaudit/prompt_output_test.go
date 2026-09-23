package securityaudit

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExtractAssistantOutputCommonJSONShapes(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "chat completions",
			body: `{"choices":[{"message":{"content":"chat answer"}}]}`,
			want: "chat answer",
		},
		{
			name: "responses",
			body: `{"output":[{"type":"message","content":[{"type":"output_text","text":"responses answer"}]}]}`,
			want: "responses answer",
		},
		{
			name: "anthropic",
			body: `{"content":[{"type":"text","text":"anthropic answer"}]}`,
			want: "anthropic answer",
		},
		{
			name: "gemini",
			body: `{"candidates":[{"content":{"parts":[{"text":"gemini answer"}]}}]}`,
			want: "gemini answer",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ExtractAssistantOutput([]byte(tt.body), false))
		})
	}
}

func TestExtractAssistantOutputStreamingShapes(t *testing.T) {
	openAI := "data: {\"choices\":[{\"delta\":{\"content\":\"hello \"}}]}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"content\":\"world\"}}]}\n\n" +
		"data: [DONE]\n\n"
	require.Equal(t, "hello world", ExtractAssistantOutput([]byte(openAI), true))

	anthropic := "event: content_block_delta\n" +
		"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hello \"}}\n\n" +
		"data: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"anthropic\"}}\n\n"
	require.Equal(t, "hello anthropic", ExtractAssistantOutput([]byte(anthropic), true))
}

func TestBuildOutputPromptSnapshotMarksOutputContent(t *testing.T) {
	snapshot, err := BuildOutputPromptSnapshot(Request{
		RequestID: "req-output", Protocol: "openai_responses", Model: "model-one", Stage: "http",
	}, "assistant answer")
	require.NoError(t, err)
	require.Equal(t, "output", snapshot.Stage)
	require.Equal(t, "output_content", snapshot.AuditSubject)
	require.Equal(t, "openai_responses", snapshot.Protocol)
	require.Contains(t, snapshot.FullPrompt, "assistant answer")
}

func TestOutputRepetitionAndFinalSnapshot(t *testing.T) {
	raw := "data: {\"type\":\"response.output_text.delta\",\"delta\":\"ha\"}\n\n"
	require.Equal(t, "haha", ExtractAssistantOutput([]byte(raw+raw), true))
	final := "data: {\"type\":\"response.completed\",\"response\":{\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"haha\"}]}]}}\n\n"
	require.Equal(t, "haha", ExtractAssistantOutput([]byte(raw+raw+final), true))
}
func TestOutputSnapshotPreservesPartialCoverage(t *testing.T) {
	req := Request{OutputCapture: &OutputCapture{Truncated: true, CapturedBytes: 100, ObservedBytes: 200, Terminal: "completed"}}
	snapshot, err := BuildOutputPromptSnapshot(req, "prefix")
	require.NoError(t, err)
	require.Equal(t, "output_content_partial", snapshot.AuditSubject)
	require.Equal(t, req.OutputCapture, snapshot.OutputCapture)
}
