package service

import (
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/apicompat"
	"github.com/stretchr/testify/require"
)

func TestNormalizeOpenAIReasoningEffortGPT6AstraMax(t *testing.T) {
	t.Parallel()

	for _, model := range []string{"gpt-6-astra", "openai/GPT-6-ASTRA"} {
		effort, present := getOpenAIReasoningEffortFromReqBody(map[string]any{
			"reasoning": map[string]any{"effort": "max"},
		}, model)
		require.True(t, present)
		require.Equal(t, "max", effort)
	}
	// Unknown models and client-only orchestration retain the existing policy.
	require.Equal(t, "xhigh", normalizeOpenAIReasoningEffortForModel("max", "gpt-6-unknown"))
	require.Empty(t, normalizeOpenAIReasoningEffortForModel("ultra", "gpt-6-astra"))
}

func TestOpenAICompatAnthropicGPT6AstraMax(t *testing.T) {
	t.Parallel()

	request := &apicompat.AnthropicRequest{
		Model:        "public-alias",
		OutputConfig: &apicompat.AnthropicOutputConfig{Effort: "max"},
	}
	// Resolve against the final upstream model so a public alias keeps max too.
	require.Equal(t, "max", openAICompatAnthropicReasoningEffort(request, "gpt-6-astra", "xhigh"))
	require.Equal(t, "xhigh", openAICompatAnthropicReasoningEffort(request, "gpt-5.5", "xhigh"))
}
