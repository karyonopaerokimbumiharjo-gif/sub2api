package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBuildCodexModelsManifestGPT6AstraCapabilities(t *testing.T) {
	t.Parallel()

	for _, modelID := range []string{"gpt-6-astra", "openai/GPT-6-ASTRA"} {
		t.Run(modelID, func(t *testing.T) {
			body, err := BuildCodexModelsManifest([]string{modelID})
			require.NoError(t, err)
			models := decodeCodexManifestModels(t, body)
			require.Len(t, models, 1)
			model := models[0]
			requireCompleteConfiguredCodexModel(t, model, modelID)
			require.Equal(t, "medium", model["default_reasoning_level"])
			require.Equal(t, []string{"low", "medium", "high", "xhigh", "max", "ultra"}, effortsFromManifestModel(t, model))
			require.Equal(t, []any{map[string]any{
				"id": "priority", "name": "Fast", "description": "Priority processing for lower latency.",
			}}, model["service_tiers"])
			require.Equal(t, "none", model["default_reasoning_summary"])
			require.Equal(t, true, model["supports_parallel_tool_calls"])
			require.Equal(t, map[string]any{"mode": "tokens", "limit": float64(10_000)}, model["truncation_policy"])
		})
	}
}

func TestCompleteAPIKeyCodexModelsManifestGPT6AstraVision(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name       string
		body       string
		modalities []any
	}{
		{
			name:       "missing capability gets known vision support",
			body:       `{"models":[{"slug":"gpt-6-astra"}]}`,
			modalities: []any{"text", "image"},
		},
		{
			name:       "explicit upstream restriction is preserved",
			body:       `{"models":[{"slug":"gpt-6-astra","input_modalities":["text"]}]}`,
			modalities: []any{"text"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			manifest := &OpenAIModelsResponse{Body: []byte(tt.body)}
			svc := &OpenAIGatewayService{}
			require.NoError(t, svc.CompleteAPIKeyCodexModelsManifestForClient(manifest, newCodexModelsAPIKeyTestAccount("http://cpa:8317/v1")))
			models := decodeCodexManifestModels(t, manifest.Body)
			require.Len(t, models, 1)
			require.Equal(t, tt.modalities, models[0]["input_modalities"])
			require.Equal(t, []string{"low", "medium", "high", "xhigh", "max", "ultra"}, effortsFromManifestModel(t, models[0]))
			require.Equal(t, codexModelsManifestBodyETag(manifest.Body), manifest.ETag)
		})
	}
}
