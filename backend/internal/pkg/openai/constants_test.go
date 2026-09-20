package openai

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultModelsIncludeBareGPT56Alias(t *testing.T) {
	require.Contains(t, DefaultModelIDs(), "gpt-5.6")
}

func TestDefaultModelsIncludeGPT6Astra(t *testing.T) {
	require.Contains(t, DefaultModelIDs(), "gpt-6-astra")
	require.Contains(t, DefaultModelIDs(), "gpt-6")
	var displayName string
	for _, model := range DefaultModels {
		if model.ID == "gpt-6-astra" {
			displayName = model.DisplayName
			break
		}
	}
	require.Equal(t, "GPT-6 Astra", displayName)
}

func TestDefaultModelsPreferConcreteGPT6AstraForAccountTests(t *testing.T) {
	require.NotEmpty(t, DefaultModels)
	require.Equal(t, "gpt-6-astra", DefaultModels[0].ID)
}

func TestModelsFromIDsPreservesUpstreamCatalog(t *testing.T) {
	models := ModelsFromIDs([]string{"gpt-6-astra", "future-upstream-model"})
	require.Len(t, models, 2)
	require.Equal(t, "GPT-6 Astra", models[0].DisplayName)
	require.Equal(t, "future-upstream-model", models[1].ID)
	require.Equal(t, "future-upstream-model", models[1].DisplayName)
	require.Equal(t, "model", models[1].Object)
}

func TestDefaultModelsIncludeGPTImage25(t *testing.T) {
	require.Contains(t, DefaultModelIDs(), "gpt-image-2.5-flare")
	require.Contains(t, DefaultModelIDs(), "gpt-image-2.5-sunburst")
}
