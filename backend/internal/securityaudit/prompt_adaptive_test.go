package securityaudit

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNextShadowEndpointUsesSavedOrderWithoutModelNames(t *testing.T) {
	endpoints := []ActiveEndpoint{
		{ID: "custom-third", Model: "anything-c"},
		{ID: "custom-first", Model: "anything-a"},
		{ID: "custom-second", Model: "anything-b"},
	}

	next, ok := nextShadowEndpoint(endpoints, "custom-third")
	require.True(t, ok)
	require.Equal(t, "custom-first", next.ID)

	next, ok = nextShadowEndpoint(endpoints, "custom-first")
	require.True(t, ok)
	require.Equal(t, "custom-second", next.ID)

	_, ok = nextShadowEndpoint(endpoints, "custom-second")
	require.False(t, ok)
	_, ok = nextShadowEndpoint(endpoints, "missing")
	require.False(t, ok)
}

func TestDeterministicAuditSampleIsStableAndBounded(t *testing.T) {
	require.False(t, deterministicAuditSample("same", 0))
	require.True(t, deterministicAuditSample("same", 100))
	require.Equal(t, deterministicAuditSample("same", 37), deterministicAuditSample("same", 37))
}

func TestAdaptiveResultsAgreeIncludesSeparateCategoryAxes(t *testing.T) {
	primary := &NormalizedResult{
		Decision: EventCritical, Action: ActionBlock,
		Categories: []string{"violent"}, IntentCategories: []string{}, ContentCategories: []string{"violence"},
	}
	shadow := *primary
	require.True(t, adaptiveResultsAgree(primary, &shadow))
	shadow.ContentCategories = []string{"violence_graphic"}
	require.False(t, adaptiveResultsAgree(primary, &shadow))
}
