package jruntime

import "testing"

func TestGPT6TextModelsExposeJSeriesAliases(t *testing.T) {
	for _, base := range []string{"gpt-6", "gpt-6-astra", "gpt-6-sol", "gpt-6-luna"} {
		if !EligibleModel(base) {
			t.Fatalf("%s must be eligible for J execution", base)
		}
		alias := Alias(base)
		got, ok := BaseModel(alias)
		if !ok || got != base {
			t.Fatalf("BaseModel(%q) = %q, %v; want %q, true", alias, got, ok, base)
		}
	}
}

func TestGPT6JLegacyAliasRemainsAstra(t *testing.T) {
	got, ok := BaseModel("gpt-6j")
	if !ok || got != "gpt-6-astra" {
		t.Fatalf("BaseModel(gpt-6j) = %q, %v; want gpt-6-astra, true", got, ok)
	}
}

func TestJSeriesExcludesMediaAndNonOpenAIModels(t *testing.T) {
	for _, model := range []string{"gpt-image-2", "gpt-6-audio", "claude-opus-5", "grok-4.6"} {
		if EligibleModel(model) {
			t.Fatalf("%s must not be eligible for J execution", model)
		}
	}
}
