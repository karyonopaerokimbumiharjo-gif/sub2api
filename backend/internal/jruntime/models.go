package jruntime

import "strings"

// The product name is a reversible alias; it never selects another base model.
func BaseModel(model string) (string, bool) {
	if model == "gpt-6j" {
		return "gpt-6-astra", true
	}
	if strings.HasSuffix(model, "-j") && EligibleModel(strings.TrimSuffix(model, "-j")) {
		return strings.TrimSuffix(model, "-j"), true
	}
	return model, false
}
func EligibleModel(model string) bool {
	return !strings.HasSuffix(model, "-j") && !strings.Contains(model, "image") && !strings.Contains(model, "audio") && (strings.HasPrefix(model, "gpt-") || strings.HasPrefix(model, "codex-")) && model != "gpt-6j"
}
func Alias(model string) string { return model + "-j" }
