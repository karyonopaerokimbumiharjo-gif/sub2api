package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStripLegacyCodexTicketExtra(t *testing.T) {
	original := map[string]any{
		"codex_turn_ticket:gpt-6-astra": map[string]any{"state": "secret"},
		"codex_harvest_proxy_url":       "socks5h://secret@example.com:1080",
		"codex_usage":                   map[string]any{"plan": "pro"},
		"ordinary":                      "retained",
	}
	clean := StripLegacyCodexTicketExtra(original)
	require.Equal(t, map[string]any{
		"codex_usage": map[string]any{"plan": "pro"},
		"ordinary":    "retained",
	}, clean)
	require.Contains(t, original, "codex_turn_ticket:gpt-6-astra")
	require.Contains(t, original, "codex_harvest_proxy_url")
	require.Nil(t, StripLegacyCodexTicketExtra(nil))
}
