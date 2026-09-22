package service

import "strings"

// StripLegacyCodexTicketExtra prevents historical collector credentials from
// reappearing through old imports or account edits after their DB migration.
// All unrelated account metadata remains unchanged.
// It returns a new map and does not mutate the caller's map.
func StripLegacyCodexTicketExtra(extra map[string]any) map[string]any {
	if extra == nil {
		return nil
	}
	clean := make(map[string]any, len(extra))
	for key, value := range extra {
		if strings.HasPrefix(key, "codex_turn_ticket:") || key == "codex_harvest_proxy_url" {
			continue
		}
		clean[key] = value
	}
	return clean
}
