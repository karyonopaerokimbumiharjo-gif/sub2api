package securityaudit

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestGenericJSONClassifierRejectsAnswersAndAmbiguousVerdicts(t *testing.T) {
	safe := `{"safety":"Safe","intent_categories":[],"content_categories":[],"bio_tier":"B0"}`
	result, err := parseGenericGuardJSON(safe, AllScannerIDs)
	require.NoError(t, err)
	require.Equal(t, ActionAllow, result.Action)
	for _, raw := range []string{
		"J14_BASIC_OK", "Here is the requested code.", "```json\n" + safe + "\n```",
		strings.Replace(safe, `"safety":"Safe"`, `"safety":"Unsafe","safety":"Safe"`, 1),
		strings.Replace(safe, `"bio_tier":"B0"`, `"bio_tier":"B2"`, 1),
		strings.Replace(safe, `"intent_categories":[]`, `"intent_categories":null`, 1),
		strings.Replace(safe, `"intent_categories":[]`, `"intent_categories":["None"]`, 1),
		strings.Replace(safe, `"safety":"Safe"`, `"Safety":"Safe"`, 1),
		strings.Replace(safe, `"safety":"Safe"`, `"safety":"Safe","answer":"anything"`, 1),
		safe + safe,
	} {
		_, err := parseGenericGuardJSON(raw, AllScannerIDs)
		require.Error(t, err, raw)
	}
	for _, finish := range []string{"length", "content_filter", "tool_calls"} {
		raw, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"finish_reason": finish, "message": map[string]string{"content": safe}}}})
		_, err := extractOpenAIContent(raw)
		require.Error(t, err)
	}
}
