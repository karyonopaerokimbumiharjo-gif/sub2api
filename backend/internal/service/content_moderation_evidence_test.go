package service

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

func TestNativeModerationEvidenceRetainsActualAuditedTextBeyondPreview(t *testing.T) {
	text := strings.Repeat("请审阅这段普通说明。", 70) + "AUDIT_END_MARKER"
	body, err := json.Marshal(map[string]any{"model": "example-model", "input": text, "instructions": "REQUEST_CONTEXT"})
	require.NoError(t, err)
	log := (&ContentModerationService{}).buildLog(ContentModerationCheckInput{Body: body}, &ContentModerationConfig{}, "allow", false, "", 0, nil, text, nil, nil, "")
	require.NotContains(t, log.InputExcerpt, "AUDIT_END_MARKER")
	require.Equal(t, text, log.AuditedPrompt)
	require.Contains(t, log.FullPrompt, "REQUEST_CONTEXT")
	require.Contains(t, log.FullPrompt, "AUDIT_END_MARKER")
	require.Len(t, log.PromptHash, 64)
	require.False(t, log.ContentTruncated)
	serialized, err := json.Marshal(log)
	require.NoError(t, err)
	require.NotContains(t, string(serialized), "AUDIT_END_MARKER", "list APIs must not disclose full evidence")
}

func TestNativeModerationEvidenceRedactsSecretsAndBinaryMedia(t *testing.T) {
	body := []byte(`{"api_key":"short-key","password":"tiny","input":[{"type":"input_image","image_url":"data:image/png;base64,short-media"},{"role":"user","content":"Hello"}],"extra":{"refresh_token":"refresh-value"},"file_data":"file-bytes","audio":{"format":"wav","data":"audio-bytes"},"source":{"type":"base64","data":"base64-bytes"}}`)
	full, audited, _, truncated := nativeModerationEvidence(body, "Hello")
	for _, secret := range []string{"short-key", "tiny", "short-media", "refresh-value", "file-bytes", "audio-bytes", "base64-bytes"} {
		require.NotContains(t, full, secret)
	}
	require.Contains(t, full, "媒体内容未保存")
	require.Equal(t, "Hello", audited)
	require.False(t, truncated)
}

func TestNativeModerationEvidenceBoundsUnicodeWithoutInventingHistory(t *testing.T) {
	text := strings.Repeat("甲", maxNativeAuditEvidenceRunes+20)
	body, _ := json.Marshal(map[string]string{"input": text})
	full, audited, _, truncated := nativeModerationEvidence(body, text)
	require.True(t, truncated)
	require.LessOrEqual(t, utf8.RuneCountInString(full), maxNativeAuditEvidenceRunes)
	require.LessOrEqual(t, utf8.RuneCountInString(audited), maxNativeAuditEvidenceRunes)
	require.True(t, utf8.ValidString(full))
	full, audited, hash, truncated := nativeModerationEvidence(nil, "")
	require.Empty(t, full)
	require.Empty(t, audited)
	require.Empty(t, hash)
	require.False(t, truncated)
}

func TestNativeModerationEvidenceRedactsValuesBeforeJSONEncoding(t *testing.T) {
	input := "Before secret\napi_key=sk-example-not-a-real-secret-1234567890\nNATIVE_EVIDENCE_END ordinary text"
	body, err := json.Marshal(map[string]any{"input": input})
	require.NoError(t, err)
	full, audited, _, _ := nativeModerationEvidence(body, input)
	var saved map[string]any
	require.NoError(t, json.Unmarshal([]byte(full), &saved))
	require.Contains(t, saved["input"], "NATIVE_EVIDENCE_END ordinary text")
	require.Equal(t, audited, saved["input"], "JSON escapes must not extend a secret redaction past a newline")
	require.NotContains(t, full, "sk-example-not-a-real-secret-1234567890")
}
