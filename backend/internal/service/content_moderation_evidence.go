package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"unicode/utf8"
)

const maxNativeAuditEvidenceRunes = 65536

// Native moderation reviews extracted current-turn text. Preserve both that
// actual input and a bounded request copy, so review never implies that the
// whole request was submitted to the moderation model. Binary media and
// credential fields are removed before the request is persisted.
func nativeModerationEvidence(body []byte, auditedText string) (full, audited, hash string, truncated bool) {
	var request any
	if len(body) > 0 && json.Unmarshal(body, &request) == nil {
		redactNativeAuditValue(request)
		if text, ok := request.(string); ok {
			request = redactContentModerationSecrets(text)
		}
		if encoded, err := json.MarshalIndent(request, "", "  "); err == nil {
			full = string(encoded)
		}
	}
	audited = redactContentModerationSecrets(auditedText)
	truncated = utf8.RuneCountInString(full) > maxNativeAuditEvidenceRunes || utf8.RuneCountInString(audited) > maxNativeAuditEvidenceRunes
	full = trimRunes(full, maxNativeAuditEvidenceRunes)
	audited = trimRunes(audited, maxNativeAuditEvidenceRunes)
	if auditedText != "" {
		digest := sha256.Sum256([]byte(auditedText))
		hash = hex.EncodeToString(digest[:])
	}
	return
}

func redactNativeAuditValue(value any) {
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			normalized := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(key, "-", ""), "_", ""))
			switch normalized {
			case "filedata", "imagedata":
				node[key] = "[媒体内容未保存]"
				continue
			case "authorization", "apikey", "accesstoken", "refreshtoken", "idtoken", "sessiontoken", "cookie", "setcookie", "password", "passwd", "secret", "clientsecret", "privatekey":
				node[key] = "[已脱敏]"
				continue
			}
			if normalized == "data" && (node["type"] == "base64" || node["format"] == "wav" || node["format"] == "mp3") {
				node[key] = "[媒体内容未保存]"
				continue
			}
			if text, ok := child.(string); ok {
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(text)), "data:") {
					node[key] = "[媒体内容未保存]"
				} else {
					node[key] = redactContentModerationSecrets(text)
				}
				continue
			}
			redactNativeAuditValue(child)
		}
	case []any:
		for i, child := range node {
			if text, ok := child.(string); ok {
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(text)), "data:") {
					node[i] = "[媒体内容未保存]"
				} else {
					node[i] = redactContentModerationSecrets(text)
				}
				continue
			}
			redactNativeAuditValue(child)
		}
	}
}
