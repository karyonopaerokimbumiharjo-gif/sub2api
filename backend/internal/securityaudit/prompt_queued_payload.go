package securityaudit

import (
	"encoding/json"
	"strings"
)

const queuedPromptPayloadVersion = 1

// queuedPromptPayload keeps the exact received text and the selected audit
// scope in transient Redis storage. PostgreSQL jobs continue to contain only
// redacted metadata; old raw-string payloads remain readable after deployment.
type queuedPromptPayload struct {
	Version             int      `json:"version"`
	AuditMode           string   `json:"audit_mode"`
	FullPrompt          string   `json:"full_prompt"`
	AuditedPrompt       string   `json:"audited_prompt"`
	ScanText            string   `json:"scan_text"`
	SegmentFingerprints []string `json:"segment_fingerprints,omitempty"`
}

func encodeQueuedPromptPayload(snapshot PromptSnapshot, auditMode string) (string, error) {
	payload := queuedPromptPayload{
		Version: queuedPromptPayloadVersion, AuditMode: auditMode,
		FullPrompt: snapshot.FullPrompt, AuditedPrompt: snapshot.AuditedPrompt,
		ScanText:            snapshot.ScanText,
		SegmentFingerprints: append([]string(nil), snapshot.SegmentFingerprints...),
	}
	raw, err := json.Marshal(payload)
	return string(raw), err
}

func decodeQueuedPromptPayload(value string) queuedPromptPayload {
	var payload queuedPromptPayload
	if strings.HasPrefix(strings.TrimSpace(value), "{") && json.Unmarshal([]byte(value), &payload) == nil && payload.Version == queuedPromptPayloadVersion && payload.ScanText != "" {
		return payload
	}
	// Backward compatibility for jobs queued by the prior release.
	return queuedPromptPayload{
		Version:    queuedPromptPayloadVersion,
		AuditMode:  BlockingAuditModeFull,
		FullPrompt: FullPromptFromScanText(value), AuditedPrompt: FullPromptFromScanText(value), ScanText: value,
	}
}
