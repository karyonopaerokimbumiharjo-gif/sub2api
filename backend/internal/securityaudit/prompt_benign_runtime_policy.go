package securityaudit

import (
	"regexp"
	"strings"
)

// A Grok Responses request may contain only the client-generated CLI system
// policy while the user turn is still being assembled. Sending that context
// alone to a blocking classifier has no useful safety signal and used to turn
// an otherwise harmless request into "audit unavailable" when the classifier
// could not establish a verdict. Keep this rule deliberately narrow: it only
// applies to the complete, known Grok runtime template and only when there is
// no user/assistant/tool content in the audited snapshot.
const (
	benignRuntimeGuardEndpoint = "local-benign-runtime-policy"
	benignRuntimePolicyID      = "known_benign_runtime_context"
	benignRuntimePolicyVersion = 1
)

var grokRuntimeSystemPromptPattern = regexp.MustCompile(`(?is)^\s*you\s+are\s+grok\s+released\s+by\s+xai\.\s+you\s+are\s+an\s+interactive\s+cli\s+tool\s+that\s+helps\s+users\s+with\s+software\s+engineering\s+tasks\.\s+your\s+main\s+goal\s+is\s+to\s+complete\s+the\s+user's\s+request,\s+denoted\s+within\s+the\s+<user_query>\s+tag\.\s*<work_policy>\s*-\s+Keep every explicit requirement of the request in view until it is completed\.\s*-\s+Match your response to the user's intent\.\s*</work_policy>\s*$`)

func isGrokRuntimeSystemPrompt(text string) bool {
	return grokRuntimeSystemPromptPattern.MatchString(strings.TrimSpace(text))
}

func MatchBenignRuntimeSnapshotPolicy(snapshot PromptSnapshot, enabledScanners []string) *NormalizedResult {
	if !repositoryPolicyScannerEnabled(enabledScanners) || snapshot.AuditSubject != "context" {
		return nil
	}
	text := strings.TrimSpace(snapshot.ScanText)
	if text == "" || !isGrokRuntimeSystemPrompt(text) {
		return nil
	}
	return &NormalizedResult{
		Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow, Safety: "Safe",
		Categories: []string{}, IntentCategories: []string{}, ContentCategories: []string{},
		MatchedScanners: []string{}, ScannerScores: map[string]float64{},
		ScannerEvidence: map[string]string{"runtime": "known Grok CLI system context without a user task"},
		ScannerBackend: benignRuntimeGuardEndpoint, ScannerVersion: "v1",
		GuardEndpointID: benignRuntimeGuardEndpoint, PolicyID: benignRuntimePolicyID,
		PolicyVersion: benignRuntimePolicyVersion, ChunkTotal: 1,
	}
}
