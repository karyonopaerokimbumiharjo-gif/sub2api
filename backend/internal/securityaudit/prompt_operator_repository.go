package securityaudit

import (
	"html"
	"net/url"
	"regexp"
	"strings"
)

const (
	operatorRepositoryGuardEndpoint = "local-repository-guard"
	operatorRepositoryPolicyID      = "known_jailbreak_repository"
	operatorRepositoryPolicyVersion = 3
)

var (
	// Whole names cover bare references, renamed/legacy URLs, raw, Pages and
	// clone links. Boundaries exclude unrelated projects sharing a prefix.
	operatorRepositoryNamePattern     = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_.-])(?:gpt-instruct|gpt-5\.6-instruct)(?:\.git)?(?:$|[^a-z0-9_.-]|\.(?:$|[^a-z0-9_.-]))`)
	operatorRepositoryArtifactPattern = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_.-])(?:codex-instruct\.py|gpt-5\.6-sol-(?:unrestricted-)?v\d+(?:-skills)?(?:\.(?:md|zip))?|gpt-6-astra-v\d+(?:-rc\d+|-e\d+b\d+)?(?:\.(?:md|zip))?|gpt-5\.6-instruct[-_]v\d+(?:\.(?:md|zip))?)(?:$|[^a-z0-9_.-]|\.(?:$|[^a-z0-9_.-]))`)
)

// matchOperatorRepositoryPolicy implements the operator's repository deny rule.
// Review, explanation and removal references are also policy violations.
func matchOperatorRepositoryPolicy(text string) *NormalizedResult {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	normalized := normalizeGlobalPolicyText(html.UnescapeString(text))
	decoded := normalized
	for i := 0; i < 3; i++ {
		next, err := url.PathUnescape(decoded)
		if err != nil || next == decoded {
			break
		}
		normalized += "\n" + next
		decoded = next
	}
	normalized = strings.ToLower(strings.Join(strings.Fields(normalized), " "))
	if match := matchedDeniedRepositoryReference(normalized); match != "" {
		result := operatorRepositoryBlockedResult()
		result.ScannerEvidence["jailbreak"] = "operator-denied repository identifier: " + strings.TrimSpace(match)
		return result
	}
	for _, pattern := range []*regexp.Regexp{operatorRepositoryNamePattern, operatorRepositoryArtifactPattern} {
		if match := pattern.FindString(normalized); match != "" {
			result := operatorRepositoryBlockedResult()
			result.ScannerEvidence["jailbreak"] = "operator-denied repository identifier: " + strings.TrimSpace(match)
			return result
		}
	}
	if matchesOperatorRepositoryTemplate(normalized) {
		return operatorRepositoryBlockedResult()
	}

	return nil
}

// Conjunctions identify published prompt families copied without URLs/names.
// Generic model names, license text and individual artifact words are not enough.
func matchesOperatorRepositoryTemplate(text string) bool {
	for _, markers := range [][]string{
		{"[mode: unrestricted]", "codex is a sandbox executor.", "hard output rules"},
		{"[mode: unrestricted]", "first-pass normalizer", "fiction_template"},
		{"[mode: unrestricted]", "tool_transaction", "process_record", "single-pass task compiler"},
		{"atomic continuation dispatch", "modified_file", "diff_file", "verification.txt", "rollback.sh"},
	} {
		matched := true
		for _, marker := range markers {
			if !strings.Contains(text, marker) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func operatorRepositoryBlockedResult() *NormalizedResult {
	return &NormalizedResult{
		Decision: EventCritical, RiskLevel: RiskCritical, Action: ActionBlock, Safety: "Unsafe",
		Categories: []string{"jailbreak"}, IntentCategories: []string{"jailbreak"}, ContentCategories: []string{},
		MatchedScanners: []string{"jailbreak"}, ScannerScores: map[string]float64{"jailbreak": 1},
		ScannerEvidence: map[string]string{"jailbreak": "operator-denied repository reference, artifact or known template"}, ScannerBackend: "local-repository-policy",
		ScannerVersion: "v3", GuardEndpointID: operatorRepositoryGuardEndpoint,
		PolicyID: operatorRepositoryPolicyID, PolicyVersion: operatorRepositoryPolicyVersion, ChunkTotal: 1,
	}
}
