package securityaudit

import (
	"net/url"
	"regexp"
	"strings"
)

const (
	knownRepositoryGuardEndpoint = "local-repository-guard"
	knownRepositoryPolicyID      = "known_jailbreak_repository"
	knownRepositoryPolicyVersion = 1
)

var (
	knownRepositoryURLPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:https?://)?(?:www\.)?github\.com/mdx-tom/gpt-5\.6-instruct(?:\.git)?(?:[/?#][^\s<]*)?`),
		regexp.MustCompile(`(?i)(?:https?://)?raw\.githubusercontent\.com/mdx-tom/gpt-5\.6-instruct(?:/[^\s<]*)?`),
		regexp.MustCompile(`(?i)(?:https?://)?api\.github\.com/repos/mdx-tom/gpt-5\.6-instruct(?:/[^\s<]*)?`),
		regexp.MustCompile(`(?i)git@github\.com:mdx-tom/gpt-5\.6-instruct(?:\.git)?`),
	}
	knownRepositoryArtifactPattern = regexp.MustCompile(`(?i)(?:gpt-5\.6-sol-unrestricted-v\d+|codex-instruct\.py)`)
	knownRepositoryInstallPattern  = regexp.MustCompile(`(?i)(?:git\s+clone|python3?\s+[^\n\r]*codex-instruct\.py|--apply\b|--restore-snapshot\b|model_instructions_file\s*=|\b(?:install|deploy|enable|activate|load|run|apply)\b|安装|部署|启用|激活|加载|运行|应用)`)
	knownRepositoryBypassPattern   = regexp.MustCompile(`(?i)(?:unrestricted|jailbreak|bypass|disable\s+(?:the\s+)?safety|suppress\s+(?:refusal|safety)|越狱|破甲|绕过.{0,12}(?:安全|审查|限制)|抑制.{0,8}(?:拒绝|回退))`)
	knownRepositoryReviewPattern   = regexp.MustCompile(`(?i)(?:分析|审查|审核|判断|确认|解释|调查|检测|识别|是否.{0,8}(?:危险|风险|违规|越狱|破甲)|为什么.{0,8}(?:危险|风险|违规|拦截)|(?:security\s+)?(?:review|audit|analysis)|analy[sz]e|explain|is\s+this.{0,16}(?:unsafe|dangerous|a\s+jailbreak)|detect.{0,12}(?:risk|jailbreak))`)
)

func MatchKnownRepositorySnapshotPolicy(snapshot PromptSnapshot, enabledScanners []string) *NormalizedResult {
	text := snapshot.ScanText
	// Blocking snapshots prioritize the latest user turn before this separator
	// and may append the previous assistant output for semantic context. A local
	// deterministic deny rule must not repeatedly block a benign new turn merely
	// because the prior model output quoted the repository. Output observations,
	// on the other hand, intentionally inspect the complete generated text.
	if !strings.EqualFold(strings.TrimSpace(snapshot.Stage), "output") {
		if index := strings.Index(text, promptAuditPrioritySeparator); index >= 0 {
			text = text[:index]
		}
	}
	return MatchKnownRepositoryPolicy(text, enabledScanners)
}

// MatchKnownRepositoryPolicy provides a deterministic, zero-upstream guard for
// a repository that explicitly distributes jailbreak instructions. It is
// intentionally narrow: generic GitHub links and ordinary Codex configuration
// discussions remain eligible for the semantic classifier.
func MatchKnownRepositoryPolicy(text string, enabledScanners []string) *NormalizedResult {
	if !repositoryPolicyScannerEnabled(enabledScanners) || strings.TrimSpace(text) == "" {
		return nil
	}

	normalized := strings.ToLower(text)
	if decoded, err := url.PathUnescape(normalized); err == nil && decoded != normalized {
		normalized += "\n" + decoded
	}

	repositoryMatch := false
	for _, pattern := range knownRepositoryURLPatterns {
		if pattern.MatchString(normalized) {
			repositoryMatch = true
			break
		}
	}
	artifactMatch := knownRepositoryArtifactPattern.MatchString(normalized)
	installMatch := knownRepositoryInstallPattern.MatchString(normalized)
	bypassMatch := knownRepositoryBypassPattern.MatchString(normalized)
	modelInstructionMatch := strings.Contains(normalized, "model_instructions_file")

	// A bare generic configuration key is not enough. Copied content without a
	// URL must contain a repository-specific artifact, or pair the configuration
	// mechanism with an explicit unrestricted/bypass signal.
	if !repositoryMatch && (!artifactMatch || (!installMatch && !bypassMatch)) && (!modelInstructionMatch || !bypassMatch) {
		return nil
	}

	action := ActionBlock
	decision := EventCritical
	risk := RiskCritical
	safety := "Unsafe"
	score := 1.0
	evidence := "known jailbreak repository or deployment signature"
	// Permit an explicit security-review question about the repository when it
	// does not also ask to install, apply, run, or activate its instructions.
	if repositoryMatch && knownRepositoryReviewPattern.MatchString(normalized) && !installMatch {
		action = ActionWarn
		decision = EventFlag
		risk = RiskHigh
		safety = "Controversial"
		score = 0.8
		evidence = "known jailbreak repository referenced for security review"
	}

	return &NormalizedResult{
		Decision: decision, RiskLevel: risk, Action: action, Safety: safety,
		Categories: []string{"jailbreak"}, IntentCategories: []string{"jailbreak"}, ContentCategories: []string{},
		MatchedScanners: []string{"jailbreak"}, ScannerScores: map[string]float64{"jailbreak": score},
		ScannerEvidence: map[string]string{"jailbreak": evidence}, ScannerBackend: "local-repository-policy",
		ScannerVersion: "v1", GuardEndpointID: knownRepositoryGuardEndpoint,
		PolicyID: knownRepositoryPolicyID, PolicyVersion: knownRepositoryPolicyVersion, ChunkTotal: 1,
	}
}

func repositoryPolicyScannerEnabled(enabledScanners []string) bool {
	for _, scanner := range enabledScanners {
		if strings.EqualFold(strings.TrimSpace(scanner), "jailbreak") {
			return true
		}
	}
	return false
}
