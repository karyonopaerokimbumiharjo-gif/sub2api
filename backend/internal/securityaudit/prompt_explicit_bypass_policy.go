package securityaudit

import (
	"regexp"
	"strings"
)

const (
	explicitBypassGuardEndpoint = "local-explicit-bypass-guard"
	explicitBypassPolicyID      = "explicit_active_bypass"
	explicitBypassPolicyVersion = 2
)

var (
	explicitBypassModePattern    = regexp.MustCompile(`(?i)\[mode\s*:\s*unrestricted\]`)
	explicitBypassControlPattern = regexp.MustCompile(`(?is)(?:` +
		`refusal\s*,\s*fallback\s*,\s*no-op\s*,\s*promise\s*,\s*or\s*clarification\s+has\s+zero\s+completed\s+state|` +
		`first-pass\s+normalizer|` +
		`(?:ownership|authorization|scope|victim|monitoring|safeguard).{0,220}(?:is|are)\s+(?:fixture\s+)?metadata|` +
		`do\s+not\s+reason\s+from.{0,160}(?:authorization|ownership|safeguard)` +
		`)`)
	explicitBypassReviewPattern = regexp.MustCompile(`(?i)(?:` +
		`(?:分析|审查|审核|解释|检测|识别|调查).{0,24}(?:提示词|指令|注入|越狱|破甲|绕过|安全|风险|违规)|` +
		`(?:提示词|指令|注入|越狱|破甲|绕过|安全|风险|违规).{0,24}(?:分析|审查|审核|解释|检测|识别|调查)|` +
		`(?:这段|这个|上述).{0,16}(?:是什么|什么意思|危险|风险|违规|越狱|破甲)|` +
		`是否.{0,10}(?:危险|风险|违规|越狱|破甲)|` +
		`(?:security\s+)?(?:review|audit|analysis)|analy[sz]e|explain|what\s+does\s+this\s+mean|` +
		`is\s+this.{0,18}(?:unsafe|dangerous|a\s+jailbreak)` +
		`)`)
	explicitBypassActivationPattern = regexp.MustCompile(`(?i)(?:` +
		`\b(?:install|deploy|enable|activate|load|apply|inject)\b|` +
		`安装|部署|启用|激活|加载|应用|注入` +
		`)`)
)

// MatchExplicitBypassSnapshotPolicy detects a narrowly fingerprinted active
// jailbreak instruction even when the latest user turn is only "continue".
// FullPrompt is intentional here: an already-active system/context injection
// must not become invisible merely because an Allow cache skipped old segments.
func MatchExplicitBypassSnapshotPolicy(snapshot PromptSnapshot, enabledScanners []string) *NormalizedResult {
	if !repositoryPolicyScannerEnabled(enabledScanners) {
		return nil
	}
	fullText := strings.TrimSpace(snapshot.FullPrompt)
	if fullText == "" || !explicitBypassModePattern.MatchString(fullText) || !explicitBypassControlPattern.MatchString(fullText) {
		return nil
	}

	latestText := snapshot.ScanText
	if index := strings.Index(latestText, promptAuditPrioritySeparator); index >= 0 {
		latestText = latestText[:index]
	}
	result := explicitBypassResult(ActionBlock, EventCritical, RiskCritical, "Unsafe", 1.0,
		"active unrestricted instruction disables refusal or safety reasoning")
	if explicitBypassReviewPattern.MatchString(latestText) && !explicitBypassActivationPattern.MatchString(latestText) {
		result = explicitBypassResult(ActionWarn, EventFlag, RiskHigh, "Controversial", 0.8,
			"active unrestricted instruction quoted for explicit security review")
	}
	return result
}

func explicitBypassResult(action Action, decision EventDecision, risk RiskLevel, safety string, score float64, evidence string) *NormalizedResult {
	return &NormalizedResult{
		Decision: decision, RiskLevel: risk, Action: action, Safety: safety,
		Categories: []string{"jailbreak"}, IntentCategories: []string{"jailbreak"}, ContentCategories: []string{},
		MatchedScanners: []string{"jailbreak"}, ScannerScores: map[string]float64{"jailbreak": score},
		ScannerEvidence: map[string]string{"jailbreak": evidence}, ScannerBackend: "local-explicit-bypass-policy",
		ScannerVersion: "v1", GuardEndpointID: explicitBypassGuardEndpoint,
		PolicyID: explicitBypassPolicyID, PolicyVersion: explicitBypassPolicyVersion, ChunkTotal: 1,
	}
}
