package securityaudit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Wei-Shaw/sub2api/internal/pkg/auditpolicy"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"golang.org/x/text/unicode/norm"
)

const globalCTFPolicyID = "operator_ctf_deny"
const globalPolicyVersion = 1

var globalPercentEncodingPattern = regexp.MustCompile(`(?:%[0-9a-fA-F]{2})+`)

var ctfPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?:^|[^a-z0-9])(?:[a-z0-9_-]*ctf(?:time|show|hub|learn|wiki|d)?)(?:$|[^a-z0-9])`),
	regexp.MustCompile(`(?:^|[^a-z0-9])c[\s._-]*t[\s._-]*f(?:$|[^a-z0-9])`),
	regexp.MustCompile(`capture[\s_-]*(?:the[\s_-]*)?flag|夺旗|奪旗`),
	regexp.MustCompile(`(?:pwn|web|crypto|misc|reverse|reversing|隐写|隱寫|逆向|密码学|密碼學)[\s_-]*(?:题目|题解|题|題|challenge|write[\s_-]*up)`),
	regexp.MustCompile(`(?:拿|获取|获取到|获取出|获得|读取|提取|找到|找出|提交|获取到|获取出|獲取|讀取|提交)[\s\p{Han}]{0,8}flag\b`),
	regexp.MustCompile(`\b(?:get|capture|retrieve|extract|submit|find|obtain)\s+(?:the\s+|a\s+)?flag\b|\bflag\{[^}]{1,256}\}`),
	regexp.MustCompile(`(?:网络|網絡|安全|漏洞|攻防|渗透|滲透|授权|授權)靶场|(?:网络|網絡|安全|漏洞|攻防|滲透|授權)靶場`),
	regexp.MustCompile(`(?:^|[^a-z0-9])(?:hackthebox|tryhackme|overthewire|pwnable[.](?:tw|kr)|pwn[.]college|root-me[.]org)(?:$|[^a-z0-9])`),
}

// This is an operator's category ban, not a claim that competitions or
// authorized security education are inherently illegal or malicious.
func MatchCTFPolicy(text string) *NormalizedResult {
	text = normalizeGlobalPolicyText(text)
	for _, pattern := range ctfPatterns {
		if pattern.MatchString(text) {
			return globalCTFBlockedResult()
		}
	}
	return nil
}

func normalizeGlobalPolicyText(text string) string {
	text = html.UnescapeString(text)
	for i := 0; i < 3; i++ {
		decoded := globalPercentEncodingPattern.ReplaceAllStringFunc(text, func(part string) string { value, _ := url.PathUnescape(part); return value })
		if decoded == text {
			break
		}
		text = decoded
	}
	text = norm.NFKC.String(html.UnescapeString(text))
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) {
			return -1
		}
		return unicode.ToLower(r)
	}, text)
}

func globalCTFBlockedResult() *NormalizedResult {
	return &NormalizedResult{Decision: EventCritical, RiskLevel: RiskCritical, Action: ActionBlock, Safety: "Unsafe",
		Categories: []string{"ctf"}, IntentCategories: []string{"ctf"}, ContentCategories: []string{},
		MatchedScanners: []string{"ctf"}, ScannerScores: map[string]float64{"ctf": 1},
		ScannerEvidence: map[string]string{"ctf": "平台全局规则禁止 CTF 相关内容，包括竞赛、学习、题解、引用和授权靶场场景"},
		ScannerBackend:  "local-global-policy", ScannerVersion: "v1", GuardEndpointID: "local-global-guard",
		PolicyID: globalCTFPolicyID, PolicyVersion: globalPolicyVersion, ChunkTotal: 1}
}

func matchGlobalPolicyText(text string) *NormalizedResult {
	if result := MatchCTFPolicy(text); result != nil {
		return result
	}
	return matchOperatorRepositoryPolicy(text)
}

// Inspect all received roles and metadata before audit-scope selection. Binary
// base64 is never searched as text; supported text files are decoded by the
// bounded plain-text data URL decoding. No remote resource is fetched.
func matchGlobalRequestPolicy(body []byte) *NormalizedResult {
	return matchSelectedGlobalRequestPolicy(body, true, true)
}
func matchSelectedGlobalRequestPolicy(body []byte, ctf, repository bool) *NormalizedResult {
	matchText := func(text string) *NormalizedResult {
		if ctf {
			if result := MatchCTFPolicy(text); result != nil {
				return result
			}
		}
		if repository {
			return matchOperatorRepositoryPolicy(text)
		}
		return nil
	}

	var document any
	if json.Unmarshal(body, &document) != nil {
		return nil
	}
	var visit func(any) *NormalizedResult
	visit = func(value any) *NormalizedResult {
		switch node := value.(type) {
		case string:
			lower := strings.ToLower(node)
			// Only encoded data URLs are opaque here. A plain-text value such
			// as "data:CTF" must not bypass the metadata policy matcher.
			if strings.HasPrefix(lower, "data:") && strings.Contains(lower, ";base64,") {
				if strings.HasPrefix(lower, "data:text/") || strings.HasPrefix(lower, "data:application/json;") {
					if _, encoded, ok := strings.Cut(node, ";base64,"); ok && len(encoded) <= 2<<20 {
						if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil && utf8.Valid(decoded) {
							return matchText(string(decoded))
						}
					}
				}
				return nil
			}
			return matchText(node)
		case []any:
			for _, child := range node {
				if result := visit(child); result != nil {
					return result
				}
			}
		case map[string]any:
			for key, child := range node {
				if result := matchText(key); result != nil {
					return result
				}
				if key == "file_data" {
					if text, ok := child.(string); ok && strings.HasPrefix(strings.ToLower(text), "data:") {
						if hit := visit(text); hit != nil {
							return hit
						}
					}
					continue
				}
				if key == "b64_json" || key == "data" && (stringValue(node["type"]) == "base64" || node["mimeType"] != nil || node["mime_type"] != nil) {
					continue
				}
				if result := visit(child); result != nil {
					return result
				}
			}
		}
		return nil
	}
	if result := visit(document); result != nil {
		return result
	}

	return nil
}

// Operator policies use the original full request, before model scope or
// latest-turn extraction, and share the selected audit source's event stream.
func (s *PromptService) CheckOperatorPolicy(ctx context.Context, req Request) (*PromptDecision, error) {
	if s == nil || s.config == nil {
		return nil, nil
	}
	cfg, ok := s.config.Active()
	if !ok {
		return nil, &GuardError{Code: ErrorCodeUnavailable}
	}
	if !cfg.OperatorPolicyEnabled || cfg.NativeAuditEnabled && cfg.NativeAuditProfile == auditpolicy.NativeProfileUpstream {
		return nil, nil
	}
	categories := auditpolicy.ResolveNativeCategories(cfg.NativeRiskCategories, cfg.Scanners, cfg.OperatorPolicyEnabled)
	result := matchSelectedGlobalRequestPolicy(req.Body, auditpolicy.HasCategory(categories, "operator_ctf"), auditpolicy.HasCategory(categories, "operator_repository"))
	if result == nil {
		return nil, nil
	}
	snapshot, err := ExtractPromptSnapshot(req)
	if err != nil {
		snapshot = PromptSnapshot{RequestID: req.RequestID, UserID: req.UserID, UsernameSnapshot: req.Username, UserEmailSnapshot: req.UserEmail,
			APIKeyID: req.APIKeyID, APIKeyNameSnapshot: req.APIKeyName, GroupID: req.GroupID, GroupName: req.GroupName, Provider: req.Provider, Protocol: req.Protocol,
			Endpoint: req.Endpoint, Model: req.Model, AuditSubject: "input"}
	}
	snapshot.FullPrompt = service.AuditRequestEvidence(req.Body)
	snapshot.AuditedPrompt = snapshot.FullPrompt
	snapshot.Stage = "local_hard_rules"
	if cfg.NativeAuditEnabled {
		snapshot.Stage = "native_hard_rules"
	}
	if req.Stage == "native_output" {
		snapshot.Stage = "native_output"
		snapshot.AuditSubject = "output"
	}
	if s.evaluator == nil {
		return nil, &GuardError{Code: ErrorCodeUnavailable}
	}
	decision, err := s.evaluator.finishEvaluation(ctx, cfg, snapshot, result, true, s.evaluator.clock.Now(), snapshotLogFields(snapshot))
	if decision != nil {
		decision.Snapshot = &snapshot
	}
	return decision, err
}

func operatorPolicyEnabled(value *bool) bool { return value == nil || *value }
