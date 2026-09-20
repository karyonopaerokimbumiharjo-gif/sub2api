package securityaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

var (
	ErrNoPromptText = errors.New("prompt audit request contains no user text")

	bearerPattern = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+\-/]+=*`)
	apiKeyPattern = regexp.MustCompile(`(?i)\b(sk|rk|pk|api[_-]?key|token|secret|password)[-_:=\s]+[A-Za-z0-9._~+\-/]{8,}`)
	canaryPattern = regexp.MustCompile(`(?i)([A-Z]+_CANARY_)[A-Za-z0-9_-]+`)
	emailPattern  = regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`)
	phonePattern  = regexp.MustCompile(`(?:\+?\d[\d\s().-]{8,}\d)`)

	systemReminderBlockPattern = regexp.MustCompile(`(?is)<system-reminder\b[^>]*>.*?</system-reminder>`)
	agentsInstructionsPattern  = regexp.MustCompile(`(?is)#\s*AGENTS\.md instructions\s*<INSTRUCTIONS>.*?</INSTRUCTIONS>`)
	environmentContextPattern  = regexp.MustCompile(`(?is)<environment_context\b[^>]*>.*?</environment_context>`)
	internalCommentPattern     = regexp.MustCompile(`(?is)<!--\s*(?:OMO|CODEX)_INTERNAL_[^>]*-->`)
	internalContextTagPattern  = regexp.MustCompile(`(?is)</?codex_internal_context\b[^>]*>`)
	activeModelRuntimePattern  = regexp.MustCompile(`(?is)^\s*\[System:\s*The active model for this chat has changed to .*?what model/provider is active\.\]\s*`)
	nonTaskRunePattern         = regexp.MustCompile(`[^\pL\pN]+`)
)

const (
	codexTitleTaskPrefix      = "You are a helpful assistant. You will be presented with a user prompt, and your job is to provide a short title for a task that will be created from that prompt."
	codexTitleUserMarker      = "User prompt:"
	codexAmbientPrefix        = "# Overview\n\nGenerate 0 to 3 hyperpersonalized suggestions for what this user can do with Codex in this local project:"
	codexAmbientSafetyPrefix  = "You are an expert at upholding safety and compliance standards for Codex ambient suggestions."
	codexCompactionPrefix     = "Another language model started to solve this problem and produced a summary of its thinking process."
	codexActionHistoryPrefix  = "The following is the Codex agent history whose request action you are assessing."
	codexApprovalReviewPrefix = "The following is the Codex agent history added since your last approval assessment."
	codexApprovalActionMarker = "Planned action JSON:"
	codexApprovalActionEnd    = ">>> APPROVAL REQUEST END"
	codexActionJudgeMarker    = "You are judging one planned coding-agent action."
	codexCheckpointPrefix     = "You are performing a CONTEXT CHECKPOINT COMPACTION."
	codexCheckpointHeaderEnd  = "Be concise, structured, and focused on helping the next LLM seamlessly continue the work."
)

const trustedRuntimeAuditMaxRunes = 8000

var codexTranscriptEntryPattern = regexp.MustCompile(`(?m)^\[\d+\]\s+(?:user|assistant|tool exec call|tool exec result):\s*`)

var embeddedAgentRuntimeMarkers = []string{
	"You are Codex, a coding agent based on GPT-5.",
	"You are Codex, an agent based on GPT-5.",
	"You are Codex, a coding agent.",
	"You are Hermes Agent, an intelligent AI assistant created by Nous Research.",
	"<agent-identity>",
	"You are Sisyphus - an AI orchestrator from OhMyOpenCode.",
}

const promptAuditPrioritySeparator = "\x00SUB2API_PROMPT_AUDIT_PRIORITY_END\x00"

type promptSegment struct {
	text          string
	user          bool
	role          string
	continuesTurn bool
}

// IncrementalPromptPlan separates content that must be checked on every turn
// from older/client-controlled context that can be reused after an Allow under
// the same principal and policy version.
type IncrementalPromptPlan struct {
	req        Request
	extracted  []promptSegment
	required   []promptSegment
	candidates []promptSegment
}

func ExtractPromptSnapshot(req Request) (PromptSnapshot, error) {
	extracted, err := extractRequestPromptSegments(req)
	if err != nil {
		return PromptSnapshot{}, err
	}
	plan := buildIncrementalPromptPlan(req, extracted)
	snapshot, _, err := plan.Snapshot(nil)
	return snapshot, err
}

// ExtractBlockingPromptSnapshot keeps the legacy configuration field but no
// longer drops client-controlled roles. Without a cache lookup, incremental
// mode safely audits every extracted segment; PromptService supplies known
// Allow fingerprints to skip only context already checked under this policy.
func ExtractBlockingPromptSnapshot(req Request, latestTurnOnly bool) (PromptSnapshot, error) {
	if !latestTurnOnly {
		return ExtractPromptSnapshot(req)
	}
	plan, err := BuildIncrementalPromptPlan(req)
	if err != nil {
		return PromptSnapshot{}, err
	}
	snapshot, _, err := plan.Snapshot(nil)
	return snapshot, err
}

// ExtractFastBlockingPromptSnapshot restores the legacy low-latency scope:
// the complete latest user turn plus the nearest preceding assistant/model
// output. FullPrompt still preserves the complete received transcript so an
// administrator can see what was omitted from the classifier input.
func ExtractFastBlockingPromptSnapshot(req Request) (PromptSnapshot, error) {
	extracted, err := extractRequestPromptSegments(req)
	if err != nil {
		return PromptSnapshot{}, err
	}
	selected := fastBlockingPromptSegments(extracted)
	return buildPromptSnapshot(req, extracted, selected)
}

func extractRequestPromptSegments(req Request) ([]promptSegment, error) {
	var document any
	if err := json.Unmarshal(req.Body, &document); err != nil {
		return nil, errors.New("prompt audit request JSON is invalid")
	}
	extracted := extractProtocolSegments(req.Protocol, document)
	if len(normalizedPromptSegments(extracted)) == 0 {
		return nil, ErrNoPromptText
	}
	return extracted, nil
}

// BuildIncrementalPromptPlan always keeps the complete latest user turn and
// nearest prior model output. Every other role remains a candidate and is
// included unless Redis proves the exact cleaned segment was previously
// allowed for this principal, model, and config version.
func BuildIncrementalPromptPlan(req Request) (*IncrementalPromptPlan, error) {
	extracted, err := extractRequestPromptSegments(req)
	if err != nil {
		return nil, err
	}
	return buildIncrementalPromptPlan(req, extracted), nil
}

func buildIncrementalPromptPlan(req Request, extracted []promptSegment) *IncrementalPromptPlan {
	normalized := normalizedPromptSegments(extracted)
	latestUserStart := latestUserSegmentStart(normalized)
	if latestUserStart < 0 {
		return &IncrementalPromptPlan{
			req:       req,
			extracted: normalized,
			required:  normalizedPromptSegmentsLatestUserFirst(normalized),
		}
	}
	latestUserEnd := latestUserStart + 1
	for latestUserEnd < len(normalized) && isUserSegment(normalized[latestUserEnd]) && normalized[latestUserEnd].continuesTurn {
		latestUserEnd++
	}
	currentUserText := make([]string, 0, latestUserEnd-latestUserStart)
	for _, segment := range normalized[latestUserStart:latestUserEnd] {
		currentUserText = append(currentUserText, segment.text)
	}
	required := []promptSegment{{text: strings.Join(currentUserText, "\n\n"), user: true, role: "user"}}
	requiredIndexes := make(map[int]struct{}, latestUserEnd-latestUserStart+2)
	for index := latestUserStart; index < latestUserEnd; index++ {
		requiredIndexes[index] = struct{}{}
	}
	for index := latestUserStart - 1; index >= 0; index-- {
		if !isAssistantOutputSegment(normalized[index]) {
			continue
		}
		start := index
		for start > 0 && normalized[start].continuesTurn && isAssistantOutputSegment(normalized[start-1]) {
			start--
		}
		required = append(required, normalized[start:index+1]...)
		for prior := start; prior <= index; prior++ {
			requiredIndexes[prior] = struct{}{}
		}
		break
	}
	candidates := make([]promptSegment, 0, len(normalized)-len(requiredIndexes))
	for index, segment := range normalized {
		if _, required := requiredIndexes[index]; !required {
			candidates = append(candidates, segment)
		}
	}
	return &IncrementalPromptPlan{req: req, extracted: normalized, required: required, candidates: candidates}
}

func (p *IncrementalPromptPlan) CandidateFingerprints() []string {
	if p == nil {
		return nil
	}
	result := make([]string, 0, len(p.candidates))
	seen := make(map[string]struct{}, len(p.candidates))
	for _, segment := range p.candidates {
		fingerprint := promptSegmentFingerprint(segment)
		if fingerprint == "" {
			continue
		}
		if _, duplicate := seen[fingerprint]; duplicate {
			continue
		}
		seen[fingerprint] = struct{}{}
		result = append(result, fingerprint)
	}
	return result
}

func (p *IncrementalPromptPlan) Snapshot(knownAllowed map[string]struct{}) (PromptSnapshot, []string, error) {
	if p == nil {
		return PromptSnapshot{}, nil, ErrNoPromptText
	}
	selected := append([]promptSegment(nil), p.required...)
	newFingerprints := make([]string, 0, len(p.candidates))
	seen := make(map[string]struct{}, len(p.candidates))
	for _, segment := range p.candidates {
		fingerprint := promptSegmentFingerprint(segment)
		if fingerprint == "" {
			continue
		}
		if _, duplicate := seen[fingerprint]; duplicate {
			continue
		}
		seen[fingerprint] = struct{}{}
		if _, allowed := knownAllowed[fingerprint]; allowed {
			continue
		}
		selected = append(selected, segment)
		newFingerprints = append(newFingerprints, fingerprint)
	}
	snapshot, err := buildPromptSnapshot(p.req, p.extracted, selected)
	return snapshot, newFingerprints, err
}

func promptSegmentFingerprint(segment promptSegment) string {
	cleaned := cleanRuntimeAuditPromptSegment(segment)
	if cleaned == "" {
		return ""
	}
	role := strings.ToLower(strings.TrimSpace(segment.role))
	if role == "" {
		role = "user"
	}
	digest := sha256.Sum256([]byte(role + "\x00" + cleaned))
	return hex.EncodeToString(digest[:])
}

func buildPromptSnapshot(req Request, extracted, audited []promptSegment) (PromptSnapshot, error) {
	// FullPrompt is evidence of the request as received, so preserve protocol
	// order. AuditedPrompt is separately priority-ordered for the classifier.
	fullSegments := normalizedPromptSegments(extracted)
	cleanedAuditSegments := cleanRuntimeAuditPromptSegments(audited)
	if req.RequireJev {
		// Runtime-looking tags are still client-controlled evidence. GPT-6J never
		// strips them or relies on the optional incremental allow cache.
		cleanedAuditSegments = normalizedPromptSegments(audited)
	}
	if len(fullSegments) == 0 || len(cleanedAuditSegments) == 0 {
		return PromptSnapshot{}, ErrNoPromptText
	}
	fullMetadataText := strings.Join(promptSegmentTexts(fullSegments), "\n\n")
	auditedTexts := promptSegmentTexts(cleanedAuditSegments)
	auditedMetadataText := strings.Join(auditedTexts, "\n\n")
	scanText, _ := buildPrioritizedScanText(auditedTexts)
	segmentFingerprints := make([]string, 0, len(cleanedAuditSegments))
	seenFingerprints := make(map[string]struct{}, len(cleanedAuditSegments))
	for _, segment := range cleanedAuditSegments {
		fingerprint := promptSegmentFingerprint(segment)
		if fingerprint == "" {
			continue
		}
		if _, duplicate := seenFingerprints[fingerprint]; duplicate {
			continue
		}
		seenFingerprints[fingerprint] = struct{}{}
		segmentFingerprints = append(segmentFingerprints, fingerprint)
	}
	digest := sha256.Sum256([]byte(fullMetadataText))
	taskFingerprint := TaskFingerprintForText(auditedMetadataText)
	stage := strings.TrimSpace(req.Stage)
	if stage == "" {
		stage = "http"
	}
	return PromptSnapshot{
		RequestID: req.RequestID, UserID: req.UserID, UsernameSnapshot: req.Username,
		UserEmailSnapshot: req.UserEmail, APIKeyID: req.APIKeyID, APIKeyNameSnapshot: req.APIKeyName,
		GroupID: cloneInt64Ptr(req.GroupID), GroupName: req.GroupName, Provider: req.Provider,
		Endpoint: req.Endpoint, Protocol: req.Protocol, Model: req.Model,
		PromptHash: hex.EncodeToString(digest[:]), TaskFingerprint: taskFingerprint,
		AuditSubject: classifyAuditSubject(cleanedAuditSegments), RedactedPreview: BuildPromptPreview(auditedMetadataText, DefaultPromptPreviewMaxRunes),
		FullPrompt:    BuildFullPrompt(fullMetadataText, DefaultFullPromptMaxRunes),
		AuditedPrompt: BuildFullPrompt(auditedMetadataText, DefaultFullPromptMaxRunes),
		PromptLength:  utf8.RuneCountInString(auditedMetadataText), MessageCount: len(cleanedAuditSegments), Stage: stage,
		ScanText: scanText, SegmentFingerprints: segmentFingerprints,
	}, nil
}

// TaskFingerprintForText produces a stable, non-reversible task key after
// removing agent-runtime noise. It is used only for alert grouping and scoped
// policy suppression; the exact prompt hash remains available separately.
func TaskFingerprintForText(value string) string {
	canonical := canonicalTaskText(value)
	if canonical == "" {
		return ""
	}
	digest := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(digest[:])
}

func canonicalTaskText(value string) string {
	value = systemReminderBlockPattern.ReplaceAllString(value, " ")
	value = agentsInstructionsPattern.ReplaceAllString(value, " ")
	value = environmentContextPattern.ReplaceAllString(value, " ")
	value = internalCommentPattern.ReplaceAllString(value, " ")
	// codex_internal_context is a wrapper around user-provided task data. Keep
	// its inner objective while removing the runtime-only role marker.
	value = internalContextTagPattern.ReplaceAllString(value, " ")
	value = strings.ToLower(strings.TrimSpace(value))
	value = nonTaskRunePattern.ReplaceAllString(value, " ")
	return strings.Join(strings.Fields(value), " ")
}

func cleanRuntimeAuditSegments(values []string) []string {
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		value = systemReminderBlockPattern.ReplaceAllString(value, " ")
		value = agentsInstructionsPattern.ReplaceAllString(value, " ")
		value = environmentContextPattern.ReplaceAllString(value, " ")
		value = internalCommentPattern.ReplaceAllString(value, " ")
		value = internalContextTagPattern.ReplaceAllString(value, " ")
		if value = strings.TrimSpace(value); value != "" {
			cleaned = append(cleaned, value)
		}
	}
	return cleaned
}

func cleanRuntimeAuditSegment(value string) string {
	cleaned := cleanRuntimeAuditSegments([]string{value})
	if len(cleaned) == 0 {
		return ""
	}
	return cleaned[0]
}

func cleanRuntimeAuditPromptSegments(values []promptSegment) []promptSegment {
	cleaned := make([]promptSegment, 0, len(values))
	for _, value := range normalizedPromptSegments(values) {
		value.text = cleanRuntimeAuditPromptSegment(value)
		if value.text != "" {
			cleaned = append(cleaned, value)
		}
	}
	return cleaned
}

// cleanRuntimeAuditPromptSegment removes only strongly identified client
// runtime envelopes. FullPrompt remains untouched for administrator evidence.
// The latest user task is never truncated merely because it mentions Codex or
// prompt injection: a runtime tail is removed from a user-role segment only
// when an exact client-generated envelope is present.
func cleanRuntimeAuditPromptSegment(segment promptSegment) string {
	text := strings.TrimSpace(segment.text)
	if text == "" {
		return ""
	}

	// Codex ambient generation and its follow-up policy filter are internal
	// control-plane calls, not user requests. The originating user turn is
	// audited separately, and generated suggestions are covered by output audit.
	if strings.HasPrefix(text, codexAmbientPrefix) || strings.HasPrefix(text, codexAmbientSafetyPrefix) {
		return ""
	}

	trustedEnvelope := false
	boundedTrustedEnvelope := false
	// Some approval-review prompts place the current action JSON first and append
	// the prior review transcript afterwards. Audit only that concrete action so
	// stale secrets or rejected actions in the transcript cannot contaminate the
	// current decision. A risky command remains present in full in the JSON.
	if action, ok := extractLeadingApprovalAction(text); ok {
		text = action
		trustedEnvelope = true
	}
	if strings.HasPrefix(text, codexTitleTaskPrefix) {
		if marker := strings.Index(text, codexTitleUserMarker); marker >= 0 {
			text = strings.TrimSpace(text[marker+len(codexTitleUserMarker):])
			trustedEnvelope = true
		}
	}
	// Approval-review calls are internal control-plane requests. Preserve and
	// audit the concrete planned action, but discard the transcript delta and
	// reviewer instructions that otherwise look like prompt injection.
	if strings.HasPrefix(text, codexApprovalReviewPrefix) {
		if marker := strings.Index(text, codexApprovalActionMarker); marker >= 0 {
			action := text[marker+len(codexApprovalActionMarker):]
			if end := strings.Index(action, codexApprovalActionEnd); end >= 0 {
				action = action[:end]
			}
			text = strings.TrimSpace(action)
			trustedEnvelope = true
		}
	}
	// A checkpoint request is also control-plane metadata, but its handoff body
	// can contain the real task. Remove only the fixed header and keep the body.
	if strings.HasPrefix(text, codexCheckpointPrefix) {
		if marker := strings.Index(text, codexCheckpointHeaderEnd); marker >= 0 {
			text = strings.TrimSpace(text[marker+len(codexCheckpointHeaderEnd):])
			trustedEnvelope = true
		}
	}
	if activeModelRuntimePattern.MatchString(text) {
		text = activeModelRuntimePattern.ReplaceAllString(text, "")
		trustedEnvelope = true
	}
	if strings.HasPrefix(text, codexCompactionPrefix) {
		// Compaction payloads can contain hundreds of historical messages and
		// embedded runtime policies. The current objective is conventionally at
		// the beginning and the latest state/action is at the end. Preserve both
		// boundaries instead of sending every stale tool result to the classifier.
		text = TrimRunesHeadTail(text, trustedRuntimeAuditMaxRunes)
		trustedEnvelope = true
		boundedTrustedEnvelope = true
	}
	if strings.HasPrefix(text, codexActionHistoryPrefix) {
		// Action-assessment payloads are a numbered Codex transcript. The latest
		// two user turns plus subsequent assistant/tool actions carry the current
		// intent; older turns are retained in FullPrompt for review but must not
		// contaminate the live classifier with stale secrets or policy text.
		text = recentCodexTranscriptWindow(text, trustedRuntimeAuditMaxRunes)
		trustedEnvelope = true
		boundedTrustedEnvelope = true
	}

	text = cleanRuntimeAuditSegment(text)
	if text == "" {
		return ""
	}
	role := strings.ToLower(strings.TrimSpace(segment.role))
	if role != "user" && role != "" {
		trustedEnvelope = true
	}
	if trustedEnvelope && !boundedTrustedEnvelope {
		text = truncateEmbeddedAgentRuntime(text)
	}
	return strings.TrimSpace(text)
}

func recentCodexTranscriptWindow(value string, maxRunes int) string {
	matches := codexTranscriptEntryPattern.FindAllStringIndex(value, -1)
	if len(matches) == 0 {
		return TrimRunesHeadTail(value, maxRunes)
	}
	userStarts := make([]int, 0, 2)
	for _, match := range matches {
		marker := strings.ToLower(value[match[0]:match[1]])
		if !strings.Contains(marker, "user:") {
			continue
		}
		userStarts = append(userStarts, match[0])
		if len(userStarts) > 2 {
			userStarts = userStarts[len(userStarts)-2:]
		}
	}
	start := matches[max(0, len(matches)-2)][0]
	if len(userStarts) > 0 {
		start = userStarts[0]
	}
	return TrimRunesHeadTail(strings.TrimSpace(value[start:]), maxRunes)
}

func extractLeadingApprovalAction(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "{") || !strings.Contains(value, codexActionJudgeMarker) {
		return "", false
	}
	decoder := json.NewDecoder(strings.NewReader(value))
	var action map[string]any
	if err := decoder.Decode(&action); err != nil {
		return "", false
	}
	if _, hasCommand := action["command"]; !hasCommand {
		return "", false
	}
	offset := decoder.InputOffset()
	if offset <= 0 || offset > int64(len(value)) || !strings.Contains(value[offset:], codexActionJudgeMarker) {
		return "", false
	}
	return strings.TrimSpace(value[:offset]), true
}

func truncateEmbeddedAgentRuntime(value string) string {
	cut := -1
	for _, marker := range embeddedAgentRuntimeMarkers {
		if index := strings.Index(value, marker); index >= 0 && (cut < 0 || index < cut) {
			cut = index
		}
	}
	if cut < 0 {
		return value
	}
	return strings.TrimSpace(value[:cut])
}

func classifyAuditSubject(values []promptSegment) string {
	hasIntent, hasAction, hasContext := false, false, false
	for _, segment := range values {
		if len(cleanRuntimeAuditSegments([]string{segment.text})) == 0 {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(segment.role)) {
		case "user", "":
			hasIntent = true
		case "assistant", "model", "tool":
			hasAction = true
		default:
			hasContext = true
		}
	}
	switch {
	case hasIntent && hasAction:
		return "mixed"
	case hasAction:
		return "action"
	case hasIntent:
		return "intent"
	case hasContext:
		return "context"
	default:
		return "context"
	}
}

// DefaultPromptPreviewMaxRunes caps how much sanitized prompt text may be
// considered before BuildPromptPreview withholds the majority for storage/UI.
const DefaultPromptPreviewMaxRunes = 96

// DefaultFullPromptMaxRunes caps how much unredacted prompt text is persisted
// on an audit event for admin review. It is deliberately generous so realistic
// prompts are kept intact while bounding per-row storage.
const DefaultFullPromptMaxRunes = 65536

func extractProtocolSegments(protocol string, document any) []promptSegment {
	root, _ := document.(map[string]any)
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	switch protocol {
	case "openai_chat_completions", "openai_chat", "chat_completions":
		return extractChatLikeSegments(root)
	case "anthropic_messages", "claude_messages", "messages":
		return append(extractAnthropicSystem(root["system"]), extractMessages(root["messages"], clientInstructionRoles...)...)
	case "gemini", "gemini_generate_content":
		return extractGeminiRoot(root)
	case "openai_responses", "responses", "responses_websocket":
		if frameType := stringValue(root["type"]); frameType != "" || protocol == "responses_websocket" {
			if frameType != "response.create" {
				return nil
			}
			if input, exists := root["input"]; exists && input != nil {
				return append(extractInstructions(root["instructions"]), extractResponses(input)...)
			}
			if response, ok := root["response"].(map[string]any); ok {
				return append(extractInstructions(response["instructions"]), extractResponses(response["input"])...)
			}
			return extractInstructions(root["instructions"])
		}
		return append(extractInstructions(root["instructions"]), extractResponses(root["input"])...)
	case "openai_images", "grok_media", "media", "images":
		return userPromptSegments(extractMediaPrompts(root))
	default:
		if segments := extractChatLikeSegments(root); len(segments) > 0 {
			return segments
		}
		if responses := append(extractInstructions(root["instructions"]), extractResponses(root["input"])...); len(responses) > 0 {
			return responses
		}
		if gemini := extractGeminiRoot(root); len(gemini) > 0 {
			return gemini
		}
		return userPromptSegments(extractMediaPrompts(root))
	}
}

// clientInstructionRoles are roles a client may freely populate. Attackers can
// place jailbreak/PII text in assistant/tool turns, so blocking audit must scan
// them too—not only user/system/developer instructions.
var clientInstructionRoles = []string{"user", "system", "developer", "assistant", "tool"}

func extractChatLikeSegments(root map[string]any) []promptSegment {
	if root == nil {
		return nil
	}
	return extractMessages(root["messages"], clientInstructionRoles...)
}

func extractMessages(value any, wantedRoles ...string) []promptSegment {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	wanted := make(map[string]struct{}, len(wantedRoles))
	for _, role := range wantedRoles {
		wanted[strings.ToLower(strings.TrimSpace(role))] = struct{}{}
	}
	result := make([]promptSegment, 0, len(items))
	for _, item := range items {
		message, ok := item.(map[string]any)
		if !ok {
			continue
		}
		role := strings.ToLower(stringValue(message["role"]))
		if _, match := wanted[role]; !match {
			continue
		}
		texts := contentTexts(message["content"])
		for index, text := range texts {
			result = append(result, promptSegment{text: text, user: role == "user", role: role, continuesTurn: index > 0})
		}
	}
	return result
}

func extractInstructions(value any) []promptSegment {
	switch typed := value.(type) {
	case string:
		if text := strings.TrimSpace(typed); text != "" {
			return []promptSegment{{text: text, role: "system"}}
		}
	case []any:
		return systemPromptSegments(contentTexts(typed))
	case map[string]any:
		return systemPromptSegments(contentTexts(typed))
	}
	return nil
}

func extractAnthropicSystem(value any) []promptSegment {
	switch typed := value.(type) {
	case string:
		if text := strings.TrimSpace(typed); text != "" {
			return []promptSegment{{text: text, role: "system"}}
		}
	case []any:
		return systemPromptSegments(contentTexts(typed))
	case map[string]any:
		return systemPromptSegments(contentTexts(typed))
	}
	return nil
}

func extractResponses(value any) []promptSegment {
	switch typed := value.(type) {
	case string:
		return []promptSegment{{text: typed, user: true, role: "user"}}
	case []any:
		result := make([]promptSegment, 0, len(typed))
		for _, item := range typed {
			switch entry := item.(type) {
			case string:
				result = append(result, promptSegment{text: entry, user: true, role: "user"})
			case map[string]any:
				// Responses tool results are untrusted input too. They use output,
				// not message.content, and must not bypass prompt auditing.
				if stringValue(entry["type"]) == "function_call_output" || stringValue(entry["type"]) == "custom_tool_call_output" {
					for _, text := range contentTexts(entry["output"]) {
						result = append(result, promptSegment{text: text, role: "tool"})
					}
					continue
				}
				role := strings.ToLower(stringValue(entry["role"]))
				if role != "" && !isClientInstructionRole(role) {
					continue
				}
				if content, exists := entry["content"]; exists {
					for index, text := range contentTexts(content) {
						result = append(result, promptSegment{text: text, user: role == "" || role == "user", role: role, continuesTurn: index > 0})
					}
				} else if text := stringValue(entry["text"]); text != "" {
					result = append(result, promptSegment{text: text, user: role == "" || role == "user", role: role})
				}
			}
		}
		return result
	case map[string]any:
		role := strings.ToLower(stringValue(typed["role"]))
		if role != "" && !isClientInstructionRole(role) {
			return nil
		}
		return promptSegmentsForRoleInTurn(contentTexts(typed["content"]), role)
	default:
		return nil
	}
}

func isClientInstructionRole(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "user", "system", "developer", "assistant", "tool", "model":
		return true
	default:
		return false
	}
}

func extractGemini(value any) []promptSegment {
	var contents []any
	switch typed := value.(type) {
	case []any:
		contents = typed
	case map[string]any:
		contents = []any{typed}
	default:
		return nil
	}
	result := make([]promptSegment, 0, len(contents))
	for _, item := range contents {
		content, ok := item.(map[string]any)
		if !ok {
			continue
		}
		role := strings.ToLower(stringValue(content["role"]))
		if role != "" && !isClientInstructionRole(role) {
			continue
		}
		parts, _ := content["parts"].([]any)
		textIndex := 0
		for _, part := range parts {
			if object, ok := part.(map[string]any); ok {
				if text := stringValue(object["text"]); text != "" {
					result = append(result, promptSegment{text: text, user: role == "" || role == "user", role: role, continuesTurn: textIndex > 0})
					textIndex++
				}
			}
		}
	}
	return result
}

func extractGeminiRoot(root map[string]any) []promptSegment {
	if root == nil {
		return nil
	}
	result := extractGeminiSystemInstruction(root["systemInstruction"])
	result = append(result, extractGeminiSystemInstruction(root["system_instruction"])...)
	result = append(result, extractGemini(root["contents"])...)
	result = append(result, extractGemini(root["content"])...)
	result = append(result, extractGeminiInstances(root["instances"])...)
	if requests, ok := root["requests"].([]any); ok {
		for _, item := range requests {
			request, ok := item.(map[string]any)
			if !ok {
				continue
			}
			result = append(result, extractGeminiSystemInstruction(request["systemInstruction"])...)
			result = append(result, extractGeminiSystemInstruction(request["system_instruction"])...)
			result = append(result, extractGemini(request["contents"])...)
			result = append(result, extractGemini(request["content"])...)
			result = append(result, extractGeminiInstances(request["instances"])...)
		}
	}
	return result
}

func extractGeminiSystemInstruction(value any) []promptSegment {
	switch typed := value.(type) {
	case string:
		if text := strings.TrimSpace(typed); text != "" {
			return []promptSegment{{text: text, role: "system"}}
		}
	case map[string]any:
		if parts, ok := typed["parts"].([]any); ok {
			result := make([]promptSegment, 0, len(parts))
			for _, part := range parts {
				if object, ok := part.(map[string]any); ok {
					if text := stringValue(object["text"]); text != "" {
						result = append(result, promptSegment{text: text, role: "system"})
					}
				}
			}
			return result
		}
		return systemPromptSegments(contentTexts(typed))
	case []any:
		segments := extractGemini(typed)
		for index := range segments {
			segments[index].user = false
			segments[index].role = "system"
		}
		return segments
	}
	return nil
}

func extractGeminiInstances(value any) []promptSegment {
	instances, ok := value.([]any)
	if !ok {
		return nil
	}
	result := make([]promptSegment, 0, len(instances))
	for _, item := range instances {
		if instance, ok := item.(map[string]any); ok {
			if prompt := stringValue(instance["prompt"]); prompt != "" {
				result = append(result, promptSegment{text: prompt, user: true, role: "user"})
			}
		}
	}
	return result
}

func extractMediaPrompts(root map[string]any) []string {
	if root == nil {
		return nil
	}
	result := make([]string, 0, 4)
	seen := map[string]struct{}{}
	var walk func(any, string)
	walk = func(value any, key string) {
		switch typed := value.(type) {
		case map[string]any:
			keys := make([]string, 0, len(typed))
			for childKey := range typed {
				keys = append(keys, childKey)
			}
			sort.Strings(keys)
			for _, childKey := range keys {
				walk(typed[childKey], childKey)
			}
		case []any:
			for _, item := range typed {
				walk(item, key)
			}
		case string:
			if !isMediaPromptKey(key) || looksLikeMediaPayload(typed) {
				return
			}
			text := strings.TrimSpace(typed)
			if text == "" {
				return
			}
			if _, duplicate := seen[text]; duplicate {
				return
			}
			seen[text] = struct{}{}
			result = append(result, text)
		}
	}
	walk(root, "")
	return result
}

func isMediaPromptKey(key string) bool {
	normalized := strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(strings.TrimSpace(key)))
	switch normalized {
	case "prompt", "inputprompt", "textprompt", "description", "query", "lyrics", "negativeprompt",
		"positiveprompt", "gptdescriptionprompt", "prompten", "finalprompt", "finalzhprompt",
		"origprompt", "actualprompt", "imageprompt", "input":
		return true
	default:
		return false
	}
}

func looksLikeMediaPayload(value string) bool {
	trimmed := strings.TrimSpace(value)
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "data:image/") || strings.HasPrefix(lower, "data:video/") ||
		strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return true
	}
	if len(trimmed) >= 256 {
		for _, r := range trimmed {
			alphaNumeric := (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
			if !alphaNumeric && r != '+' && r != '/' && r != '=' {
				return false
			}
		}
		return true
	}
	return false
}

func contentTexts(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []any:
		result := make([]string, 0, len(typed))
		for _, part := range typed {
			object, ok := part.(map[string]any)
			if !ok {
				continue
			}
			typeName := strings.ToLower(stringValue(object["type"]))
			if typeName != "" && typeName != "text" && typeName != "input_text" && typeName != "output_text" {
				continue
			}
			if text := stringValue(object["text"]); text != "" {
				result = append(result, text)
			}
		}
		return result
	case map[string]any:
		if text := stringValue(typed["text"]); text != "" {
			return []string{text}
		}
	}
	return nil
}

func normalizedPromptSegmentsLatestUserFirst(values []promptSegment) []promptSegment {
	normalized := normalizedPromptSegments(values)
	if len(normalized) == 0 {
		return nil
	}
	priorityIndex := len(normalized) - 1
	for index := len(normalized) - 1; index >= 0; index-- {
		if isUserSegment(normalized[index]) {
			priorityIndex = index
			break
		}
	}
	result := make([]promptSegment, 0, len(normalized))
	result = append(result, normalized[priorityIndex])
	for index, segment := range normalized {
		if index != priorityIndex {
			result = append(result, segment)
		}
	}
	return result
}

func fastBlockingPromptSegments(values []promptSegment) []promptSegment {
	normalized := normalizedPromptSegments(values)
	latestUserStart := latestUserSegmentStart(normalized)
	if latestUserStart < 0 {
		// A request without user content cannot be narrowed safely. Preserve the
		// established full-snapshot behavior for unusual protocol payloads.
		return normalizedPromptSegmentsLatestUserFirst(values)
	}
	latestUserEnd := latestUserStart + 1
	for latestUserEnd < len(normalized) && isUserSegment(normalized[latestUserEnd]) && normalized[latestUserEnd].continuesTurn {
		latestUserEnd++
	}
	currentUserText := make([]string, 0, latestUserEnd-latestUserStart)
	for _, segment := range normalized[latestUserStart:latestUserEnd] {
		currentUserText = append(currentUserText, segment.text)
	}
	// A single client turn may have several text content parts. Keep it in one
	// priority segment so every part of the latest input is scanned before the
	// prior output begins.
	selected := []promptSegment{{text: strings.Join(currentUserText, "\n\n"), user: true, role: "user"}}
	for index := latestUserStart - 1; index >= 0; index-- {
		if !isAssistantOutputSegment(normalized[index]) {
			continue
		}
		start := index
		for start > 0 && normalized[start].continuesTurn && isAssistantOutputSegment(normalized[start-1]) {
			start--
		}
		selected = append(selected, normalized[start:index+1]...)
		break
	}
	return selected
}

func normalizedPromptSegments(values []promptSegment) []promptSegment {
	normalized := make([]promptSegment, 0, len(values))
	for _, value := range values {
		value.text = strings.TrimSpace(value.text)
		if value.text != "" {
			normalized = append(normalized, value)
		}
	}
	return normalized
}

func latestUserSegmentStart(values []promptSegment) int {
	latest := -1
	for index := len(values) - 1; index >= 0; index-- {
		if isUserSegment(values[index]) {
			latest = index
			break
		}
	}
	for latest > 0 && values[latest].continuesTurn && isUserSegment(values[latest-1]) {
		latest--
	}
	return latest
}

func isUserSegment(segment promptSegment) bool {
	return segment.user || segment.role == "user"
}

func isAssistantOutputSegment(segment promptSegment) bool {
	return segment.role == "assistant" || segment.role == "model"
}

func promptSegmentTexts(values []promptSegment) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		result = append(result, value.text)
	}
	return result
}

func buildPrioritizedScanText(segments []string) (scanText string, metadataText string) {
	metadataText = strings.Join(segments, "\n\n")
	if len(segments) <= 1 {
		return metadataText, metadataText
	}
	return segments[0] + promptAuditPrioritySeparator + strings.Join(segments[1:], "\n\n"), metadataText
}

func promptSegmentsForRole(texts []string, role string) []promptSegment {
	result := make([]promptSegment, 0, len(texts))
	for _, text := range texts {
		result = append(result, promptSegment{text: text, user: role == "" || role == "user", role: role})
	}
	return result
}

func promptSegmentsForRoleInTurn(texts []string, role string) []promptSegment {
	result := promptSegmentsForRole(texts, role)
	for index := range result {
		result[index].continuesTurn = index > 0
	}
	return result
}

func userPromptSegments(texts []string) []promptSegment {
	return promptSegmentsForRole(texts, "user")
}

func systemPromptSegments(texts []string) []promptSegment {
	return promptSegmentsForRole(texts, "system")
}

func RedactPreview(value string, maxRunes int) string {
	value = bearerPattern.ReplaceAllString(value, "Bearer ***")
	value = apiKeyPattern.ReplaceAllStringFunc(value, func(match string) string {
		if index := strings.IndexAny(match, ":= \t"); index >= 0 {
			return match[:index+1] + "***"
		}
		return "***"
	})
	value = canaryPattern.ReplaceAllString(value, "${1}***")
	value = emailPattern.ReplaceAllString(value, "***@***")
	value = phonePattern.ReplaceAllString(value, "***PHONE***")
	return TrimRunes(value, maxRunes)
}

// BuildPromptPreview stores only a short, non-recoverable head of sanitized
// input. Ordinary confidential prompts must not land nearly intact in PostgreSQL
// or the admin UI merely because no secret regex matched.
func BuildPromptPreview(value string, maxRunes int) string {
	if maxRunes <= 0 {
		maxRunes = DefaultPromptPreviewMaxRunes
	}
	redacted := strings.TrimSpace(RedactPreview(value, maxRunes))
	if redacted == "" {
		return ""
	}
	runes := []rune(redacted)
	hadTruncation := strings.HasSuffix(redacted, "…")
	if hadTruncation && len(runes) > 0 {
		runes = runes[:len(runes)-1]
	}
	if len(runes) == 0 {
		return "***…"
	}
	// Short unlabelled secrets would otherwise leak a recoverable prefix (e.g.
	// 20 runes → 5 visible). Fully withhold anything below the keep threshold.
	const minLengthForPartialPreview = 32
	if len(runes) < minLengthForPartialPreview {
		if hadTruncation {
			return "***…"
		}
		return "***"
	}
	// Keep at most a quarter of the already-truncated text, and never more than
	// 24 runes, so the majority of prompt content is withheld by default.
	keep := len(runes) / 4
	if keep > 24 {
		keep = 24
	}
	preview := string(runes[:keep]) + "***"
	if hadTruncation || keep < len(runes) {
		preview += "…"
	}
	return preview
}

// BuildFullPrompt returns bounded prompt evidence for audit-event storage and
// admin review, without redaction. NUL bytes are stripped because PostgreSQL
// TEXT rejects them. When a prompt exceeds the storage bound, both its opening
// context and latest tail are preserved so the current request remains visible.
func BuildFullPrompt(value string, maxRunes int) string {
	if maxRunes <= 0 {
		maxRunes = DefaultFullPromptMaxRunes
	}
	value = strings.ReplaceAll(value, "\x00", "")
	return TrimRunesHeadTail(strings.TrimSpace(value), maxRunes)
}

// FullPromptFromScanText reconstructs the display prompt from the worker scan
// payload. buildPrioritizedScanText inserts exactly one priority separator
// between the prioritized segment and the remainder, so replacing it with the
// metadata joiner yields the original multi-segment text.
func FullPromptFromScanText(scanText string) string {
	return BuildFullPrompt(strings.ReplaceAll(scanText, promptAuditPrioritySeparator, "\n\n"), DefaultFullPromptMaxRunes)
}

func TrimRunes(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit]) + "…"
}

func TrimRunesHeadTail(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	const marker = "\n\n…[middle omitted; beginning and latest tail retained]…\n\n"
	markerRunes := []rune(marker)
	contentLimit := limit - len(markerRunes)
	if contentLimit <= 0 {
		return string(runes[:limit])
	}
	head := contentLimit / 2
	tail := contentLimit - head
	return string(runes[:head]) + marker + string(runes[len(runes)-tail:])
}

func stringValue(value any) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func cloneInt64Ptr(value *int64) *int64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
