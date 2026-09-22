package securityaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	jevCompactionPolicyID        = "silicon-gpt6j-compaction-v1"
	jevCompactionDropProbability = 0.97
	jevCompactionDropConfidence  = 0.90
	jevCompactionRecentItems     = 8
	jevCompactionMaxCandidates   = 16
	jevCompactionExcerptRunes    = 1800
)

type JevCompactionReport struct {
	Applied      bool `json:"applied"`
	InputItems   int  `json:"input_items"`
	OutputItems  int  `json:"output_items"`
	Candidates   int  `json:"candidates"`
	DroppedItems int  `json:"dropped_items"`
}

type jevCompactionCandidate struct {
	Index int
	Key   string
	Text  string
}

type jevCompactionEnvelope struct {
	Model   string               `json:"model"`
	Answers map[string]jevAnswer `json:"answers"`
}

func (s *PromptService) JevBlockingReady() bool {
	if s == nil || s.config == nil || s.config.BlockingActivationDegraded() || s.EffectiveMode() != ModeBlocking {
		return false
	}
	cfg, ok := s.config.Active()
	if !ok || cfg.EffectiveMode() != ModeBlocking {
		return false
	}
	return jevEndpointsReady(cfg)
}

func jevEndpointsReady(cfg ActiveConfig) bool {
	endpoints := cfg.EnabledEndpointsFor(true)
	if len(endpoints) == 0 {
		return false
	}
	for _, endpoint := range endpoints {
		if endpoint.Protocol != JevProtocol || endpoint.TokenInvalid || strings.TrimSpace(endpoint.Token) == "" {
			return false
		}
	}
	return true
}

func (s *PromptService) EnhanceCompaction(ctx context.Context, body []byte) ([]byte, JevCompactionReport, error) {
	report := JevCompactionReport{}
	if s == nil || s.config == nil || !s.JevBlockingReady() {
		return body, report, &GuardError{Code: ErrorCodeUnavailable}
	}
	// OpenAI's previous_response_id flow already carries server-side state. Do
	// not manually prune it; enhanced compaction is only for explicit windows.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return body, report, err
	}
	if raw := top["previous_response_id"]; len(raw) > 0 && string(bytes.TrimSpace(raw)) != "null" && string(bytes.TrimSpace(raw)) != "\"\"" {
		return body, report, nil
	}
	var input []json.RawMessage
	if err := json.Unmarshal(top["input"], &input); err != nil || len(input) == 0 {
		return body, report, nil
	}
	report.InputItems = len(input)
	report.OutputItems = len(input)

	candidates, recent := collectJevCompactionCandidates(input)
	report.Candidates = len(candidates)
	if len(candidates) == 0 {
		return body, report, nil
	}

	cfg, _ := s.config.Active()
	var lastErr error
	for _, endpoint := range cfg.EnabledEndpointsFor(true) {
		if endpoint.TokenInvalid || strings.TrimSpace(endpoint.Token) == "" {
			continue
		}
		drop, err := planJevCompaction(ctx, endpoint, candidates, recent)
		if err != nil {
			lastErr = err
			continue
		}
		if len(drop) == 0 {
			return body, report, nil
		}
		kept := make([]json.RawMessage, 0, len(input)-len(drop))
		for i, item := range input {
			if drop[i] {
				continue
			}
			kept = append(kept, item)
		}
		encodedInput, err := json.Marshal(kept)
		if err != nil {
			return body, report, err
		}
		top["input"] = encodedInput
		encoded, err := json.Marshal(top)
		if err != nil {
			return body, report, err
		}
		report.Applied = true
		report.DroppedItems = len(drop)
		report.OutputItems = len(kept)
		return encoded, report, nil
	}
	if lastErr == nil {
		lastErr = &GuardError{Code: ErrorCodeUnavailable}
	}
	return body, report, lastErr
}

func collectJevCompactionCandidates(input []json.RawMessage) ([]jevCompactionCandidate, string) {
	protectedFrom := len(input) - jevCompactionRecentItems
	if protectedFrom < 0 {
		protectedFrom = 0
	}
	recentParts := make([]string, 0, jevCompactionRecentItems)
	for i := protectedFrom; i < len(input); i++ {
		if text := compactItemText(input[i]); text != "" {
			recentParts = append(recentParts, fmt.Sprintf("[%d] %s", i, truncateRunes(text, jevCompactionExcerptRunes)))
		}
	}
	recent := strings.Join(recentParts, "\n")

	out := make([]jevCompactionCandidate, 0, jevCompactionMaxCandidates)
	for i := 0; i < protectedFrom && len(out) < jevCompactionMaxCandidates; i++ {
		var item struct {
			Type string `json:"type"`
			Role string `json:"role"`
		}
		if json.Unmarshal(input[i], &item) != nil {
			continue
		}
		typ := strings.TrimSpace(item.Type)
		role := strings.ToLower(strings.TrimSpace(item.Role))
		// Only old assistant messages are candidates. User constraints,
		// developer/system instructions, tools, tool results, compaction items,
		// unknown item types and recent context are never removed here.
		if typ != "message" || role != "assistant" {
			continue
		}
		text, complete := compactCandidateText(input[i])
		if !complete || text == "" {
			continue
		}
		key := fmt.Sprintf("candidate_%d", len(out))
		out = append(out, jevCompactionCandidate{
			Index: i,
			Key:   key,
			Text:  text,
		})
	}
	return out, recent
}

func compactItemText(raw json.RawMessage) string {
	var item map[string]any
	if json.Unmarshal(raw, &item) != nil {
		return ""
	}
	parts := contentTexts(item["content"])
	if len(parts) == 0 {
		if text, ok := item["text"].(string); ok {
			parts = append(parts, text)
		}
	}
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

func truncateRunes(value string, max int) string {
	if max <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= max {
		return value
	}
	return string(runes[:max])
}

func planJevCompaction(
	ctx context.Context,
	endpoint ActiveEndpoint,
	candidates []jevCompactionCandidate,
	recent string,
) (map[int]bool, error) {
	state := map[string]any{
		"policy_version": jevCompactionPolicyID,
		"recent_context": redactJevSecrets(recent),
	}
	questions := make(map[string]jevQuestion, len(candidates))
	for _, candidate := range candidates {
		state[candidate.Key] = redactJevSecrets(candidate.Text)
		questions[candidate.Key] = jevQuestion{
			Type: "choice",
			Instructions: map[string]string{
				"question": fmt.Sprintf("Can `%s` be removed from the older assistant transcript without losing a still-relevant fact, decision, constraint, unresolved task, file/path/identifier, tool consequence, or instruction needed to continue correctly? Compare it with `recent_context`. Prefer keep whenever unsure.", candidate.Key),
				"rule":     "This is loss-avoidance pruning, not summarization. Do not rewrite content. User/developer/system/tool items are already protected by code.",
			},
			Criteria: map[string]string{
				"keep":      "Removing it could lose information or it is not clearly superseded.",
				"uncertain": "There is not enough evidence to prove removal is lossless.",
				"drop":      "It is clearly redundant or superseded by later preserved context and can be removed without changing continuation behavior.",
			},
		}
	}

	payload, err := json.Marshal(struct {
		Model     string                 `json:"model"`
		State     map[string]any         `json:"state"`
		Questions map[string]jevQuestion `json:"questions"`
	}{Model: endpoint.Model, State: state, Questions: questions})
	if err != nil {
		return nil, err
	}
	target, err := jevEvaluationURL(endpoint.BaseURL)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := time.Duration(endpoint.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+endpoint.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := jevHTTPClient.Do(req)
	if err != nil {
		return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: ctx.Err() == nil, Cause: err}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, &GuardError{
			Code:       ErrorCodeUnavailable,
			HTTPStatus: resp.StatusCode,
			Retryable:  resp.StatusCode == 429 || resp.StatusCode == 529 || resp.StatusCode >= 500,
		}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, jevMaxResponseBytes+1))
	if err != nil || len(raw) > jevMaxResponseBytes {
		return nil, &GuardError{Code: ErrorCodeInvalidResponse}
	}
	if err := validateJevJSON(raw); err != nil {
		return nil, &GuardError{Code: ErrorCodeInvalidResponse, Cause: err}
	}
	var wire jevCompactionEnvelope
	if json.Unmarshal(raw, &wire) != nil || wire.Model != endpoint.Model || len(wire.Answers) != len(candidates) {
		return nil, &GuardError{Code: ErrorCodeInvalidResponse}
	}

	drop := make(map[int]bool)
	for _, candidate := range candidates {
		answer, ok := wire.Answers[candidate.Key]
		if !ok || answer.Type != "choice" || answer.Confidence == nil || !jevProbability(*answer.Confidence) {
			return nil, &GuardError{Code: ErrorCodeInvalidResponse}
		}
		if len(answer.Probabilities) != 3 {
			return nil, &GuardError{Code: ErrorCodeInvalidResponse}
		}
		sum := 0.0
		for _, label := range []string{"keep", "uncertain", "drop"} {
			p, exists := answer.Probabilities[label]
			if !exists || p == nil || !jevProbability(*p) {
				return nil, &GuardError{Code: ErrorCodeInvalidResponse}
			}
			sum += *p
		}
		selected, ok := answer.Probabilities[answer.Choice]
		if !ok || selected == nil || mathAbs(sum-1) > 0.00001 {
			return nil, &GuardError{Code: ErrorCodeInvalidResponse}
		}
		// Only a high-confidence explicit drop can remove an item. Everything
		// else, including uncertainty, is kept.
		if answer.Choice == "drop" &&
			*selected >= jevCompactionDropProbability &&
			*answer.Confidence >= jevCompactionDropConfidence {
			drop[candidate.Index] = true
		}
	}
	return drop, nil
}

func mathAbs(value float64) float64 {
	if value < 0 {
		return -value
	}
	return value
}

// A lossy excerpt cannot justify deleting the complete item. Retain long,
// multimodal, annotated and unknown content even if its text looks redundant.
func compactCandidateText(raw json.RawMessage) (string, bool) {
	var item map[string]json.RawMessage
	if json.Unmarshal(raw, &item) != nil {
		return "", false
	}
	for key := range item {
		switch key {
		case "type", "role", "content", "id", "status":
		default:
			return "", false
		}
	}
	var content string
	if json.Unmarshal(item["content"], &content) != nil {
		var parts []map[string]json.RawMessage
		if json.Unmarshal(item["content"], &parts) != nil {
			return "", false
		}
		texts := make([]string, 0, len(parts))
		for _, part := range parts {
			var typ, text string
			if json.Unmarshal(part["type"], &typ) != nil || (typ != "text" && typ != "output_text") || json.Unmarshal(part["text"], &text) != nil {
				return "", false
			}
			for key, value := range part {
				if key == "type" || key == "text" {
					continue
				}
				if key == "annotations" && string(bytes.TrimSpace(value)) == "[]" {
					continue
				}
				return "", false
			}
			texts = append(texts, text)
		}
		content = strings.Join(texts, "\n")
	}
	return content, len([]rune(content)) <= jevCompactionExcerptRunes
}
