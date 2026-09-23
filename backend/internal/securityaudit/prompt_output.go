package securityaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/sseparse"
	"strings"
	"unicode/utf8"
)

// BuildOutputPromptSnapshot reuses the normal prompt canonicalization path but
// marks assistant text as an output/content observation. The original inbound
// protocol remains visible in event metadata.
func BuildOutputPromptSnapshot(req Request, text string) (PromptSnapshot, error) {
	body, err := json.Marshal(map[string]any{
		"messages": []map[string]string{{"role": "assistant", "content": text}},
	})
	if err != nil {
		return PromptSnapshot{}, err
	}
	originalProtocol := req.Protocol
	req.Protocol = "openai_chat_completions"
	req.Stage = "output"
	req.Body = body
	snapshot, err := ExtractPromptSnapshot(req)
	if errors.Is(err, ErrNoPromptText) && req.OutputCapture != nil && !req.OutputCapture.Complete {
		sum := sha256.Sum256([]byte(req.RequestID + "|partial-output"))
		snapshot = PromptSnapshot{RequestID: req.RequestID, UserID: req.UserID, UsernameSnapshot: req.Username, UserEmailSnapshot: req.UserEmail,
			APIKeyID: req.APIKeyID, APIKeyNameSnapshot: req.APIKeyName, GroupID: req.GroupID, GroupName: req.GroupName,
			Provider: req.Provider, Endpoint: req.Endpoint, Model: req.Model, Stage: "output", PromptHash: hex.EncodeToString(sum[:])}
	} else if err != nil {
		return PromptSnapshot{}, err
	}
	snapshot.Protocol = originalProtocol
	snapshot.AuditSubject = "output_content"
	if req.OutputCapture != nil {
		capture := *req.OutputCapture
		snapshot.OutputCapture = &capture
		if utf8.RuneCountInString(text) > DefaultFullPromptMaxRunes {
			capture.Truncated = true
			capture.Complete = false
		}
		if !capture.Complete {
			snapshot.AuditSubject = "output_content_partial"
		}
	}
	return snapshot, nil
}

// ExtractAssistantOutput supports the common OpenAI Responses, Chat
// Completions, Anthropic Messages, and Gemini response shapes. For SSE, each
// data frame is parsed independently so comments and event-name lines are
// ignored.
func ExtractAssistantOutput(raw []byte, streaming bool) string {
	parts := make([]string, 0, 16)
	if streaming {
		var parser sseparse.Parser
		// Deltas must retain repetition; a terminal Responses snapshot supersedes
		// prior deltas instead of concatenating the entire answer a second time.
		var final []string
		parser.Feed(raw, func(event sseparse.Event) {
			var document any
			if json.Unmarshal(event.Data, &document) != nil {
				return
			}
			if event.Terminal() == "completed" {
				if texts := outputTexts(document); len(texts) > 0 {
					final = texts
				}
			} else {
				root, _ := document.(map[string]any)
				kind, _ := root["type"].(string)
				if kind == "response.output_text.done" || kind == "response.content_part.done" || kind == "response.output_item.done" {
					return
				}
				parts = append(parts, outputTexts(document)...)
			}
		})
		if len(final) > 0 {
			parts = final
		}
	} else {
		var document any
		if json.Unmarshal(raw, &document) == nil {
			parts = append(parts, outputTexts(document)...)
		}
	}
	return strings.TrimSpace(strings.Join(parts, ""))
}

func outputTexts(value any) []string {
	root, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, 8)
	if delta, ok := root["delta"].(string); ok && delta != "" {
		result = append(result, delta)
	} else if delta, ok := root["delta"].(map[string]any); ok {
		// Anthropic streaming events wrap text in a delta object.
		result = append(result, messageOutputTexts(delta)...)
	}
	if text, ok := root["text"].(string); ok && text != "" && outputTextType(root) {
		result = append(result, text)
	}
	if choices, ok := root["choices"].([]any); ok {
		for _, item := range choices {
			choice, _ := item.(map[string]any)
			result = append(result, messageOutputTexts(choice["delta"])...)
			result = append(result, messageOutputTexts(choice["message"])...)
			if text, ok := choice["text"].(string); ok {
				result = append(result, text)
			}
		}
	}
	if candidates, ok := root["candidates"].([]any); ok {
		for _, item := range candidates {
			candidate, _ := item.(map[string]any)
			result = append(result, messageOutputTexts(candidate["content"])...)
		}
	}
	for _, key := range []string{"output", "content"} {
		result = append(result, nestedOutputTexts(root[key])...)
	}
	if response, ok := root["response"].(map[string]any); ok {
		result = append(result, nestedOutputTexts(response["output"])...)
	}
	if message, ok := root["message"].(map[string]any); ok {
		result = append(result, messageOutputTexts(message)...)
	}
	return result
}

func outputTextType(value map[string]any) bool {
	typeName, _ := value["type"].(string)
	return typeName == "" || typeName == "output_text" || typeName == "text" || strings.HasSuffix(typeName, ".delta")
}

func messageOutputTexts(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case map[string]any:
		result := make([]string, 0, 2)
		if content, ok := typed["content"].(string); ok {
			result = append(result, content)
		} else {
			result = append(result, nestedOutputTexts(typed["content"])...)
		}
		result = append(result, nestedOutputTexts(typed["parts"])...)
		if delta, ok := typed["text"].(string); ok {
			result = append(result, delta)
		}
		return result
	default:
		return nestedOutputTexts(value)
	}
}

func nestedOutputTexts(value any) []string {
	switch typed := value.(type) {
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			if object, ok := item.(map[string]any); ok {
				if text, ok := object["text"].(string); ok && outputTextType(object) {
					result = append(result, text)
				}
				result = append(result, nestedOutputTexts(object["content"])...)
				result = append(result, nestedOutputTexts(object["parts"])...)
			}
		}
		return result
	case map[string]any:
		return messageOutputTexts(typed)
	case string:
		return []string{typed}
	default:
		return nil
	}
}
