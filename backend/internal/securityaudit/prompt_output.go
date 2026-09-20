package securityaudit

import (
	"encoding/json"
	"strings"
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
	if err != nil {
		return PromptSnapshot{}, err
	}
	snapshot.Protocol = originalProtocol
	snapshot.AuditSubject = "output_content"
	return snapshot, nil
}

// ExtractAssistantOutput supports the common OpenAI Responses, Chat
// Completions, Anthropic Messages, and Gemini response shapes. For SSE, each
// data frame is parsed independently so comments and event-name lines are
// ignored.
func ExtractAssistantOutput(raw []byte, streaming bool) string {
	parts := make([]string, 0, 16)
	if streaming {
		for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if payload == "" || payload == "[DONE]" {
				continue
			}
			var document any
			if json.Unmarshal([]byte(payload), &document) == nil {
				parts = append(parts, outputTexts(document)...)
			}
		}
	} else {
		var document any
		if json.Unmarshal(raw, &document) == nil {
			parts = append(parts, outputTexts(document)...)
		}
	}
	return TrimRunes(strings.TrimSpace(strings.Join(compactOutputParts(parts), "")), DefaultFullPromptMaxRunes)
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

func compactOutputParts(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		// Terminal Responses events can repeat the full text after delta frames.
		// Avoid the common exact duplicate without attempting lossy fuzzy merging.
		if len(result) > 0 && result[len(result)-1] == value {
			continue
		}
		result = append(result, value)
	}
	return result
}
