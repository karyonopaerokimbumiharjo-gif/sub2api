package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/tidwall/gjson"
)

type openAICyberTranscriptBlockKeys struct {
	lookupKeys          []string
	preLatestUserKey    string
	lookupKeysTruncated bool
	hasModelHistory     bool
}

// Bound the Redis lookup work for a single request while retaining the most
// recent transcript prefixes, where a continuation is most likely to match.
const maxOpenAICyberTranscriptLookupKeys = 256

// deriveOpenAICyberTranscriptBlockKeys returns cumulative semantic-history
// hashes plus the context key immediately before the latest user turn. The
// context key requires model-generated history so shared first-turn templates
// cannot block unrelated conversations.
func deriveOpenAICyberTranscriptBlockKeys(apiKeyID int64, body []byte) openAICyberTranscriptBlockKeys {
	return deriveOpenAICyberTranscriptBlockKeysWithLimit(apiKeyID, body, maxOpenAICyberTranscriptLookupKeys)
}

func deriveOpenAICyberTranscriptBlockKeysWithLimit(apiKeyID int64, body []byte, limit int) openAICyberTranscriptBlockKeys {
	if len(body) == 0 {
		return openAICyberTranscriptBlockKeys{}
	}
	root := openAIRequestPayloadView(body)
	if !root.Exists() || !root.IsObject() {
		return openAICyberTranscriptBlockKeys{}
	}

	h := sha256.New()
	_, _ = h.Write([]byte("cyber-transcript:v3|api_key="))
	_, _ = h.Write([]byte(strconv.FormatInt(apiKeyID, 10)))
	// Model and tool definitions are request configuration rather than history.
	// Root instructions remain model-visible context and participate in identity.
	for _, field := range []string{"instructions"} {
		v := root.Get(field)
		if !v.Exists() || (v.Type == gjson.String && strings.TrimSpace(v.String()) == "") {
			continue
		}
		canonical := normalizeCompatSeedJSON(json.RawMessage(v.Raw))
		if v.Type == gjson.String {
			canonical = v.String()
		}
		_, _ = h.Write([]byte("|"))
		_, _ = h.Write([]byte(field))
		_, _ = h.Write([]byte("="))
		_, _ = h.Write([]byte(canonical))
	}

	appendSequence := func(sequence gjson.Result) openAICyberTranscriptBlockKeys {
		if !sequence.Exists() || !sequence.IsArray() {
			return openAICyberTranscriptBlockKeys{}
		}
		result := openAICyberTranscriptBlockKeys{
			lookupKeys: make([]string, 0, min(limit, 64)),
		}
		nextLookupKey := 0
		lookupKeysRotated := false
		lastLookupKey := ""
		// This is an entropy heuristic, not provenance proof: authenticated
		// server-side history would be required to distinguish fixed few-shot
		// assistant items perfectly.
		hasModelGeneratedItem := false
		sequence.ForEach(func(_, item gjson.Result) bool {
			canonical := item.Raw
			switch item.Type {
			case gjson.String:
				encoded, _ := json.Marshal(item.String())
				canonical = string(encoded)
			case gjson.JSON:
				canonical = normalizeCompatSeedJSON(json.RawMessage(item.Raw))
			}
			if strings.TrimSpace(canonical) == "" {
				return true
			}
			if openAICyberTranscriptItemStartsUserTurn(item) && hasModelGeneratedItem && lastLookupKey != "" {
				result.preLatestUserKey = lastLookupKey
			}
			_, _ = h.Write([]byte("|item="))
			_, _ = h.Write([]byte(canonical))
			lastLookupKey = hex.EncodeToString(h.Sum(nil))
			if len(result.lookupKeys) < limit {
				result.lookupKeys = append(result.lookupKeys, lastLookupKey)
			} else {
				result.lookupKeys[nextLookupKey] = lastLookupKey
				nextLookupKey = (nextLookupKey + 1) % limit
				lookupKeysRotated = true
				result.lookupKeysTruncated = true
			}
			if openAICyberTranscriptItemIsModelGenerated(item) {
				hasModelGeneratedItem = true
			}
			return true
		})
		if lookupKeysRotated {
			ordered := make([]string, 0, len(result.lookupKeys))
			ordered = append(ordered, result.lookupKeys[nextLookupKey:]...)
			ordered = append(ordered, result.lookupKeys[:nextLookupKey]...)
			result.lookupKeys = ordered
		}
		result.hasModelHistory = hasModelGeneratedItem
		return result
	}

	if messages := root.Get("messages"); messages.Exists() {
		return appendSequence(messages)
	}
	if contents := root.Get("contents"); contents.Exists() {
		return appendSequence(contents)
	}
	input := root.Get("input")
	if input.IsArray() {
		return appendSequence(input)
	}
	if input.Type == gjson.String && strings.TrimSpace(input.String()) != "" {
		encoded, _ := json.Marshal(input.String())
		_, _ = h.Write([]byte("|item="))
		_, _ = h.Write(encoded)
		return openAICyberTranscriptBlockKeys{lookupKeys: []string{hex.EncodeToString(h.Sum(nil))}}
	}
	return openAICyberTranscriptBlockKeys{}
}

// AuditConversationKeys reuses the gateway's canonical transcript identity.
// A first-turn template is never used as a conversation-wide block: without
// model history only the explicit session and exact request can be invalidated.
// This keeps a fresh conversation that removed unsafe tool metadata usable.
func AuditConversationKeys(principalID int64, sessionID string, body []byte) (lookup, block []string, overflow bool) {
	if principalID <= 0 || len(body) == 0 {
		return nil, nil, false
	}
	root := openAIRequestPayloadView(body)
	if !root.IsObject() {
		return nil, nil, false
	}
	if sessionID == "" {
		sessionID = strings.TrimSpace(root.Get("prompt_cache_key").String())
	}
	if key := hashCyberSessionBlockKey(principalID, sessionID); key != "" {
		lookup, block = append(lookup, key), append(block, key)
	}
	if previous := strings.TrimSpace(root.Get("previous_response_id").String()); previous != "" {
		key := hashCyberSessionBlockKey(principalID, "previous_response:"+previous)
		lookup, block = append(lookup, key), append(block, key)
	}
	// Hash the wire bytes for exact replay without copying a potentially large
	// image/file payload into another canonical JSON buffer.
	wireDigest := sha256.Sum256(body)
	exact := hashCyberSessionBlockKey(principalID, "audit-request:"+hex.EncodeToString(wireDigest[:]))
	lookup, block = append(lookup, exact), append(block, exact)
	derived := deriveOpenAICyberTranscriptBlockKeysWithLimit(principalID, body, 4096)
	lookup = append(lookup, derived.lookupKeys...)
	if derived.hasModelHistory && len(derived.lookupKeys) > 0 {
		block = append(block, derived.lookupKeys[len(derived.lookupKeys)-1])
		if derived.preLatestUserKey != "" && derived.preLatestUserKey != block[len(block)-1] {
			block = append(block, derived.preLatestUserKey)
		}
	}
	return lookup, block, derived.lookupKeysTruncated
}

func openAICyberTranscriptItemStartsUserTurn(item gjson.Result) bool {
	if strings.EqualFold(strings.TrimSpace(item.Get("role").String()), "user") {
		content := item.Get("content")
		if !content.Exists() {
			content = item.Get("parts")
		}
		if content.IsArray() {
			hasUserContent := false
			content.ForEach(func(_, block gjson.Result) bool {
				switch strings.ToLower(strings.TrimSpace(block.Get("type").String())) {
				case "tool_result", "function_call_output", "custom_tool_call_output", "computer_call_output":
				default:
					hasUserContent = true
				}
				return !hasUserContent
			})
			return hasUserContent
		}
		return content.Exists()
	}
	return strings.EqualFold(strings.TrimSpace(item.Get("type").String()), "input_text")
}

func openAICyberTranscriptItemIsModelGenerated(item gjson.Result) bool {
	switch strings.ToLower(strings.TrimSpace(item.Get("role").String())) {
	case "assistant", "model":
		return true
	}
	switch strings.ToLower(strings.TrimSpace(item.Get("type").String())) {
	case "output_text", "function_call", "tool_call", "custom_tool_call", "computer_call":
		return true
	default:
		return false
	}
}
