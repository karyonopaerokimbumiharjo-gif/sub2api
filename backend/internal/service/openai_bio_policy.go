package service

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

const opsBioPolicyKey = "ops_bio_policy"

var errOpenAIBioPolicyForwarded = errors.New("openai bio_policy forwarded to client")

// BioPolicyMark records an upstream OpenAI biological-safety rejection. It is
// deliberately separate from CyberPolicyMark because bio feedback is used to
// block repeated prompt fingerprints, not an entire conversation session.
type BioPolicyMark struct {
	Code           string
	Message        string
	Body           string
	UpstreamStatus int
	UpstreamInTok  int
	UpstreamOutTok int
}

func MarkOpsBioPolicy(c *gin.Context, mark BioPolicyMark) {
	if c == nil || GetOpsBioPolicy(c) != nil {
		return
	}
	mark.Code = "bio_policy"
	mark.Message = strings.TrimSpace(mark.Message)
	mark.Body = sanitizeOpenAIPolicyFailureBody([]byte(mark.Body))
	c.Set(opsBioPolicyKey, &mark)
}

// sanitizeOpenAIPolicyFailureBody keeps only diagnostic response metadata and
// the provider error. OpenAI response.failed payloads may echo the complete
// instructions field; persisting that field leaks internal agent prompts and
// makes the admin error body misleading.
func sanitizeOpenAIPolicyFailureBody(payload []byte) string {
	trimmed := strings.TrimSpace(string(payload))
	if trimmed == "" {
		return ""
	}
	var root map[string]any
	if err := json.Unmarshal(payload, &root); err != nil {
		// Never retain an unparseable policy payload because it may contain a
		// truncated instructions field. The structured message is stored
		// separately in UpstreamErrorMessage.
		return ""
	}
	safe := map[string]any{}
	if value, ok := root["type"]; ok {
		safe["type"] = value
	}
	if value, ok := root["error"]; ok {
		safe["error"] = value
	}
	if response, ok := root["response"].(map[string]any); ok {
		clean := map[string]any{}
		for _, key := range []string{"id", "object", "status", "model", "error", "incomplete_details"} {
			if value, exists := response[key]; exists {
				clean[key] = value
			}
		}
		safe["response"] = clean
	}
	encoded, err := json.Marshal(safe)
	if err != nil {
		return ""
	}
	return truncateString(string(encoded), 4096)
}

func GetOpsBioPolicy(c *gin.Context) *BioPolicyMark {
	if c == nil {
		return nil
	}
	value, ok := c.Get(opsBioPolicyKey)
	if !ok {
		return nil
	}
	mark, _ := value.(*BioPolicyMark)
	return mark
}

func ClearOpsBioPolicy(c *gin.Context) {
	if c != nil {
		c.Set(opsBioPolicyKey, (*BioPolicyMark)(nil))
	}
}

func detectOpenAIBioPolicy(payload []byte) (bool, string, string) {
	code := gjson.GetBytes(payload, "error.code").String()
	if code == "" {
		code = gjson.GetBytes(payload, "response.error.code").String()
	}
	if !strings.EqualFold(strings.TrimSpace(code), "bio_policy") {
		return false, "", ""
	}
	message := gjson.GetBytes(payload, "error.message").String()
	if message == "" {
		message = gjson.GetBytes(payload, "response.error.message").String()
	}
	return true, "bio_policy", strings.TrimSpace(message)
}

func markOpenAIBioPolicy(c *gin.Context, payload []byte, upstreamStatus, inputTokens, outputTokens int) (bool, string) {
	hit, code, message := detectOpenAIBioPolicy(payload)
	if !hit {
		return false, ""
	}
	MarkOpsBioPolicy(c, BioPolicyMark{
		Code: code, Message: message, Body: sanitizeOpenAIPolicyFailureBody(payload),
		UpstreamStatus: upstreamStatus, UpstreamInTok: inputTokens, UpstreamOutTok: outputTokens,
	})
	return true, message
}

const OpenAIBioPolicyClientMessage = "该请求触发了生物安全策略，请调整输入后重试 / This request was blocked by biological-safety policy; please revise the input"
