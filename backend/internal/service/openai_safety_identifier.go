package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/sjson"
	"net/url"
	"strconv"
	"strings"
)

// The installation secret is the tenant boundary. Never trust a client-supplied
// identifier or expose an email, API key, user name or internal numeric ID.
func safetyIdentifier(secret string, userID int64) string {
	if len(secret) < 32 || userID <= 0 {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("sub2api:safety:v1:user:" + strconv.FormatInt(userID, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}
func (s *OpenAIGatewayService) applySafetyIdentifier(c *gin.Context, account *Account, body []byte) []byte {
	// Codex OAuth, CPA and Pi do not promise this public Platform API field.
	// Strip caller-supplied values on every route; inject only on the supported host.
	clean, err := sjson.DeleteBytes(body, "safety_identifier")
	if err != nil {
		return body
	}
	if account == nil || account.Type != AccountTypeAPIKey || !account.IsOpenAI() || s.cfg == nil || c == nil {
		return clean
	}
	endpoint, err := url.Parse(account.GetOpenAIBaseURL())
	if err != nil || endpoint.Scheme != "https" || !strings.EqualFold(endpoint.Hostname(), "api.openai.com") {
		return clean
	}
	value, ok := c.Get("api_key")
	if !ok {
		return clean
	}
	key, ok := value.(*APIKey)
	if !ok || key == nil {
		return clean
	}
	id := safetyIdentifier(s.cfg.JWT.Secret, key.UserID)
	if id == "" {
		return clean
	}
	updated, err := sjson.SetBytes(clean, "safety_identifier", id)
	if err != nil {
		return clean
	}
	return updated
}
