package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

// PI is a transport, not a separate scheduling policy. A quota failure must
// reach the same cooldown and bounded retry/switch loop as direct OAuth calls,
// before any response is written to the caller.
func (s *OpenAIGatewayService) nativePiRateLimitFailover(ctx context.Context, c *gin.Context, account *Account, resp *http.Response, model string) error {
	const message = "Pi upstream rate limit reached; retry later"
	var metadata struct {
		RateLimit struct {
			Type            string `json:"type"`
			ResetsAt        int64  `json:"resets_at"`
			ResetsInSeconds int64  `json:"resets_in_seconds"`
		} `json:"rate_limit"`
	}
	if resp.Body != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&metadata); err != nil {
			metadata.RateLimit.Type = ""
		}
	}
	// Rebuild a narrow provider-compatible error; never use arbitrary runtime
	// text as account policy evidence or expose it in a client error.
	detail := map[string]any{"type": "rate_limit_exceeded", "message": message}
	if metadata.RateLimit.Type == "usage_limit_reached" || metadata.RateLimit.Type == "rate_limit_exceeded" {
		detail["type"] = metadata.RateLimit.Type
		if metadata.RateLimit.ResetsAt > 0 {
			detail["resets_at"] = metadata.RateLimit.ResetsAt
		}
		if metadata.RateLimit.ResetsInSeconds > 0 {
			detail["resets_in_seconds"] = metadata.RateLimit.ResetsInSeconds
		}
	}
	body, _ := json.Marshal(map[string]any{"error": detail})
	appendOpsUpstreamError(c, OpsUpstreamErrorEvent{
		Platform: account.Platform, AccountID: account.ID, AccountName: account.Name,
		UpstreamStatusCode: http.StatusTooManyRequests, UpstreamRequestID: resp.Header.Get("x-request-id"),
		Kind: "failover", Message: message,
	})
	disabled := s.handleFailoverSideEffects(ctx, resp, account, body, model)
	return s.newOpenAIAccountFailoverError(account, http.StatusTooManyRequests, resp.Header, body, message, disabled, false)
}
