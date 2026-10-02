package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

// Keep rejected upstream credentials inside the existing account retry loop.
// Committing a 502 here pins sticky requests to the failed account indefinitely.
func (s *OpenAIGatewayService) nativePiAuthorizationFailover(ctx context.Context, c *gin.Context, account *Account, resp *http.Response, model string) error {
	const message = "Pi upstream rejected the account authorization; reauthorize the account"
	var raw []byte
	if resp.Body != nil {
		raw, _ = io.ReadAll(io.LimitReader(resp.Body, 4096))
	}
	var runtimeFailure struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(raw, &runtimeFailure)
	if runtimeFailure.Error == "unauthorized" {
		// The runtime rejects its private service bearer before contacting a
		// provider. This is not evidence against any upstream account.
		return &nativePiRequestError{status: http.StatusServiceUnavailable, message: "Pi runtime authentication is unavailable"}
	}
	// The runtime masks the reason for a 403. It may be a request or content
	// rejection, so neither retry another credential nor penalize an account.
	if resp.StatusCode == http.StatusForbidden {
		return &nativePiRequestError{status: http.StatusForbidden, message: "Pi upstream rejected the request or its permissions"}
	}
	detail := map[string]any{"type": "authentication_error", "message": message}
	// Only explicit provider codes can establish permanent revocation. Do not
	// classify free-form text, which may contain echoed input or credentials.
	if code := extractUpstreamErrorCode(raw); resp.StatusCode == http.StatusUnauthorized && (code == "token_invalidated" || code == "token_revoked") {
		detail["code"] = code
	}
	body, _ := json.Marshal(map[string]any{"error": detail})
	appendOpsUpstreamError(c, OpsUpstreamErrorEvent{
		Platform: account.Platform, AccountID: account.ID, AccountName: account.Name,
		UpstreamStatusCode: resp.StatusCode, UpstreamRequestID: resp.Header.Get("x-request-id"),
		Kind: "failover", Message: message,
	})
	// Shared business aliases intentionally have no refresh token. Apply the
	// auth cooldown to their credential owner, as token lookup and refresh do.
	disabled := false
	// Only credential authorization failures enter account cooldown handling.
	if resp.StatusCode == http.StatusUnauthorized {
		if owner, err := ResolveNativePiRuntimeAccount(ctx, s.accountRepo, account); err == nil {
			disabled = s.handleFailoverSideEffects(ctx, resp, owner, body, model)
		}
	}
	return s.newOpenAIAccountFailoverError(account, resp.StatusCode, resp.Header, body, message, disabled, false)
}

// PI is a transport, not a separate scheduling policy. A quota failure must
// reach the same cooldown and bounded retry/switch loop as direct OAuth calls,
// before any response is written to the caller.
func (s *OpenAIGatewayService) nativePiRateLimitFailover(ctx context.Context, c *gin.Context, account *Account, resp *http.Response, model string) error {
	const message = "Pi upstream rate limit reached; retry later"
	var metadata struct {
		RateLimit struct {
			Scope           string `json:"scope"`
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
		if metadata.RateLimit.Scope == "image" {
			detail["param"] = "gpt-image"
		}
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

// A credential can become unavailable after account selection. Keep this race
// within the request's bounded failover loop without writing a response first.
func nativePiCredentialOwnerUnavailable() *UpstreamFailoverError {
	const message = "Pi credential owner is unavailable for dispatch"
	body, _ := json.Marshal(map[string]any{"error": map[string]any{"type": "upstream_error", "message": message}})
	return newOpenAIUpstreamFailoverError(http.StatusServiceUnavailable, http.Header{}, body, message, false)
}
