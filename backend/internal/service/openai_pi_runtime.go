package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/piruntime"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func (a *Account) UsesNativePiRuntime() bool {
	if a == nil || a.Platform != PlatformOpenAI || a.Type != AccountTypeOAuth {
		return false
	}
	kind := a.GetCredential("harness_kind")
	return kind == PiNativeHarnessKind || kind == PiSharedHarnessKind
}
func piRequestOwner(c *gin.Context, account *Account) (int64, error) {
	value, ok := c.Get("api_key")
	if !ok {
		return 0, errors.New("Pi account requires an authenticated API key")
	}
	key, ok := value.(*APIKey)
	if !ok || key == nil || key.ID <= 0 || key.UserID <= 0 {
		return 0, errors.New("Pi account requires an authenticated API key")
	}
	owner, err := strconv.ParseInt(account.GetCredential("pi_owner_user_id"), 10, 64)
	if err != nil || owner <= 0 {
		return 0, errors.New("Pi credential owner is invalid")
	}
	// The credential owner controls refresh, not exclusive use of the account.
	// A selected shared account is usable only inside the authenticated key's
	// active OpenAI group. Never take this binding from request headers.
	if key.GroupID == nil || key.Group == nil || key.Group.ID != *key.GroupID ||
		!key.Group.IsActive() || key.Group.Platform != PlatformOpenAI ||
		key.User == nil || key.User.ID != key.UserID || !key.User.IsActive() ||
		(!key.Group.IsSubscriptionType() && !key.User.CanBindGroup(*key.GroupID, key.Group.IsExclusive)) {
		return 0, errors.New("Pi request requires an authorized OpenAI group")
	}
	for _, groupID := range account.GroupIDs {
		if groupID == *key.GroupID {
			return owner, nil
		}
	}
	return 0, errors.New("Pi account does not belong to the selected group")
}

// A request correlation ID can change every turn; it cannot establish the
// stable identity used by Pi's connection and continuation cache.
func nativePiSession(c *gin.Context, request map[string]any) string {
	for _, header := range []string{"session-id", "session_id"} {
		if session := strings.TrimSpace(c.GetHeader(header)); session != "" {
			return session
		}
	}
	session, _ := request["prompt_cache_key"].(string)
	if session = strings.TrimSpace(session); session != "" {
		return session
	}
	// The Responses API does not require callers to supply a session. Give a
	// one-shot request a fresh namespace so Pi can execute it without ever
	// attaching it to another caller's continuation cache.
	return "one-shot:" + uuid.NewString()
}

// The caller's session name is only unique within one API key. Include the
// authenticated key ID before the private runtime hashes the session together
// with the owner, credential, OAuth account and model.
func scopedNativePiSession(c *gin.Context, session string) (string, error) {
	value, ok := c.Get("api_key")
	if !ok {
		return "", errors.New("Pi account requires an authenticated API key")
	}
	key, ok := value.(*APIKey)
	if !ok || key == nil || key.ID <= 0 || key.UserID <= 0 {
		return "", errors.New("Pi account requires an authenticated API key")
	}
	return strconv.FormatInt(key.UserID, 10) + ":" + strconv.FormatInt(key.ID, 10) + ":" + session, nil
}

type nativePiRequestError struct {
	status  int
	message string
}

func (e *nativePiRequestError) Error() string { return e.message }

// openNativePiResponse is the shared authenticated transport for Responses,
// Chat Completions and Messages. Protocol adapters keep their existing output
// conversion while using the same credential owner and API-key session scope.
func (s *OpenAIGatewayService) openNativePiResponse(ctx context.Context, c *gin.Context, account *Account, body []byte, upstreamModel string) (*http.Response, error) {
	fail := func(status int, message string) (*http.Response, error) {
		return nil, &nativePiRequestError{status: status, message: message}
	}
	runtimeAccount, resolveErr := ResolveNativePiRuntimeAccount(ctx, s.accountRepo, account)
	if resolveErr != nil {
		return fail(http.StatusServiceUnavailable, "Pi credential binding is unavailable")
	}
	if err := ValidateExecutionAccount(account); err != nil || ValidateExecutionAccount(runtimeAccount) != nil {
		return fail(http.StatusServiceUnavailable, "Pi credential binding is unavailable")
	}
	owner, err := piRequestOwner(c, account)
	if err != nil {
		return fail(http.StatusForbidden, err.Error())
	}
	if account.ProxyID != nil {
		return fail(http.StatusBadRequest, "Pi runtime uses its configured network route; per-account proxy is not supported")
	}
	normalizedBody, _, normalizeErr := normalizeOpenAIResponsesLegacyIngress(body)
	if normalizeErr != nil {
		return fail(http.StatusBadRequest, "Invalid Responses request")
	}
	body = normalizedBody
	if sanitized, _, sanitizeErr := sanitizeOpenAIResponsesToolSchemasForPlatform(body, account.Platform); sanitizeErr != nil {
		return fail(http.StatusBadRequest, "Invalid Responses tool schema")
	} else {
		body = sanitized
	}
	var request map[string]any
	if json.Unmarshal(body, &request) != nil {
		return fail(http.StatusBadRequest, "Invalid Responses request")
	}
	// CPA and Pi share the same public Responses ingress. Codex clients may
	// include client-only metadata and a continuation id from a different
	// backend session. Those values are not part of Pi's upstream contract:
	// discard them and let Pi derive its own isolated session/continuation
	// state instead of rejecting an otherwise valid request at the gateway.
	delete(request, "client_metadata")
	delete(request, "previous_response_id")
	// Match the existing Codex ingress treatment of fields unsupported by
	// ChatGPT Responses, including output limits and sampling parameters.
	for _, field := range openAICodexOAuthUnsupportedFields {
		delete(request, field)
	}
	session := nativePiSession(c, request)
	session, err = scopedNativePiSession(c, session)
	if err != nil {
		return fail(http.StatusForbidden, err.Error())
	}
	delete(request, "prompt_cache_key")
	model, _ := request["model"].(string)
	if model == "" {
		return fail(http.StatusBadRequest, "Model is required")
	}
	if s.openAITokenProvider == nil {
		return fail(http.StatusServiceUnavailable, "Pi token provider unavailable")
	}
	token, err := s.openAITokenProvider.GetAccessToken(ctx, runtimeAccount)
	if err != nil {
		return fail(http.StatusUnauthorized, "Pi credential is unavailable; reauthorize this account")
	}
	if upstreamModel == "" {
		upstreamModel = account.GetMappedModel(model)
	}
	request["model"] = upstreamModel
	SetOpsUpstreamModel(c, upstreamModel)
	transport := runtimeAccount.GetCredential("pi_transport")
	if transport == "" {
		transport = "sse"
	}
	headerTimeoutMS, idleTimeoutMS := s.nativePiRuntimeTimeouts()
	resp, err := piruntime.Do(ctx, "/responses", map[string]any{"request": request, "access_token": token, "account_id": runtimeAccount.GetCredential("chatgpt_account_id"),
		"owner_id": owner, "credential_id": runtimeAccount.ID, "session_id": session, "transport": transport,
		"response_header_timeout_ms": headerTimeoutMS, "stream_idle_timeout_ms": idleTimeoutMS})
	if err != nil {
		var runtimeErr *piruntime.Error
		if errors.As(err, &runtimeErr) {
			switch runtimeErr.Code {
			case "pi_upstream_busy":
				return fail(http.StatusServiceUnavailable, "Pi upstream is temporarily busy; retry later")
			case "pi_upstream_rate_limited":
				return fail(http.StatusTooManyRequests, "Pi upstream rate limit reached; retry later")
			case "pi_upstream_authorization_rejected":
				return fail(http.StatusBadGateway, "Pi upstream rejected this account's authorization")
			case "pi_upstream_failed":
				return fail(http.StatusBadGateway, "Pi native upstream rejected the request")
			case "pi_upstream_timeout":
				return fail(http.StatusGatewayTimeout, "Pi upstream timed out while waiting for response data; retry the request")
			}
		}
		return fail(http.StatusBadGateway, "Pi runtime unavailable")
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		if resp.StatusCode == 400 || resp.StatusCode == 409 {
			return fail(resp.StatusCode, "Invalid or concurrent Pi request")
		}
		switch resp.StatusCode {
		case http.StatusTooManyRequests:
			return fail(http.StatusTooManyRequests, "Pi upstream rate limit reached; retry later")
		case http.StatusServiceUnavailable:
			return fail(http.StatusServiceUnavailable, "Pi upstream is temporarily busy; retry later")
		case http.StatusGatewayTimeout:
			return fail(http.StatusGatewayTimeout, "Pi upstream timed out while waiting for response data; retry the request")
		case http.StatusUnauthorized, http.StatusForbidden:
			return fail(http.StatusBadGateway, "Pi upstream rejected this account's authorization")
		}
		return fail(http.StatusBadGateway, "Pi native upstream rejected the request")
	}
	return resp, nil
}

// The selected executor must not impose a shorter total generation limit.
// Forward the same OpenAI header and stream-idle policy used by the gateway.
func (s *OpenAIGatewayService) nativePiRuntimeTimeouts() (headerMS, idleMS int64) {
	if s == nil || s.cfg == nil {
		return 0, 180000
	}
	return int64(s.cfg.Gateway.OpenAIResponseHeaderTimeout) * 1000, int64(s.cfg.Gateway.StreamDataIntervalTimeout) * 1000
}

func (s *OpenAIGatewayService) forwardNativePi(ctx context.Context, c *gin.Context, account *Account, body []byte) (*OpenAIForwardResult, error) {
	fail := func(status int, message string) (*OpenAIForwardResult, error) {
		c.JSON(status, gin.H{"error": gin.H{"type": "pi_request_error", "message": message}})
		return nil, &ForwardResponseWrittenError{Err: errors.New(message)}
	}
	if isOpenAIResponsesCompactPath(c) {
		if ValidateExecutionAccount(account) != nil {
			return fail(http.StatusServiceUnavailable, "Pi credential binding is unavailable")
		}
		return s.forwardNativePiCompact(ctx, c, account, body)
	}
	var request struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	if json.Unmarshal(body, &request) != nil {
		return fail(http.StatusBadRequest, "Invalid Responses request")
	}
	model, reqStream := request.Model, request.Stream
	upstreamModel := account.GetMappedModel(model)
	started := time.Now()
	resp, err := s.openNativePiResponse(ctx, c, account, body, upstreamModel)
	if err != nil {
		var requestErr *nativePiRequestError
		if errors.As(err, &requestErr) {
			return fail(requestErr.status, requestErr.message)
		}
		return fail(http.StatusBadGateway, "Pi runtime unavailable")
	}
	defer resp.Body.Close()
	SetActualOpenAIUpstreamEndpoint(c, "/backend-api/codex/responses")
	result := &OpenAIForwardResult{Model: model, UpstreamModel: upstreamModel, Stream: reqStream, UpstreamHeaders: resp.Header, UpstreamEndpoint: "/backend-api/codex/responses"}
	if reqStream {
		streamResult, e := s.handleStreamingResponse(ctx, resp, c, account, started, model, upstreamModel)
		if e != nil {
			return nil, e
		}
		if streamResult.usage != nil {
			result.Usage = *streamResult.usage
		}
		result.FirstTokenMs = streamResult.firstTokenMs
		result.ResponseID = streamResult.responseID
	} else {
		nonstream, e := s.handleNonStreamingResponse(ctx, resp, c, account, model, upstreamModel)
		if e != nil {
			return nil, e
		}
		if nonstream.usage != nil {
			result.Usage = *nonstream.usage
		}
		result.ResponseID = nonstream.responseID
	}
	result.UpstreamResponseModel = observedUpstreamResponseModel(c)
	result.UpstreamResponseModelConflict = observedUpstreamResponseModelConflict(c)
	result.UpstreamResponseServiceTier = observedUpstreamResponseServiceTier(c)
	result.BillingModel = model
	result.RequestID = resp.Header.Get("x-request-id")
	result.Duration = time.Since(started)
	return result, nil
}

// forwardNativePiCompact uses the account's Codex OAuth credential directly
// for the stateless /responses/compact contract.  Pi's agent loop does not
// own this endpoint; routing it through the private runtime keeps refresh,
// account binding and credential redaction identical to normal Pi Responses.
func (s *OpenAIGatewayService) forwardNativePiCompact(ctx context.Context, c *gin.Context, account *Account, body []byte) (*OpenAIForwardResult, error) {
	fail := func(status int, message string) (*OpenAIForwardResult, error) {
		c.JSON(status, gin.H{"error": gin.H{"type": "pi_request_error", "message": message}})
		return nil, &ForwardResponseWrittenError{Err: errors.New(message)}
	}
	owner, err := piRequestOwner(c, account)
	if err != nil {
		return fail(http.StatusForbidden, err.Error())
	}
	runtimeAccount, err := ResolveNativePiRuntimeAccount(ctx, s.accountRepo, account)
	if err != nil || ValidateExecutionAccount(runtimeAccount) != nil {
		return fail(http.StatusServiceUnavailable, "Pi credential binding is unavailable")
	}
	var request map[string]any
	if json.Unmarshal(body, &request) != nil {
		return fail(http.StatusBadRequest, "Invalid compact request")
	}
	model, _ := request["model"].(string)
	if strings.TrimSpace(model) == "" {
		return fail(http.StatusBadRequest, "Model is required")
	}
	if mapped := account.GetCompactModelMapping(); len(mapped) > 0 {
		if compactModel, ok := account.ResolveCompactMappedModel(model); ok {
			model = compactModel
			request["model"] = compactModel
		}
	}
	if s.openAITokenProvider == nil {
		return fail(http.StatusServiceUnavailable, "Pi token provider unavailable")
	}
	token, err := s.openAITokenProvider.GetAccessToken(ctx, runtimeAccount)
	if err != nil {
		return fail(http.StatusUnauthorized, "Pi credential is unavailable; reauthorize this account")
	}
	started := time.Now()
	resp, err := piruntime.Do(ctx, "/compact", map[string]any{
		"request": request, "access_token": token,
		"account_id": runtimeAccount.GetCredential("chatgpt_account_id"),
		"owner_id":   owner, "credential_id": runtimeAccount.ID,
	})
	if err != nil {
		return fail(http.StatusBadGateway, "Pi runtime unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusTooManyRequests {
			return fail(http.StatusTooManyRequests, "Pi upstream rate limit reached; retry later")
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return fail(http.StatusBadGateway, "Pi upstream rejected this account's authorization")
		}
		return fail(http.StatusBadGateway, "Pi compact upstream rejected the request")
	}
	result := &OpenAIForwardResult{Model: model, UpstreamModel: model, Stream: false, UpstreamHeaders: resp.Header, UpstreamEndpoint: "/backend-api/codex/responses/compact", BillingModel: model, RequestID: resp.Header.Get("x-request-id"), Duration: time.Since(started)}
	nonstream, err := s.handleNonStreamingResponse(ctx, resp, c, account, model, model)
	if err != nil {
		return nil, err
	}
	if nonstream.usage != nil {
		result.Usage = *nonstream.usage
	}
	result.ResponseID = nonstream.responseID
	result.UpstreamResponseModel = observedUpstreamResponseModel(c)
	result.UpstreamResponseModelConflict = observedUpstreamResponseModelConflict(c)
	result.UpstreamResponseServiceTier = observedUpstreamResponseServiceTier(c)
	return result, nil
}

// Native Pi credentials stay on the Pi SDK refresh path, under Sub2API's existing refresh lock.
func refreshNativePiToken(ctx context.Context, account *Account) (*OpenAITokenInfo, error) {
	if account.GetCredential("harness_kind") == PiSharedHarnessKind {
		return nil, errors.New("shared Pi aliases must refresh through their runtime owner")
	}
	owner, err := strconv.ParseInt(account.GetCredential("pi_owner_user_id"), 10, 64)
	if err != nil || owner <= 0 || account.ProxyID != nil || account.GetOpenAIRefreshToken() == "" {
		return nil, errors.New("invalid Pi credential binding")
	}
	var info OpenAITokenInfo
	if err := piruntime.JSON(ctx, "/oauth/refresh", map[string]any{"owner_id": owner, "account_id": account.GetCredential("chatgpt_account_id"), "refresh_token": account.GetOpenAIRefreshToken()}, &info); err != nil {
		return nil, err
	}
	if info.HarnessKind != "pi" || info.PiOwnerUserID != strconv.FormatInt(owner, 10) || info.ChatGPTAccountID != account.GetCredential("chatgpt_account_id") || info.AccessToken == "" || info.ExpiresAt <= time.Now().Unix() {
		return nil, errors.New("Pi refresh returned an invalid binding")
	}
	return &info, nil
}
