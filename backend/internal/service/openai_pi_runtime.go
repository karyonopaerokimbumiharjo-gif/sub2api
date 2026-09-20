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
)

func (a *Account) UsesNativePiRuntime() bool {
	return a != nil && a.Platform == PlatformOpenAI && a.Type == AccountTypeOAuth && a.GetCredential("harness_kind") == "pi"
}
func piRequestOwner(c *gin.Context, account *Account) (int64, error) {
	value, ok := c.Get("api_key")
	if !ok {
		return 0, errors.New("Pi account requires an authenticated API key")
	}
	key, ok := value.(*APIKey)
	if !ok || key == nil {
		return 0, errors.New("Pi account requires an authenticated API key")
	}
	owner, err := strconv.ParseInt(account.GetCredential("pi_owner_user_id"), 10, 64)
	if err != nil || owner <= 0 || key.UserID != owner {
		return 0, errors.New("Pi credential does not belong to this user")
	}
	return owner, nil
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
	return strings.TrimSpace(session)
}
func (s *OpenAIGatewayService) forwardNativePi(ctx context.Context, c *gin.Context, account *Account, body []byte) (*OpenAIForwardResult, error) {
	fail := func(status int, message string) (*OpenAIForwardResult, error) {
		c.JSON(status, gin.H{"error": gin.H{"type": "pi_request_error", "message": message}})
		return nil, errors.New(message)
	}
	owner, err := piRequestOwner(c, account)
	if err != nil {
		return fail(http.StatusForbidden, err.Error())
	}
	if account.ProxyID != nil {
		return fail(http.StatusBadRequest, "Pi runtime uses its configured network route; per-account proxy is not supported")
	}
	if isOpenAIResponsesCompactPath(c) {
		return fail(http.StatusBadRequest, "Pi native compact is not supported")
	}
	var request map[string]any
	if json.Unmarshal(body, &request) != nil {
		return fail(http.StatusBadRequest, "Invalid Responses request")
	}
	if metadata, ok := request["client_metadata"]; ok && metadata != nil {
		return fail(http.StatusBadRequest, "Native Pi requests must not include Codex client metadata")
	}
	if _, present := c.Request.Header[http.CanonicalHeaderKey("x-codex-turn-metadata")]; present {
		return fail(http.StatusBadRequest, "Native Pi requests must not include Codex turn metadata")
	}
	if _, ok := request["previous_response_id"]; ok {
		return fail(http.StatusBadRequest, "Pi runtime owns continuation; send full input")
	}
	session := nativePiSession(c, request)
	if session == "" {
		return fail(http.StatusBadRequest, "A stable Pi session is required")
	}
	delete(request, "prompt_cache_key")
	delete(request, "max_output_tokens")
	model, _ := request["model"].(string)
	reqStream, _ := request["stream"].(bool)
	if model == "" {
		return fail(http.StatusBadRequest, "Model is required")
	}
	if s.openAITokenProvider == nil {
		return fail(http.StatusServiceUnavailable, "Pi token provider unavailable")
	}
	token, err := s.openAITokenProvider.GetAccessToken(ctx, account)
	if err != nil {
		return fail(http.StatusUnauthorized, "Pi credential is unavailable; reauthorize this account")
	}
	upstreamModel := account.GetMappedModel(model)
	request["model"] = upstreamModel
	SetOpsUpstreamModel(c, upstreamModel)
	transport := account.GetCredential("pi_transport")
	if transport == "" {
		transport = "sse"
	}
	started := time.Now()
	resp, err := piruntime.Do(ctx, "/responses", map[string]any{"request": request, "access_token": token, "account_id": account.GetCredential("chatgpt_account_id"),
		"owner_id": owner, "credential_id": account.ID, "session_id": session, "transport": transport})
	if err != nil {
		return fail(http.StatusBadGateway, "Pi runtime unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == 400 || resp.StatusCode == 409 {
			return fail(resp.StatusCode, "Invalid or concurrent Pi request")
		}
		return fail(http.StatusBadGateway, "Pi native upstream rejected the request")
	}
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

// Native Pi credentials stay on the Pi SDK refresh path, under Sub2API's existing refresh lock.
func refreshNativePiToken(ctx context.Context, account *Account) (*OpenAITokenInfo, error) {
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
