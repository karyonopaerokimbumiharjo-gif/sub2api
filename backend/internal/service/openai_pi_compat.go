package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

// The compatibility converters already produce Responses input. Keep their
// protocol-specific response and policy handling, but execute that input using
// Pi rather than opening the standard direct Codex transport.
func (s *OpenAIGatewayService) forwardNativePiCompat(ctx context.Context, c *gin.Context, account *Account, body []byte, promptCacheKey, originalModel, billingModel, upstreamModel string, clientStream, anthropic bool, started time.Time) (*OpenAIForwardResult, error) {
	var request map[string]any
	if err := json.Unmarshal(body, &request); err != nil {
		return nil, err
	}
	if promptCacheKey != "" {
		request["prompt_cache_key"] = promptCacheKey
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	resp, err := s.openNativePiResponse(ctx, c, account, body, upstreamModel)
	if err != nil {
		status, message := http.StatusBadGateway, "Pi runtime unavailable"
		var requestErr *nativePiRequestError
		if errors.As(err, &requestErr) {
			status, message = requestErr.status, requestErr.message
		}
		if anthropic {
			writeAnthropicError(c, status, "api_error", message)
		} else {
			writeChatCompletionsError(c, status, "pi_request_error", message)
		}
		return nil, &ForwardResponseWrittenError{Err: err}
	}
	defer resp.Body.Close()
	SetActualOpenAIUpstreamEndpoint(c, "/backend-api/codex/responses")
	var result *OpenAIForwardResult
	if anthropic {
		if clientStream {
			result, err = s.handleAnthropicStreamingResponse(resp, c, account, originalModel, billingModel, upstreamModel, started)
		} else {
			result, err = s.handleAnthropicBufferedStreamingResponse(resp, c, account, originalModel, billingModel, upstreamModel, started)
		}
	} else if clientStream {
		result, err = s.handleChatStreamingResponse(resp, c, account, originalModel, billingModel, upstreamModel, started, len(body))
	} else {
		result, err = s.handleChatBufferedStreamingResponse(resp, c, account, originalModel, billingModel, upstreamModel, started)
	}
	if GetOpsCyberPolicy(c) != nil {
		if err == nil {
			err = errOpenAICyberPolicyForwarded
		}
		return nil, err
	}
	if GetOpsBioPolicy(c) != nil {
		if err == nil {
			err = errOpenAIBioPolicyForwarded
		}
		return nil, err
	}
	if err == nil && result != nil {
		result.UpstreamEndpoint = "/backend-api/codex/responses"
		result.ServiceTier = resolvedOpenAIUpstreamServiceTier(c, extractOpenAIServiceTierFromBody(body))
		if effort := gjson.GetBytes(body, "reasoning.effort").String(); effort != "" {
			result.ReasoningEffort = &effort
		}
		if snapshot := ParseCodexRateLimitHeaders(resp.Header); snapshot != nil {
			s.updateCodexUsageSnapshot(ctx, account.ID, snapshot)
		}
	}
	return result, err
}
