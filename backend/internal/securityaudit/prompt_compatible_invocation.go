package securityaudit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

type promptInvocationRecorder interface {
	RecordInvocation(context.Context, PromptAuditInvocation) error
}

type auditCostCalculator interface {
	CalculateCost(string, service.UsageTokens, float64) (*service.CostBreakdown, error)
}

type compatibleAuditUsage struct {
	Model           string
	InputTokens     int // Includes cache reads, as in the upstream Chat Completions usage.
	OutputTokens    int
	CacheReadTokens int
}

func parseCompatibleAuditUsage(body []byte) *compatibleAuditUsage {
	var response struct {
		Model string `json:"model"`
		Usage *struct {
			PromptTokens        *int `json:"prompt_tokens"`
			CompletionTokens    *int `json:"completion_tokens"`
			PromptTokensDetails struct {
				CachedTokens *int `json:"cached_tokens"`
			} `json:"prompt_tokens_details"`
			PromptCacheHitTokens *int `json:"prompt_cache_hit_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(body, &response) != nil || response.Usage == nil ||
		response.Usage.PromptTokens == nil || response.Usage.CompletionTokens == nil {
		return nil // Never fabricate a zero-cost usage record when tokens are absent.
	}
	u := response.Usage
	value := &compatibleAuditUsage{
		Model: strings.TrimSpace(response.Model), InputTokens: *u.PromptTokens, OutputTokens: *u.CompletionTokens,
	}
	if u.PromptTokensDetails.CachedTokens != nil {
		value.CacheReadTokens = *u.PromptTokensDetails.CachedTokens
	} else if u.PromptCacheHitTokens != nil {
		value.CacheReadTokens = *u.PromptCacheHitTokens
	}
	if value.InputTokens < 0 || value.OutputTokens < 0 || value.CacheReadTokens < 0 || value.CacheReadTokens > value.InputTokens {
		return nil
	}
	return value
}

func (s *RoutingPromptScanner) recordCompatibleInvocation(ctx context.Context, endpoint ActiveEndpoint, usage *compatibleAuditUsage, scanErr error, latency time.Duration) {
	if s == nil || s.invocations == nil {
		return
	}
	meta, ok := promptInvocationContextFrom(ctx)
	if !ok {
		return // Connection probes do not belong to request audit usage totals.
	}
	value := PromptAuditInvocation{
		RequestID: meta.RequestID, ConfigVersion: meta.ConfigVersion,
		GuardEndpointID: endpoint.ID, GuardEndpointName: endpoint.Name,
		Protocol: EndpointProtocolOpenAICompatible, Model: endpoint.Model,
		Status: "success", LatencyMS: latency.Milliseconds(),
	}
	// A CPA node is a transport, not a known underlying OAuth account. Do not
	// assign its usage to an arbitrary email or charge the requesting user again.
	if scanErr != nil {
		value.Status, value.ErrorCode = "failed", ErrorCodeUnavailable
		var guardErr *GuardError
		if errors.As(scanErr, &guardErr) {
			value.ErrorCode = guardErr.Code
			if guardErr.Code == ErrorCodeInvalidResponse {
				value.Status = "invalid"
			}
		}
	}
	if usage != nil {
		value.InputTokens, value.OutputTokens, value.CacheReadTokens = usage.InputTokens, usage.OutputTokens, usage.CacheReadTokens
		if usage.Model != "" {
			value.Model = usage.Model
		}
		if s.billing != nil {
			tokens := service.UsageTokens{
				InputTokens:  usage.InputTokens - usage.CacheReadTokens,
				OutputTokens: usage.OutputTokens, CacheReadTokens: usage.CacheReadTokens,
			}
			cost, err := s.billing.CalculateCost(endpoint.Model, tokens, 1)
			if err != nil && value.Model != endpoint.Model {
				cost, err = s.billing.CalculateCost(value.Model, tokens, 1)
			}
			if err == nil && cost != nil {
				value.EstimatedCostUSD, value.PricingKnown = cost.TotalCost, true
			}
		}
	}
	// Bound bookkeeping independently of the classifier's deadline, including
	// canceled scans. This adds no model call and cannot turn an error into Allow.
	recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 250*time.Millisecond)
	defer cancel()
	if err := s.invocations.RecordInvocation(recordCtx, value); err != nil {
		LogWarn(EventProcessFailed, map[string]any{
			"guard_endpoint_id": endpoint.ID, "status": "usage_record_failed", "error_code": "audit_usage_record_failed",
		})
	}
}
