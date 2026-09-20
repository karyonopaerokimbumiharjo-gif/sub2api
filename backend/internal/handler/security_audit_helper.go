package handler

import (
	"context"
	"crypto/sha256"
	"net/http"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ip"
	"github.com/Wei-Shaw/sub2api/internal/securityaudit"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const (
	securityAuditCompletedContextKey = "sub2api.security_audit.completed"
	securityAuditSnapshotContextKey  = "sub2api.security_audit.snapshot"
	securityAuditWSTurnContextKey    = "sub2api.security_audit.ws_turn"
	securityAuditWSDedupeContextKey  = "sub2api.security_audit.ws_dedupe"
)

type securityAuditWSDedupeEntry struct {
	stage    string
	turn     int
	bodyHash [sha256.Size]byte
	decision securityaudit.Decision
}

// cachesSecurityAuditCompletion reports whether a successful audit may be
// reused for the rest of the gin request. WebSocket turns share one Context
// across many response.create frames and must be audited independently.
func cachesSecurityAuditCompletion(stage string) bool {
	switch strings.TrimSpace(stage) {
	case "", "http":
		return true
	default:
		return false
	}
}

func isSecurityAuditWebSocketStage(stage string) bool {
	switch strings.TrimSpace(stage) {
	case "first_turn", "subsequent_turn":
		return true
	default:
		return false
	}
}

func (h *GatewayHandler) checkSecurityAudit(c *gin.Context, reqLog *zap.Logger, apiKey *service.APIKey, subject middleware2.AuthSubject, protocol, model string, body []byte) *securityaudit.Decision {
	if h == nil {
		return nil
	}
	return runSecurityAudit(c, reqLog, h.securityAuditCoordinator, h.contentModerationService, nil, apiKey, subject, protocol, model, body, "http")
}

func (h *OpenAIGatewayHandler) checkSecurityAudit(c *gin.Context, reqLog *zap.Logger, apiKey *service.APIKey, subject middleware2.AuthSubject, protocol, model string, body []byte) *securityaudit.Decision {
	if h == nil {
		return nil
	}
	return runSecurityAudit(c, reqLog, h.securityAuditCoordinator, h.contentModerationService, h.gatewayService, apiKey, subject, protocol, model, body, "http")
}

func (h *OpenAIGatewayHandler) checkSecurityAuditStage(c *gin.Context, reqLog *zap.Logger, apiKey *service.APIKey, subject middleware2.AuthSubject, protocol, model string, body []byte, stage string) *securityaudit.Decision {
	if h == nil {
		return nil
	}
	return runSecurityAudit(c, reqLog, h.securityAuditCoordinator, h.contentModerationService, h.gatewayService, apiKey, subject, protocol, model, body, stage)
}

func runSecurityAudit(c *gin.Context, reqLog *zap.Logger, coordinator *securityaudit.Coordinator, legacy *service.ContentModerationService, gatewayService *service.OpenAIGatewayService, apiKey *service.APIKey, subject middleware2.AuthSubject, protocol, model string, body []byte, stage string) *securityaudit.Decision {
	if c == nil || c.Request == nil {
		return nil
	}
	// Recheck every WS turn before any per-request allow cache. Revocations
	// survive changes to the optional upstream cyber-cooldown setting.
	if gatewayService != nil && apiKey != nil {
		key := gatewayService.FindSecurityAuditSessionInvalidatedForRequest(c.Request.Context(), apiKey.ID, c, body, strings.TrimSpace(ip.GetClientIP(c)), c.GetHeader("User-Agent"))
		if key == service.SecurityAuditSessionStoreUnavailable {
			return &securityaudit.Decision{Kind: securityaudit.DecisionUnavailable, HTTPStatus: http.StatusServiceUnavailable, ErrorCode: securityaudit.ErrorCodeUnavailable, ClientMessage: "Conversation safety state is temporarily unavailable. Please retry."}
		}
		if key != "" {
			c.Set(securityAuditContextInvalidatedContextKey, true)
			return &securityaudit.Decision{Kind: securityaudit.DecisionBlock, HTTPStatus: http.StatusForbidden, ErrorCode: securityaudit.ErrorCodeBlocked, ClientMessage: "This conversation has been invalidated by the safety policy. Start a new conversation."}
		}
	}
	cacheCompletion := cachesSecurityAuditCompletion(stage)
	if cacheCompletion {
		if completed, exists := c.Get(securityAuditCompletedContextKey); exists && completed == true {
			return nil
		}
	}
	if coordinator == nil {
		legacyDecision := runContentModeration(c, reqLog, legacy, apiKey, subject, protocol, model, body)
		if legacyDecision == nil {
			return nil
		}
		decision := securityaudit.Decision{Kind: securityaudit.DecisionAllow, HTTPStatus: http.StatusOK, AllowNextStage: true}
		decision.Legacy = &securityaudit.LegacyDecision{
			Allowed: legacyDecision.Allowed, Blocked: legacyDecision.Blocked, Flagged: legacyDecision.Flagged,
			Message: legacyDecision.Message, StatusCode: legacyDecision.StatusCode,
			ErrorCode: "content_policy_violation", Action: legacyDecision.Action,
		}
		if legacyDecision.Blocked {
			decision.Kind, decision.HTTPStatus, decision.ErrorCode, decision.ClientMessage, decision.AllowNextStage = securityaudit.DecisionBlock, contentModerationStatus(legacyDecision), "content_policy_violation", legacyDecision.Message, false
		}
		if decision.Kind == securityaudit.DecisionBlock {
			invalidateSecurityAuditContext(c, reqLog, gatewayService, apiKey, body)
		}
		if decision.AllowNextStage && cacheCompletion {
			c.Set(securityAuditCompletedContextKey, true)
		}
		return &decision
	}
	request := buildSecurityAuditRequest(c, apiKey, subject, protocol, model, body, stage)
	if isSecurityAuditWebSocketStage(request.Stage) {
		if turnNo, ok := securityAuditWSTurn(c); ok {
			bodyHash := sha256.Sum256(body)
			if cached, exists := c.Get(securityAuditWSDedupeContextKey); exists {
				if entry, ok := cached.(securityAuditWSDedupeEntry); ok &&
					entry.stage == request.Stage && entry.turn == turnNo && entry.bodyHash == bodyHash {
					decision := entry.decision
					logSecurityAuditDone(reqLog, request, decision, true)
					return &decision
				}
			}
			logSecurityAuditStart(reqLog, request, len(body), false)
			auditStarted := time.Now()
			decision := coordinator.Check(c.Request.Context(), request)
			applySecurityAuditSideEffects(c, coordinator, request, decision, auditStarted)
			switch decision.Kind {
			case securityaudit.DecisionAllow:
				c.Set(securityAuditWSDedupeContextKey, securityAuditWSDedupeEntry{
					stage: request.Stage, turn: turnNo, bodyHash: bodyHash, decision: decision,
				})
			case securityaudit.DecisionBlock:
				invalidateSecurityAuditContext(c, reqLog, gatewayService, apiKey, body)
			}
			logSecurityAuditDone(reqLog, request, decision, false)
			return &decision
		}
	}
	logSecurityAuditStart(reqLog, request, len(body), false)
	auditStarted := time.Now()
	decision := coordinator.Check(c.Request.Context(), request)
	if decision.Kind == securityaudit.DecisionBlock {
		invalidateSecurityAuditContext(c, reqLog, gatewayService, apiKey, body)
	}
	applySecurityAuditSideEffects(c, coordinator, request, decision, auditStarted)
	if decision.AllowNextStage && cacheCompletion {
		c.Set(securityAuditCompletedContextKey, true)
	}
	logSecurityAuditDone(reqLog, request, decision, false)
	return &decision
}

const securityAuditContextInvalidatedContextKey = "sub2api.security_audit.context_invalidated"

func invalidateSecurityAuditContext(c *gin.Context, reqLog *zap.Logger, gatewayService *service.OpenAIGatewayService, apiKey *service.APIKey, body []byte) {
	if c == nil || c.Request == nil || gatewayService == nil || apiKey == nil {
		return
	}
	plan := buildCyberSessionBlockWritePlan(apiKey.ID, c, body)
	if previousKey := service.CyberSessionPreviousResponseBlockKey(apiKey.ID, body); previousKey != "" {
		seen := false
		for _, key := range plan.keys {
			if key == previousKey {
				seen = true
				break
			}
		}
		if !seen {
			plan.keys = append([]string{previousKey}, plan.keys...)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()
	if err := gatewayService.InvalidateSecurityAuditSession(ctx, apiKey.GroupID, c, body, plan.scopeKey, plan.keys); err != nil {
		if reqLog != nil {
			reqLog.Warn("security_audit.context_invalidation_degraded", zap.Error(err))
		}
		return
	}
	c.Set(securityAuditContextInvalidatedContextKey, true)
}

func applySecurityAuditSideEffects(c *gin.Context, coordinator *securityaudit.Coordinator, request securityaudit.Request, decision securityaudit.Decision, auditStarted time.Time) {
	if decision.Prompt != nil && decision.Prompt.Result != nil {
		c.Request = c.Request.WithContext(service.WithPromptAuditLatency(c.Request.Context(), int(time.Since(auditStarted).Milliseconds())))
	}
	if decision.Prompt != nil && decision.Prompt.Snapshot != nil {
		snapshot := *decision.Prompt.Snapshot
		c.Set(securityAuditSnapshotContextKey, snapshot)
	}
	if decision.AllowNextStage {
		installSecurityAuditOutputCapture(c, coordinator, request, decision.Kind)
	}
}

func securityAuditSnapshot(c *gin.Context) (securityaudit.PromptSnapshot, bool) {
	if c == nil {
		return securityaudit.PromptSnapshot{}, false
	}
	value, ok := c.Get(securityAuditSnapshotContextKey)
	if !ok {
		return securityaudit.PromptSnapshot{}, false
	}
	snapshot, ok := value.(securityaudit.PromptSnapshot)
	return snapshot, ok && strings.TrimSpace(snapshot.PromptHash) != ""
}

func logSecurityAuditStart(reqLog *zap.Logger, request securityaudit.Request, bodyBytes int, cached bool) {
	if reqLog == nil {
		return
	}
	reqLog.Info("security_audit.gateway_check_start",
		zap.String("request_id", request.RequestID), zap.Int64("user_id", request.UserID),
		zap.Int64("api_key_id", request.APIKeyID), zap.Int64p("group_id", request.GroupID),
		zap.String("endpoint", request.Endpoint), zap.String("provider", request.Provider),
		zap.String("protocol", request.Protocol), zap.String("model", request.Model), zap.String("stage", request.Stage),
		zap.Int("body_bytes", bodyBytes), zap.Bool("cached", cached))
}

func logSecurityAuditDone(reqLog *zap.Logger, request securityaudit.Request, decision securityaudit.Decision, cached bool) {
	if reqLog == nil {
		return
	}
	reqLog.Info("security_audit.gateway_check_done",
		zap.String("request_id", request.RequestID), zap.String("decision", string(decision.Kind)),
		zap.String("error_code", decision.ErrorCode), zap.Bool("allow_next_stage", decision.AllowNextStage),
		zap.String("stage", request.Stage), zap.Bool("cached", cached))
}

func securityAuditWSTurn(c *gin.Context) (int, bool) {
	turn, exists := c.Get(securityAuditWSTurnContextKey)
	if !exists {
		return 0, false
	}
	turnNo, ok := turn.(int)
	return turnNo, ok
}

func buildSecurityAuditRequest(c *gin.Context, apiKey *service.APIKey, subject middleware2.AuthSubject, protocol, model string, body []byte, stage string) securityaudit.Request {
	legacy := buildContentModerationInput(c, apiKey, subject, protocol, model, body)
	request := securityaudit.Request{
		RequireJev: c.GetBool(gpt6JContextKey),
		RequestID:  legacy.RequestID, UserID: legacy.UserID, UserEmail: legacy.UserEmail,
		APIKeyID: legacy.APIKeyID, APIKeyName: legacy.APIKeyName, GroupID: cloneSecurityAuditGroupID(legacy.GroupID),
		GroupName: legacy.GroupName, Provider: legacy.Provider, Endpoint: legacy.Endpoint,
		Protocol: legacy.Protocol, Model: legacy.Model, Body: body, Stage: strings.TrimSpace(stage),
	}
	if apiKey != nil && apiKey.User != nil {
		request.Username = apiKey.User.Username
		request.PromptAuditBypass = apiKey.User.PromptAuditBypass
		if request.UserEmail == "" {
			request.UserEmail = apiKey.User.Email
		}
	}
	if request.Stage == "" {
		request.Stage = "http"
	}
	return request
}

func securityAuditStatus(decision *securityaudit.Decision) int {
	if decision == nil || decision.HTTPStatus < 400 || decision.HTTPStatus > 599 {
		return http.StatusForbidden
	}
	return decision.HTTPStatus
}

func securityAuditErrorCode(decision *securityaudit.Decision) string {
	if decision == nil || strings.TrimSpace(decision.ErrorCode) == "" {
		return "content_policy_violation"
	}
	return decision.ErrorCode
}

func securityAuditMessage(decision *securityaudit.Decision) string {
	if decision == nil {
		return "Request blocked by content policy"
	}
	if decision.Legacy != nil && decision.Legacy.Blocked && strings.TrimSpace(decision.Legacy.Message) != "" {
		return decision.Legacy.Message
	}
	if strings.TrimSpace(decision.ClientMessage) != "" {
		return decision.ClientMessage
	}
	return "Request blocked by content policy"
}

func cloneSecurityAuditGroupID(value *int64) *int64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
