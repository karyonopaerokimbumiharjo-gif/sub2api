package handler

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ip"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

const (
	bioPolicyRecordedKey    = "ops_bio_policy_recorded"
	bioPromptLocallyBlocked = "ops_bio_prompt_locally_blocked"
	BioPromptBlockedMessage = "该提示词近期已触发生物安全策略，请调整输入后重试 / This prompt recently triggered biological-safety policy; please revise the input"
)

func (h *OpenAIGatewayHandler) rejectIfBioPromptBlocked(c *gin.Context, apiKey *service.APIKey, model string, format cyberSessionBlockFormat) bool {
	if h == nil || h.gatewayService == nil || apiKey == nil || c == nil || c.Request == nil {
		return false
	}
	snapshot, ok := securityAuditSnapshot(c)
	if !ok {
		return false
	}
	fingerprint := snapshot.TaskFingerprint
	if strings.TrimSpace(fingerprint) == "" {
		fingerprint = snapshot.PromptHash
	}
	keys := service.BioPromptBlockKeys(snapshot.UserID, apiKey.ID, snapshot.Provider, "bio_policy", fingerprint, snapshot.FullPrompt)
	if !h.gatewayService.IsBioPromptBlocked(c.Request.Context(), keys) {
		return false
	}
	// A repeated local hit extends the rolling suppression window from the
	// initial 30 days to 90 days without sending the prompt upstream again.
	h.gatewayService.MarkBioPromptBlocked(c.Request.Context(), keys)
	c.Set(bioPromptLocallyBlocked, true)
	service.MarkOpsClientBusinessLimited(c, service.OpsClientBusinessLimitedReasonLocalPolicyDenied)
	service.MarkOpsBioPolicy(c, service.BioPolicyMark{Code: "bio_policy", Message: BioPromptBlockedMessage, UpstreamStatus: http.StatusForbidden})
	switch format {
	case cyberBlockFormatAnthropic:
		c.JSON(http.StatusForbidden, gin.H{"type": "error", "error": gin.H{
			"type": "permission_error", "message": BioPromptBlockedMessage,
		}})
	default:
		c.JSON(http.StatusForbidden, gin.H{"error": gin.H{
			"type": "permission_error", "code": "prompt_blocked_by_bio_policy", "message": BioPromptBlockedMessage,
		}})
	}
	h.enqueueBioPromptBlockedOpsEntry(c, apiKey, model, snapshot.PromptHash)
	if h.securityAuditCoordinator != nil {
		coordinator := h.securityAuditCoordinator
		snapshotCopy := snapshot
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = coordinator.RecordLocalPolicyCacheBlock(ctx, snapshotCopy, "bio_policy", BioPromptBlockedMessage)
		}()
	}
	return true
}

func (h *OpenAIGatewayHandler) enqueueBioPromptBlockedOpsEntry(c *gin.Context, apiKey *service.APIKey, model, promptHash string) {
	if h == nil || h.opsService == nil || c == nil || apiKey == nil {
		return
	}
	meta := bioPolicyOpsMeta(c, apiKey, nil, model)
	rt := int16(service.RequestTypeFromLegacy(meta.Stream, false))
	entry := &service.OpsInsertErrorLogInput{
		RequestID: meta.RequestID, ClientRequestID: meta.ClientRequestID,
		Platform: meta.Platform, Model: meta.Model, RequestPath: meta.RequestPath,
		Stream: meta.Stream, InboundEndpoint: meta.InboundEndpoint, RequestType: &rt,
		UserAgent: meta.UserAgent, APIKeyPrefix: meta.APIKeyPrefix,
		ErrorPhase: "request", ErrorType: "bio_policy_prompt_blocked", Severity: "P3",
		StatusCode: http.StatusForbidden, IsBusinessLimited: true,
		ErrorMessage: "bio_policy_prompt_blocked: request rejected locally by prompt fingerprint",
		ErrorBody:    "prompt_hash=" + strings.TrimSpace(promptHash), ErrorSource: "gateway_local", ErrorOwner: "platform",
		CreatedAt: meta.CreatedAt,
	}
	entry.UserID, entry.APIKeyID, entry.GroupID, entry.ClientIP = meta.userIDPtr(), meta.apiKeyIDPtr(), meta.GroupID, meta.clientIPPtr()
	enqueueOpsErrorLog(h.opsService, entry)
}

// recordBioPolicyIfMarked records one semantic 403, feeds the provider verdict
// back into the prompt-audit library, and stores exact+normalized prompt keys
// for pre-upstream rejection on subsequent attempts.
func (h *OpenAIGatewayHandler) recordBioPolicyIfMarked(c *gin.Context, apiKey *service.APIKey, account *service.Account, model string) {
	mark := service.GetOpsBioPolicy(c)
	if mark == nil || c == nil || c.GetBool(bioPromptLocallyBlocked) || c.GetBool(bioPolicyRecordedKey) {
		return
	}
	snapshot, ok := securityAuditSnapshot(c)
	if !ok {
		return
	}
	c.Set(bioPolicyRecordedKey, true)
	meta := bioPolicyOpsMeta(c, apiKey, account, clientRequestedModel(c, model))
	fingerprint := snapshot.TaskFingerprint
	if strings.TrimSpace(fingerprint) == "" {
		fingerprint = snapshot.PromptHash
	}
	keys := service.BioPromptBlockKeys(snapshot.UserID, snapshot.APIKeyID, snapshot.Provider, mark.Code, fingerprint, snapshot.FullPrompt)
	coordinator := h.securityAuditCoordinator
	gateway := h.gatewayService
	ops := h.opsService
	markCopy := *mark
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if gateway != nil {
			gateway.MarkBioPromptBlocked(ctx, keys)
		}
		if coordinator != nil {
			_ = coordinator.RecordUpstreamPolicyFeedback(ctx, snapshot, markCopy.Code, markCopy.Message)
		}
		if ops != nil {
			rt := int16(service.RequestTypeFromLegacy(meta.Stream, false))
			upstreamStatus := markCopy.UpstreamStatus
			upstreamMessage := markCopy.Message
			upstreamDetail := markCopy.Body
			entry := &service.OpsInsertErrorLogInput{
				RequestID: meta.RequestID, ClientRequestID: meta.ClientRequestID,
				Platform: meta.Platform, Model: meta.Model, RequestPath: meta.RequestPath,
				Stream: meta.Stream, InboundEndpoint: meta.InboundEndpoint, RequestType: &rt,
				UserAgent: meta.UserAgent, APIKeyPrefix: meta.APIKeyPrefix,
				ErrorPhase: "request", ErrorType: "bio_policy", Severity: "P3",
				StatusCode: http.StatusForbidden, IsBusinessLimited: true,
				ErrorMessage: "bio_policy: " + markCopy.Message, ErrorBody: markCopy.Body,
				ErrorSource: "upstream_http", ErrorOwner: "provider",
				UpstreamStatusCode: &upstreamStatus, UpstreamErrorMessage: &upstreamMessage, UpstreamErrorDetail: &upstreamDetail,
				CreatedAt: meta.CreatedAt,
			}
			entry.UserID, entry.APIKeyID, entry.AccountID, entry.GroupID, entry.ClientIP = meta.userIDPtr(), meta.apiKeyIDPtr(), meta.accountIDPtr(), meta.GroupID, meta.clientIPPtr()
			enqueueOpsErrorLog(ops, entry)
		}
	}()
}

type bioPolicyRequestMeta struct {
	RequestID, ClientRequestID, Platform, Model, RequestPath, InboundEndpoint string
	UserAgent, APIKeyPrefix, ClientIP                                         string
	UserID, APIKeyID, AccountID                                               int64
	GroupID                                                                   *int64
	Stream                                                                    bool
	CreatedAt                                                                 time.Time
}

func bioPolicyOpsMeta(c *gin.Context, apiKey *service.APIKey, account *service.Account, model string) bioPolicyRequestMeta {
	meta := bioPolicyRequestMeta{Model: model, CreatedAt: time.Now()}
	if c != nil {
		meta.RequestID = c.Writer.Header().Get("X-Request-Id")
		meta.InboundEndpoint = GetInboundEndpoint(c)
		if c.Request != nil {
			if c.Request.URL != nil {
				meta.RequestPath = c.Request.URL.Path
			}
			meta.ClientRequestID, _ = c.Request.Context().Value(ctxkey.ClientRequestID).(string)
			meta.UserAgent = c.GetHeader("User-Agent")
			meta.ClientIP = strings.TrimSpace(ip.GetClientIP(c))
			meta.Platform = resolveOpsPlatform(c.Request.Context(), apiKey, guessPlatformFromPath(meta.RequestPath))
		}
		if value, ok := c.Get(opsStreamKey); ok {
			meta.Stream, _ = value.(bool)
		}
	}
	if apiKey != nil {
		meta.APIKeyID, meta.GroupID, meta.APIKeyPrefix = apiKey.ID, apiKey.GroupID, keyPrefix(apiKey.Key, 8)
		if apiKey.User != nil {
			meta.UserID = apiKey.User.ID
		}
	}
	if account != nil {
		meta.AccountID = account.ID
	}
	return meta
}

func (m bioPolicyRequestMeta) userIDPtr() *int64 {
	if m.UserID > 0 {
		v := m.UserID
		return &v
	}
	return nil
}
func (m bioPolicyRequestMeta) apiKeyIDPtr() *int64 {
	if m.APIKeyID > 0 {
		v := m.APIKeyID
		return &v
	}
	return nil
}
func (m bioPolicyRequestMeta) accountIDPtr() *int64 {
	if m.AccountID > 0 {
		v := m.AccountID
		return &v
	}
	return nil
}
func (m bioPolicyRequestMeta) clientIPPtr() *string {
	if m.ClientIP != "" {
		v := m.ClientIP
		return &v
	}
	return nil
}
