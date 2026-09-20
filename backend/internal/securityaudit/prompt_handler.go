package securityaudit

import (
	"context"
	"errors"
	"strconv"
	"strings"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/gin-gonic/gin"
)

type PromptAdminService interface {
	GetConfig() (PublicConfig, error)
	SaveConfig(context.Context, UpdateConfigRequest, int64) (PublicConfig, error)
	ListPolicyVersions(context.Context, int) ([]PromptPolicyVersion, error)
	RollbackPolicy(context.Context, int64, int64, int64) (PublicConfig, error)
	Probe(context.Context, ProbeRequest) ProbeResult
	Runtime(context.Context) RuntimeSnapshot
	ListEvents(context.Context, EventFilter, int, int) (*EventPage, error)
	GetEvent(context.Context, int64) (*Event, error)
	ListAdaptiveSamples(context.Context, string, int, int) (*AdaptiveSamplePage, error)
	ReviewAdaptiveSample(context.Context, int64, int64, AdaptiveReviewRequest) (*AdaptiveSample, error)
	DeleteEvent(context.Context, int64) (*DeleteResult, error)
	DeleteEventsByIDs(context.Context, []int64) (*DeleteResult, error)
	PreviewDelete(context.Context, EventFilter, int64) (*DeletePreview, error)
	DeleteByFilter(context.Context, DeleteByFilterRequest, int64) (*DeleteResult, error)
}

type PromptAdminHandler struct{ service PromptAdminService }

func NewPromptAdminHandler(service PromptAdminService) *PromptAdminHandler {
	return &PromptAdminHandler{service: service}
}

func (h *PromptAdminHandler) GetConfig(c *gin.Context) {
	config, err := h.service.GetConfig()
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, config)
}

func (h *PromptAdminHandler) UpdateConfig(c *gin.Context) {
	var request UpdateConfigRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		setPromptAdminAudit(c, "failed", "prompt_audit_invalid_config_request", nil)
		response.ErrorFrom(c, infraerrors.BadRequest("prompt_audit_invalid_config_request", "提示词审计配置请求无效"))
		return
	}
	config, err := h.service.SaveConfig(c.Request.Context(), request, adminID(c))
	if err != nil {
		setPromptAdminAudit(c, "failed", infraerrors.Reason(err), configAuditFields(request, nil))
		response.ErrorFrom(c, err)
		return
	}
	setPromptAdminAudit(c, "success", "", configAuditFields(request, &config))
	response.Success(c, config)
}

func (h *PromptAdminHandler) ListPolicyVersions(c *gin.Context) {
	limit, err := positiveIntQuery(c, "limit", 20, 100)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	versions, err := h.service.ListPolicyVersions(c.Request.Context(), limit)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, versions)
}

func (h *PromptAdminHandler) RollbackPolicy(c *gin.Context) {
	targetVersion, err := strconv.ParseInt(c.Param("config_version"), 10, 64)
	if err != nil || targetVersion <= 0 {
		response.ErrorFrom(c, infraerrors.BadRequest("prompt_audit_invalid_policy_version", "策略版本无效"))
		return
	}
	var request RollbackPolicyRequest
	if err := c.ShouldBindJSON(&request); err != nil || request.ExpectedConfigVersion < 1 {
		response.ErrorFrom(c, infraerrors.BadRequest("prompt_audit_invalid_policy_rollback", "策略回退请求无效"))
		return
	}
	config, err := h.service.RollbackPolicy(c.Request.Context(), targetVersion, request.ExpectedConfigVersion, adminID(c))
	if err != nil {
		setPromptAdminAudit(c, "failed", infraerrors.Reason(err), map[string]any{"target_config_version": targetVersion})
		response.ErrorFrom(c, err)
		return
	}
	setPromptAdminAudit(c, "success", "", map[string]any{
		"target_config_version": targetVersion,
		"config_version":        config.ConfigVersion,
	})
	response.Success(c, config)
}

func (h *PromptAdminHandler) ProbeEndpoint(c *gin.Context) {
	var request ProbeRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		setPromptAdminAudit(c, "failed", "prompt_audit_invalid_probe_request", nil)
		response.ErrorFrom(c, infraerrors.BadRequest("prompt_audit_invalid_probe_request", "审计节点探测请求无效"))
		return
	}
	result := h.service.Probe(c.Request.Context(), request)
	status := "failed"
	if result.OK {
		status = "success"
	}
	setPromptAdminAudit(c, status, result.ErrorCode, map[string]any{
		"guard_endpoint_id": request.Endpoint.ID, "http_status": result.HTTPStatus,
		"latency_ms": result.LatencyMS, "token_applied": result.TokenApplied, "retryable": result.Retryable,
	})
	response.Success(c, result)
}

func (h *PromptAdminHandler) GetRuntime(c *gin.Context) {
	response.Success(c, h.service.Runtime(c.Request.Context()))
}

func (h *PromptAdminHandler) ListEvents(c *gin.Context) {
	page, err := positiveIntQuery(c, "page", 1, 0)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	pageSize, err := positiveIntQuery(c, "page_size", 20, 100)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	filter, err := eventFilterFromQuery(c)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	result, err := h.service.ListEvents(c.Request.Context(), filter, page, pageSize)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}

func (h *PromptAdminHandler) GetEvent(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		response.ErrorFrom(c, infraerrors.BadRequest("prompt_audit_invalid_event_id", "事件 ID 无效"))
		return
	}
	event, err := h.service.GetEvent(c.Request.Context(), id)
	if errors.Is(err, ErrEventNotFound) {
		response.ErrorFrom(c, infraerrors.NotFound("prompt_audit_event_not_found", "提示词审计事件不存在"))
		return
	}
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, event)
}

func (h *PromptAdminHandler) ListAdaptiveSamples(c *gin.Context) {
	page, err := positiveIntQuery(c, "page", 1, 0)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	pageSize, err := positiveIntQuery(c, "page_size", 20, 100)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	result, err := h.service.ListAdaptiveSamples(c.Request.Context(), c.Query("status"), page, pageSize)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}

func (h *PromptAdminHandler) ReviewAdaptiveSample(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		response.ErrorFrom(c, infraerrors.BadRequest("prompt_audit_invalid_adaptive_sample_id", "自适应样本 ID 无效"))
		return
	}
	var request AdaptiveReviewRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.ErrorFrom(c, infraerrors.BadRequest("prompt_audit_invalid_adaptive_review", "自适应样本复核请求无效"))
		return
	}
	sample, err := h.service.ReviewAdaptiveSample(c.Request.Context(), id, adminID(c), request)
	if errors.Is(err, ErrAdaptiveSampleNotFound) {
		response.ErrorFrom(c, infraerrors.NotFound("prompt_audit_adaptive_sample_not_found", "自适应样本不存在"))
		return
	}
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	setPromptAdminAudit(c, "success", "", map[string]any{
		"adaptive_sample_id": id, "review_decision": sample.ReviewStatus,
	})
	response.Success(c, sample)
}

func (h *PromptAdminHandler) DeleteEvent(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		setPromptAdminAudit(c, "failed", "prompt_audit_invalid_event_id", nil)
		response.ErrorFrom(c, infraerrors.BadRequest("prompt_audit_invalid_event_id", "事件 ID 无效"))
		return
	}
	result, err := h.service.DeleteEvent(c.Request.Context(), id)
	if err != nil {
		setPromptAdminAudit(c, "failed", infraerrors.Reason(err), map[string]any{"event_id": id})
		response.ErrorFrom(c, err)
		return
	}
	setPromptAdminAudit(c, "success", "", deleteAuditFields(result, map[string]any{"event_id": id}))
	LogWarn(EventEventDeleted, map[string]any{"user_id": adminID(c), "event_id": id, "status": "deleted"})
	response.Success(c, result)
}

type batchDeleteRequest struct {
	IDs []int64 `json:"ids" binding:"required"`
}

func (h *PromptAdminHandler) BatchDelete(c *gin.Context) {
	var request batchDeleteRequest
	if err := c.ShouldBindJSON(&request); err != nil || len(request.IDs) == 0 || len(request.IDs) > 500 {
		setPromptAdminAudit(c, "failed", "prompt_audit_invalid_delete_batch", nil)
		response.ErrorFrom(c, infraerrors.BadRequest("prompt_audit_invalid_delete_batch", "批量删除必须包含 1-500 个事件 ID"))
		return
	}
	for _, id := range request.IDs {
		if id <= 0 {
			setPromptAdminAudit(c, "failed", "prompt_audit_invalid_event_id", map[string]any{"requested_count": len(request.IDs)})
			response.ErrorFrom(c, infraerrors.BadRequest("prompt_audit_invalid_event_id", "事件 ID 无效"))
			return
		}
	}
	result, err := h.service.DeleteEventsByIDs(c.Request.Context(), request.IDs)
	if err != nil {
		setPromptAdminAudit(c, "failed", infraerrors.Reason(err), map[string]any{"requested_count": len(request.IDs)})
		response.ErrorFrom(c, err)
		return
	}
	setPromptAdminAudit(c, "success", "", deleteAuditFields(result, map[string]any{"requested_count": len(request.IDs)}))
	LogWarn(EventEventsDeleted, map[string]any{"user_id": adminID(c), "status": "deleted"})
	response.Success(c, result)
}

func (h *PromptAdminHandler) DeletePreview(c *gin.Context) {
	var filter EventFilter
	if err := c.ShouldBindJSON(&filter); err != nil {
		setPromptAdminAudit(c, "failed", "prompt_audit_delete_preview_invalid", nil)
		response.ErrorFrom(c, infraerrors.BadRequest("prompt_audit_delete_preview_invalid", "删除预览筛选无效"))
		return
	}
	preview, err := h.service.PreviewDelete(c.Request.Context(), filter, adminID(c))
	if err != nil {
		setPromptAdminAudit(c, "failed", "prompt_audit_delete_preview_invalid", nil)
		response.ErrorFrom(c, infraerrors.BadRequest("prompt_audit_delete_preview_invalid", "删除预览筛选无效"))
		return
	}
	setPromptAdminAudit(c, "success", "", map[string]any{
		"matched_count": preview.MatchedCount, "snapshot_max_id": preview.SnapshotMaxID, "filter_hash": preview.FilterHash,
	})
	response.Success(c, preview)
}

func (h *PromptAdminHandler) DeleteByFilter(c *gin.Context) {
	var request DeleteByFilterRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		setPromptAdminAudit(c, "failed", "prompt_audit_delete_confirmation_invalid", nil)
		response.ErrorFrom(c, infraerrors.BadRequest("prompt_audit_delete_confirmation_invalid", "删除确认无效或已过期"))
		return
	}
	result, err := h.service.DeleteByFilter(c.Request.Context(), request, adminID(c))
	if err != nil {
		setPromptAdminAudit(c, "failed", "prompt_audit_delete_confirmation_invalid", map[string]any{
			"snapshot_max_id": request.SnapshotMaxID, "filter_hash": request.FilterHash, "confirm": request.Confirm,
		})
		response.ErrorFrom(c, infraerrors.BadRequest("prompt_audit_delete_confirmation_invalid", "删除确认无效或已过期"))
		return
	}
	setPromptAdminAudit(c, "success", "", deleteAuditFields(result, map[string]any{
		"snapshot_max_id": request.SnapshotMaxID, "filter_hash": request.FilterHash, "confirm": request.Confirm,
	}))
	response.Success(c, result)
}

func setPromptAdminAudit(c *gin.Context, result, errorCode string, fields map[string]any) {
	details := make(map[string]any, len(fields)+2)
	details["result"] = result
	if strings.TrimSpace(errorCode) != "" {
		details["error_code"] = errorCode
	}
	for key, value := range fields {
		details[key] = value
	}
	middleware.SetAuditExtra(c, details)
}

func configAuditFields(request UpdateConfigRequest, saved *PublicConfig) map[string]any {
	version := request.ExpectedConfigVersion
	if saved != nil {
		version = saved.ConfigVersion
	}
	return map[string]any{
		"enabled": request.Enabled, "blocking_enabled": request.BlockingEnabled,
		"blocking_audit_mode":       request.BlockingAuditMode,
		"background_audit_mode":     request.BackgroundAuditMode,
		"blocking_latest_turn_only": request.BlockingLatestTurnOnly,
		"config_version":            version, "endpoint_count": len(request.Endpoints),
		"scanner_count": len(request.Scanners), "all_groups": request.AllGroups,
		"group_count": len(request.GroupIDs),
		"whitelist_count": func() int {
			if request.WhitelistEmails == nil {
				return 0
			}
			return len(*request.WhitelistEmails)
		}(),
	}
}

func deleteAuditFields(result *DeleteResult, base map[string]any) map[string]any {
	fields := make(map[string]any, len(base)+2)
	for key, value := range base {
		fields[key] = value
	}
	if result != nil {
		fields["deleted_events"] = result.DeletedEvents
		fields["deleted_jobs"] = result.DeletedJobs
	}
	return fields
}

func adminID(c *gin.Context) int64 {
	subject, ok := middleware.GetAuthSubjectFromContext(c)
	if !ok {
		return 0
	}
	return subject.UserID
}

func eventFilterFromQuery(c *gin.Context) (EventFilter, error) {
	groupID, err := optionalPositiveInt64Query(c, "group_id")
	if err != nil {
		return EventFilter{}, err
	}
	userID, err := optionalPositiveInt64Query(c, "user_id")
	if err != nil {
		return EventFilter{}, err
	}
	apiKeyID, err := optionalPositiveInt64Query(c, "api_key_id")
	if err != nil {
		return EventFilter{}, err
	}
	filter := EventFilter{
		Decision: c.Query("decision"), RiskLevel: c.Query("risk_level"), Endpoint: c.Query("endpoint"),
		GroupID: groupID, UserID: userID, APIKeyID: apiKeyID, RequestID: c.Query("request_id"),
		PromptHash: c.Query("prompt_hash"), Keyword: c.Query("keyword"),
	}
	if value := strings.TrimSpace(c.Query("aggregate")); value != "" {
		aggregate, parseErr := strconv.ParseBool(value)
		if parseErr != nil {
			return EventFilter{}, infraerrors.BadRequest("prompt_audit_invalid_aggregate", "聚合参数无效")
		}
		filter.Aggregate = aggregate
	}
	if value := strings.TrimSpace(c.Query("start_at")); value != "" {
		filter.StartAt = parseTimeQuery(value)
		if filter.StartAt == nil {
			return EventFilter{}, infraerrors.BadRequest("prompt_audit_invalid_time", "开始时间无效")
		}
	}
	if value := strings.TrimSpace(c.Query("end_at")); value != "" {
		filter.EndAt = parseTimeQuery(value)
		if filter.EndAt == nil {
			return EventFilter{}, infraerrors.BadRequest("prompt_audit_invalid_time", "结束时间无效")
		}
	}
	return filter, nil
}

func optionalPositiveInt64Query(c *gin.Context, key string) (*int64, error) {
	value := strings.TrimSpace(c.Query(key))
	if value == "" {
		return nil, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return nil, infraerrors.BadRequest("prompt_audit_invalid_filter_id", "事件筛选 ID 无效")
	}
	return &parsed, nil
}

func positiveIntQuery(c *gin.Context, key string, defaultValue, maxValue int) (int, error) {
	value := strings.TrimSpace(c.Query(key))
	if value == "" {
		return defaultValue, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 || (maxValue > 0 && parsed > maxValue) {
		return 0, infraerrors.BadRequest("prompt_audit_invalid_pagination", "分页参数无效")
	}
	return parsed, nil
}
