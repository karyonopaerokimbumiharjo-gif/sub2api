package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/jruntime"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/gin-gonic/gin"
)

func (h *APIKeyHandler) JSettings(c *gin.Context) {
	subject, ok := middleware2.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "User not authenticated")
		return
	}
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		response.BadRequest(c, "Invalid key ID")
		return
	}
	if h.jStore == nil {
		response.Error(c, 503, "J execution is unavailable")
		return
	}
	if c.Request.Method == http.MethodPut {
		var input struct {
			Enabled *bool `json:"enabled"`
		}
		if c.ShouldBindJSON(&input) != nil || input.Enabled == nil {
			response.BadRequest(c, "enabled is required")
			return
		}
		if err := h.jStore.SetEnabled(c.Request.Context(), subject.UserID, id, *input.Enabled); err != nil {
			response.Error(c, 404, "API key not found")
			return
		}
	}
	enabled, err := h.jStore.Enabled(c.Request.Context(), subject.UserID, id)
	if err != nil {
		response.Error(c, 404, "API key not found")
		return
	}
	response.Success(c, gin.H{"enabled": enabled})
}

// Bridge endpoints authenticate the ordinary API key and an additional grant
// secret. They never accept an account/user binding from a caller's payload.
func (h *OpenAIGatewayHandler) JBridge(c *gin.Context) {
	key, ok := middleware2.GetAPIKeyFromContext(c)
	if !ok || key == nil || h.jStore == nil {
		response.Error(c, 503, "J bridge unavailable")
		return
	}
	var input struct {
		Session string          `json:"session_id"`
		Tools   []jruntime.Tool `json:"tools"`
		TTL     int             `json:"ttl_seconds"`
		Grant   string          `json:"grant_id"`
		Secret  string          `json:"secret"`
		Task    string          `json:"task_id"`
		Call    string          `json:"call_id"`
		Lease   string          `json:"lease"`
		Output  json.RawMessage `json:"output"`
	}
	if c.ShouldBindJSON(&input) != nil {
		response.BadRequest(c, "Invalid bridge request")
		return
	}
	ctx := c.Request.Context()
	switch c.Param("action") {
	case "register":
		if input.TTL == 0 {
			input.TTL = 900
		}
		grant, err := h.jStore.Grant(ctx, key.UserID, key.ID, input.Session, input.Tools, time.Duration(input.TTL)*time.Second)
		if err != nil {
			response.Error(c, 403, "J must be enabled and the local tool grant must be valid")
			return
		}
		response.Success(c, grant)
	case "poll":
		delivery, err := h.jStore.Poll(ctx, key.UserID, key.ID, input.Grant, input.Secret)
		if err != nil {
			response.Error(c, 403, "Tool grant is unavailable")
			return
		}
		response.Success(c, delivery)
	case "check":
		valid, err := h.jStore.CheckTool(ctx, key.UserID, key.ID, input.Grant, input.Secret, input.Task, input.Call, input.Lease)
		if err != nil {
			response.Error(c, 503, "Tool lease check failed")
			return
		}
		response.Success(c, gin.H{"active": valid})
	case "complete":
		if err := h.jStore.CompleteTool(ctx, key.UserID, key.ID, input.Grant, input.Secret, input.Task, input.Call, input.Lease, input.Output); err != nil {
			response.Error(c, 409, "Tool result is expired, cancelled or already consumed")
			return
		}
		response.Success(c, gin.H{"accepted": true})
	case "revoke":
		if err := h.jStore.RevokeGrant(ctx, key.UserID, key.ID, input.Grant); err != nil {
			response.Error(c, 503, "Could not revoke the tool grant")
			return
		}
		response.Success(c, gin.H{"revoked": true})
	default:
		response.NotFound(c, "Unknown bridge action")
	}
}
