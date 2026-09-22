package admin

import (
	"net/http"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/gin-gonic/gin"
)

// SyncCPAAccounts makes specifically imported CPA Codex auth files visible in
// the Sub2 account list. It does not activate or group newly created accounts.
func (h *OpenAIOAuthHandler) SyncCPAAccounts(c *gin.Context) {
	if h.cpaRuntimeService == nil {
		response.Error(c, http.StatusServiceUnavailable, "CPA account synchronization is unavailable")
		return
	}
	var request struct {
		AuthNames []string `json:"auth_names" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(c, "Invalid CPA auth file selection")
		return
	}
	result, err := h.cpaRuntimeService.SyncCPAAccounts(c.Request.Context(), request.AuthNames)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, result)
}
