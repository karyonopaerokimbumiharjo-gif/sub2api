package admin

import (
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

func (h *OpenAIOAuthHandler) ListCPACredentials(c *gin.Context) {
	if h.cpaRuntimeService == nil {
		response.BadRequest(c, "CPA settings service is unavailable")
		return
	}
	items, err := h.cpaRuntimeService.ListCPACredentials(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, items)
}

func (h *OpenAIOAuthHandler) UpdateCPACredential(c *gin.Context) {
	if h.cpaRuntimeService == nil {
		response.BadRequest(c, "CPA settings service is unavailable")
		return
	}
	var input service.CPACredentialUpdate
	if err := c.ShouldBindJSON(&input); err != nil {
		response.BadRequest(c, "Invalid credential settings")
		return
	}
	item, err := h.cpaRuntimeService.UpdateCPACredential(c.Request.Context(), input)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, item)
}
