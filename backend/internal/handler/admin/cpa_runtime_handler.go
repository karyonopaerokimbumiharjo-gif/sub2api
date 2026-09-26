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
	if h.adminService != nil {
		accounts, listErr := h.adminService.ListAccountsForSchedulerScoreFilter(c.Request.Context(), service.PlatformOpenAI, "", "", "", 0, "")
		if listErr != nil {
			response.ErrorFrom(c, listErr)
			return
		}
		attachCPABusinessAccounts(items, accounts)
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
	var accounts []service.Account
	if h.adminService != nil {
		var listErr error
		accounts, listErr = h.adminService.ListAccountsForSchedulerScoreFilter(c.Request.Context(), service.PlatformOpenAI, "", "", "", 0, "")
		if listErr != nil {
			response.ErrorFrom(c, listErr)
			return
		}
	}
	item, err := h.cpaRuntimeService.UpdateCPACredential(c.Request.Context(), input)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if h.adminService != nil {
		items := []service.CPACredentialSettings{*item}
		attachCPABusinessAccounts(items, accounts)
		*item = items[0]
	}
	response.Success(c, item)
}

// Saved CPA authorization metadata can survive a switch to Pi or deletion of
// its business account. Describe that binding separately from CPA scheduling;
// it is not evidence of the current Pi route or a measured egress address.
func attachCPABusinessAccounts(items []service.CPACredentialSettings, accounts []service.Account) {
	for i := range items {
		item := &items[i]
		bestScore, matches, selected := 0, 0, -1
		for j := range accounts {
			a := &accounts[j]
			if a.Platform != service.PlatformOpenAI {
				continue
			}
			score := 0
			switch {
			case item.AuthID != "" && a.GetExtraString("cpa_auth_id") == item.AuthID:
				score = 3
			case item.Name != "" && a.GetExtraString(service.OpenAIQuotaBridgeAuthNameExtraKey) == item.Name:
				score = 2
			case item.Identity != "" && a.GetExtraString("cpa_identity") == item.Identity:
				score = 1
			}
			if score > bestScore {
				bestScore, matches, selected = score, 1, j
			} else if score > 0 && score == bestScore {
				matches++
			}
		}
		if matches != 1 {
			continue
		}
		a := &accounts[selected]
		item.BusinessAccountID, item.BusinessStatus = a.ID, a.Status
		item.Schedulable, item.GroupIDs = a.Schedulable, a.GroupIDs
		if a.UsesNativePiRuntime() {
			item.BusinessBackend = "pi"
		} else if service.ValidateCPAAccount(a) == nil {
			item.BusinessBackend = "cpa"
		}
		item.CPARoutingEnabled = item.BusinessBackend == "cpa" && a.IsActive() && a.Schedulable && !item.Disabled && !item.Unavailable
	}
}
