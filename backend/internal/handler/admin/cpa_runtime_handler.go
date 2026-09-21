package admin

import (
	"encoding/json"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"os"
	"time"
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
		accounts, listErr := h.adminService.ListAccountsForSchedulerScoreFilter(c.Request.Context(), service.PlatformOpenAI, service.AccountTypeAPIKey, "", "", 0, "")
		if listErr != nil {
			response.ErrorFrom(c, listErr)
			return
		}
		for i := range items {
			for _, a := range accounts {
				if a.GetExtraString("cpa_identity") == items[i].Identity {
					items[i].BusinessAccountID = a.ID
					items[i].BusinessStatus = a.Status
					items[i].Schedulable = a.Schedulable
					items[i].GroupIDs = a.GroupIDs
					break
				}
			}
		}
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

// CPAStateStatus returns only safe metadata, never the state envelope or auth index.
func (h *OpenAIOAuthHandler) CPAStateStatus(c *gin.Context) {
	path := os.Getenv("SUB2API_CPA_STATE_FILE")
	if path == "" {
		response.Success(c, gin.H{"available": false, "reason": "状态采集器未连接"})
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		response.Success(c, gin.H{"available": false, "reason": "无法读取状态采集器"})
		return
	}
	var snapshot struct {
		Models []string `json:"models"`
		Enabled   bool  `json:"enabled"`
		UpdatedAt int64 `json:"updated_at"`
		Standbys  map[string]struct {
			State     string `json:"state"`
			ExpiresAt int64  `json:"expires_at"`
		} `json:"standbys"`
		Entries map[string]struct {
			State     string `json:"state"`
			ExpiresAt int64  `json:"expires_at"`
		} `json:"entries"`
		Events []struct {
			Time      int64  `json:"time"`
            Reason string `json:"reason"`
            Action string `json:"action"`
            ActualModel string `json:"actual_model"`
			Model     string `json:"model"`
			Length    int    `json:"length"`
			Status    int    `json:"status"`
			Completed bool   `json:"completed"`
			Accepted  bool   `json:"accepted"`
		} `json:"events"`
	}
	if json.Unmarshal(data, &snapshot) != nil {
		response.Success(c, gin.H{"available": false, "reason": "状态快照不可解析"})
		return
	}
	now := time.Now().Unix()
	states := []gin.H{}
	for key, value := range snapshot.Entries {
		model := ""
		for i := len(key) - 1; i >= 0; i-- {
			if key[i] == 0 {
				model = key[i+1:]
				break
			}
		}
		reserve := snapshot.Standbys[key]
		states = append(states, gin.H{"standby_present": len(reserve.State) > 0, "standby_length": len(reserve.State), "standby_expires_at": reserve.ExpiresAt, "standby_ready": snapshot.Enabled && now-snapshot.UpdatedAt <= 30 && now < reserve.ExpiresAt && len(reserve.State) == 292, "model": model, "length": len(value.State), "expires_at": value.ExpiresAt, "ready": snapshot.Enabled && now-snapshot.UpdatedAt <= 30 && now < value.ExpiresAt && len(value.State) == 292})
	}
	response.Success(c, gin.H{"available": true, "models": snapshot.Models, "enabled": snapshot.Enabled, "updated_at": snapshot.UpdatedAt, "healthy": now-snapshot.UpdatedAt <= 30, "states": states, "events": snapshot.Events})
}
