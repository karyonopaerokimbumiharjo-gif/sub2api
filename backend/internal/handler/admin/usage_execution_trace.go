package admin

import (
	"sort"
	"strconv"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/executiontrace"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/gin-gonic/gin"
)

// ExecutionTrace exposes recent metadata-only GPT-6J events through the
// existing admin-authenticated usage route. It cannot return request content.
func (h *UsageHandler) ExecutionTrace(c *gin.Context) {
	limit := executiontrace.DefaultListLimit
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > executiontrace.MaxListLimit {
			response.BadRequest(c, "limit must be between 1 and 200")
			return
		}
		limit = parsed
	}
	events := executiontrace.Default.List(c.Query("request_id"), limit)
	if h.jStore != nil {
		durable, err := h.jStore.ListEvents(c.Request.Context(), c.Query("request_id"), limit)
		if err != nil {
			response.Error(c, 503, "Execution history is unavailable")
			return
		}
		events = append(events, durable...)
		sort.SliceStable(events, func(i, j int) bool { return events[i].Time > events[j].Time })
		if len(events) > limit {
			events = events[:limit]
		}
	}
	response.Success(c, events)
}
