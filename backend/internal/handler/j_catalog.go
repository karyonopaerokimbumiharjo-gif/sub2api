package handler

import (
	"encoding/json"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/jruntime"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

const jCatalogContext = "sub2api.j.catalog"

func (h *OpenAIGatewayHandler) JModeContext(c *gin.Context) {
	key, ok := middleware2.GetAPIKeyFromContext(c)
	if !ok || key == nil || key.Group == nil || key.Group.Platform != service.PlatformOpenAI || h.jStore == nil {
		c.Next()
		return
	}
	enabled, err := h.jStore.Enabled(c.Request.Context(), key.UserID, key.ID)
	if err != nil {
		enabled = false
	}
	c.Set(jCatalogContext, enabled)
	if strings.Contains(c.FullPath(), "/models") {
		// Upstream ETags do not include this key's local J setting.
		c.Set("sub2api.j.client_etag", c.GetHeader("If-None-Match"))
		c.Request.Header.Del("If-None-Match")
	}
	c.Next()
}

func decorateJCatalogue(c *gin.Context, body []byte) []byte {
	value, present := c.Get(jCatalogContext)
	if !present {
		return body
	}
	enabled, _ := value.(bool)
	var catalog map[string]json.RawMessage
	if json.Unmarshal(body, &catalog) != nil {
		return body
	}
	field, idField := "data", "id"
	if _, ok := catalog["models"]; ok {
		field, idField = "models", "slug"
	}
	var entries []map[string]json.RawMessage
	if json.Unmarshal(catalog[field], &entries) != nil {
		return body
	}
	final := make([]map[string]json.RawMessage, 0, len(entries)*2)
	for _, entry := range entries {
		var id string
		_ = json.Unmarshal(entry[idField], &id)
		if _, alias := jruntime.BaseModel(id); alias {
			continue
		}
		final = append(final, entry)
		if !enabled || !jruntime.EligibleModel(id) {
			continue
		}
		alias := map[string]json.RawMessage{}
		for k, v := range entry {
			alias[k] = v
		}
		alias[idField], _ = json.Marshal(jruntime.Alias(id))
		if idField == "id" {
			alias["owned_by"] = json.RawMessage(`"pegasusailabs"`)
		} else {
			alias["display_name"], _ = json.Marshal(id + " + Jev")
			alias["description"], _ = json.Marshal("J cooperation with " + id + "; full-input Responses API")
			alias["prefer_websockets"] = json.RawMessage(`false`)
			alias["supports_websockets"] = json.RawMessage(`false`)
		}
		final = append(final, alias)
		if id == "gpt-6-astra" {
			legacy := map[string]json.RawMessage{}
			for k, v := range alias {
				legacy[k] = v
			}
			legacy[idField] = json.RawMessage(`"gpt-6j"`)
			final = append(final, legacy)
		}
	}
	catalog[field], _ = json.Marshal(final)
	out, err := json.Marshal(catalog)
	if err != nil {
		return body
	}
	return out
}
