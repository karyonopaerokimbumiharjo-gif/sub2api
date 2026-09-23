package handler

import (
	"errors"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/jruntime"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

const (
	gpt6JModeHeader               = "X-Sub2API-Model-Mode"
	gpt6JEnhancedCompactionHeader = "X-Sub2API-Enhanced-Compaction"
	gpt6JContextKey               = service.OpenAIGPT6JContextKey
	gpt6JModeValue                = "gpt6j"
	gpt6JUpstreamModel            = "gpt-6-astra"
)

type gpt6JRequestMode struct {
	Enabled     bool
	BaseModel   string
	PublicModel string
}

var (
	errGPT6JWrongModel        = errors.New("J execution requires an eligible OpenAI text base model")
	errGPT6JCompactionRetired = errors.New("Jev context pruning has been removed; use native context management")
)

func parseGPT6JRequestMode(c *gin.Context, requestedModel string) (gpt6JRequestMode, error) {
	if c == nil || c.Request == nil {
		return gpt6JRequestMode{}, nil
	}
	modeValue := strings.ToLower(strings.TrimSpace(c.GetHeader(gpt6JModeHeader)))
	rawEnhanced := strings.TrimSpace(c.GetHeader(gpt6JEnhancedCompactionHeader))

	// Control headers are consumed by Sub2API and must never be forwarded to an
	// upstream model provider.
	c.Request.Header.Del(gpt6JModeHeader)
	c.Request.Header.Del(gpt6JEnhancedCompactionHeader)

	base, alias := jruntime.BaseModel(strings.TrimSpace(requestedModel))
	mode := gpt6JRequestMode{Enabled: modeValue == gpt6JModeValue || modeValue == "j" || alias, BaseModel: base, PublicModel: requestedModel}

	if rawEnhanced != "" && !strings.EqualFold(rawEnhanced, "false") && rawEnhanced != "0" {
		return mode, errGPT6JCompactionRetired
	}
	if mode.Enabled && !jruntime.EligibleModel(base) {
		return mode, errGPT6JWrongModel
	}
	if mode.Enabled {
		c.Set(gpt6JContextKey, true)
		c.Set(service.OpenAIJBaseModelContextKey, base)
	}

	return mode, nil
}
