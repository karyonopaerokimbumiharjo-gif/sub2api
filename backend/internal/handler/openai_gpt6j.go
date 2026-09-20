package handler

import (
	"errors"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	gpt6JModeHeader                = "X-Sub2API-Model-Mode"
	gpt6JEnhancedCompactionHeader = "X-Sub2API-Enhanced-Compaction"
	gpt6JModeValue                 = "gpt6j"
	gpt6JUpstreamModel             = "gpt-6-astra"
)

type gpt6JRequestMode struct {
	Enabled             bool
	EnhancedCompaction bool
}

var (
	errGPT6JWrongModel        = errors.New("gpt6j mode requires model gpt-6-astra")
	errGPT6JCompactionNoMode  = errors.New("enhanced compaction is only available in GPT-6J mode")
	errGPT6JInvalidToggle     = errors.New("invalid enhanced compaction toggle")
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

	mode := gpt6JRequestMode{Enabled: modeValue == gpt6JModeValue}
	if rawEnhanced != "" {
		enabled, err := strconv.ParseBool(rawEnhanced)
		if err != nil {
			return mode, errGPT6JInvalidToggle
		}
		mode.EnhancedCompaction = enabled
	}
	if mode.EnhancedCompaction && !mode.Enabled {
		return mode, errGPT6JCompactionNoMode
	}
	if mode.Enabled && !strings.EqualFold(strings.TrimSpace(requestedModel), gpt6JUpstreamModel) {
		return mode, errGPT6JWrongModel
	}
	return mode, nil
}
