package service

import (
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
)

const OpenAIGPT6JContextKey = "sub2api.gpt6j.required"

// Validate the final model after channel/account mapping, including fallbacks.
func validateGPT6JUpstreamModel(c *gin.Context, model string) error {
	if c != nil && c.GetBool(OpenAIGPT6JContextKey) && strings.TrimSpace(model) != "gpt-6-astra" {
		return errors.New("GPT-6J cannot forward to a different upstream model")
	}
	return nil
}
