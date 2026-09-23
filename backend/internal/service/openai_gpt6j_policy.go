package service

import (
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
)

const OpenAIGPT6JContextKey = "sub2api.gpt6j.required"
const OpenAIJBaseModelContextKey = "sub2api.j.base_model"

func jExpectedBase(c *gin.Context) string {
	if c != nil {
		if model := c.GetString(OpenAIJBaseModelContextKey); model != "" {
			return model
		}
	}
	return "gpt-6-astra"
}

// Validate the final model after channel/account mapping, including fallbacks.
func validateGPT6JUpstreamModel(c *gin.Context, model string) error {
	if c != nil && c.GetBool(OpenAIGPT6JContextKey) && strings.TrimSpace(model) != jExpectedBase(c) {
		return errors.New("J cannot forward to a different selected base model")
	}
	return nil
}
