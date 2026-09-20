package handler

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestParseGPT6JRequestMode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	req := httptest.NewRequest("POST", "/openai/v1/responses", nil)
	req.Header.Set(gpt6JModeHeader, "gpt6j")
	req.Header.Set(gpt6JEnhancedCompactionHeader, "true")
	c.Request = req

	mode, err := parseGPT6JRequestMode(c, "gpt-6-astra")
	require.NoError(t, err)
	require.True(t, mode.Enabled)
	require.True(t, mode.EnhancedCompaction)
	require.Empty(t, c.Request.Header.Get(gpt6JModeHeader))
	require.Empty(t, c.Request.Header.Get(gpt6JEnhancedCompactionHeader))
}

func TestGPT6JRejectsWrongModelAndStandaloneCompression(t *testing.T) {
	gin.SetMode(gin.TestMode)
	t.Run("wrong model", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest("POST", "/openai/v1/responses", nil)
		req.Header.Set(gpt6JModeHeader, "gpt6j")
		c.Request = req
		_, err := parseGPT6JRequestMode(c, "gpt-5.6-sol")
		require.ErrorIs(t, err, errGPT6JWrongModel)
	})
	t.Run("enhanced without mode", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest("POST", "/openai/v1/responses", nil)
		req.Header.Set(gpt6JEnhancedCompactionHeader, "true")
		c.Request = req
		_, err := parseGPT6JRequestMode(c, "gpt-6-astra")
		require.ErrorIs(t, err, errGPT6JCompactionNoMode)
	})
	t.Run("invalid toggle", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest("POST", "/openai/v1/responses", nil)
		req.Header.Set(gpt6JModeHeader, "gpt6j")
		req.Header.Set(gpt6JEnhancedCompactionHeader, "maybe")
		c.Request = req
		_, err := parseGPT6JRequestMode(c, "gpt-6-astra")
		require.ErrorIs(t, err, errGPT6JInvalidToggle)
	})
}
