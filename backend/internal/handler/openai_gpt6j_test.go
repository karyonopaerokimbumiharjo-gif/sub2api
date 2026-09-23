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
	req.Header.Set(gpt6JEnhancedCompactionHeader, "false")
	c.Request = req

	mode, err := parseGPT6JRequestMode(c, "gpt-6-astra")
	require.NoError(t, err)
	require.True(t, mode.Enabled)
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
		_, err := parseGPT6JRequestMode(c, "gpt-image-2")
		require.ErrorIs(t, err, errGPT6JWrongModel)
	})
	t.Run("enhanced without mode", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest("POST", "/openai/v1/responses", nil)
		req.Header.Set(gpt6JEnhancedCompactionHeader, "true")
		c.Request = req
		_, err := parseGPT6JRequestMode(c, "gpt-6-astra")
		require.ErrorIs(t, err, errGPT6JCompactionRetired)
	})
	t.Run("invalid toggle", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		req := httptest.NewRequest("POST", "/openai/v1/responses", nil)
		req.Header.Set(gpt6JModeHeader, "gpt6j")
		req.Header.Set(gpt6JEnhancedCompactionHeader, "maybe")
		c.Request = req
		_, err := parseGPT6JRequestMode(c, "gpt-6-astra")
		require.ErrorIs(t, err, errGPT6JCompactionRetired)
	})
}

func TestGPT6JNamedModelActivatesModeWithoutHeaders(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/v1/responses", nil)
	mode, err := parseGPT6JRequestMode(c, "gpt-6j")
	require.NoError(t, err)
	require.True(t, mode.Enabled)
	require.True(t, c.GetBool(gpt6JContextKey))
}

func TestGPT6JRetiredCompactionIsExplicitlyRejected(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("POST", "/v1/responses", nil)
	c.Request.Header.Set(gpt6JEnhancedCompactionHeader, "true")
	_, err := parseGPT6JRequestMode(c, "gpt-6j")
	require.ErrorIs(t, err, errGPT6JCompactionRetired)
	require.Empty(t, c.Request.Header.Get(gpt6JEnhancedCompactionHeader))
}
