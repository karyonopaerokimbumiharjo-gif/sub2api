package service

import (
	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
	"testing"
)

func TestSafetyIdentifierIsStableTenantScopedAndServerOwned(t *testing.T) {
	secret := "fixture-only-secret-with-more-than-32-bytes"
	a := safetyIdentifier(secret, 12)
	require.Len(t, a, 64)
	require.Equal(t, a, safetyIdentifier(secret, 12))
	require.NotEqual(t, a, safetyIdentifier(secret, 13))
	require.NotEqual(t, a, safetyIdentifier(secret+"other", 12))
	require.Empty(t, safetyIdentifier("", 12))
	c, _ := gin.CreateTestContext(nil)
	c.Set("api_key", &APIKey{UserID: 12})
	svc := &OpenAIGatewayService{cfg: &config.Config{JWT: config.JWTConfig{Secret: secret}}}
	account := &Account{Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Credentials: map[string]any{"base_url": "https://api.openai.com/v1"}}
	body := []byte(`{"safety_identifier":"pretend-user","input":"hello"}`)
	require.Equal(t, a, gjson.GetBytes(svc.applySafetyIdentifier(c, account, body), "safety_identifier").String())
	account.Credentials["base_url"] = "http://cpa:8317/v1"
	require.False(t, gjson.GetBytes(svc.applySafetyIdentifier(c, account, body), "safety_identifier").Exists())
}
