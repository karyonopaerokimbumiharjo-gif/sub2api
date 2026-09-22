package service

import (
	"net/http"
	"strconv"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/Wei-Shaw/sub2api/internal/pkg/piruntime"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Admin probes use the same private runtime and credential binding as traffic.
// Never fall through to the ordinary Codex HTTP tester for a Pi account.
func (s *AccountTestService) testNativePiAccount(c *gin.Context, account *Account, model, prompt, mode string) error {
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("X-Accel-Buffering", "no")
	if err := ValidateExecutionAccount(account); err != nil {
		return s.sendErrorAndEnd(c, "Invalid Pi account binding")
	}
	if mode == AccountTestModeCompact || isOpenAIImageModel(model) {
		return s.sendErrorAndEnd(c, "Pi account tests support Responses text only")
	}
	if s.openaiGatewayService == nil || s.openaiGatewayService.openAITokenProvider == nil {
		return s.sendErrorAndEnd(c, "Pi token provider unavailable")
	}
	if model == "" { model = openai.DefaultTestModel }
	model = account.GetMappedModel(model)
	token, err := s.openaiGatewayService.openAITokenProvider.GetAccessToken(c.Request.Context(), account)
	if err != nil { return s.sendErrorAndEnd(c, "Pi credential unavailable; reauthorize this account") }
	owner, _ := strconv.ParseInt(account.GetCredential("pi_owner_user_id"), 10, 64)
	transport := account.GetCredential("pi_transport")
	if transport == "" { transport = "sse" }
	resp, err := piruntime.Do(c.Request.Context(), "/responses", map[string]any{
		"request": createOpenAITestPayload(model, true, prompt), "access_token": token,
		"owner_id": owner, "credential_id": account.ID, "account_id": account.GetCredential("chatgpt_account_id"),
		"session_id": "admin-test-" + uuid.NewString(), "transport": transport,
	})
	if err != nil { return s.sendErrorAndEnd(c, "Pi runtime unavailable") }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { return s.sendErrorAndEnd(c, "Pi runtime rejected the test (HTTP " + strconv.Itoa(resp.StatusCode) + ")") }
	s.sendEvent(c, TestEvent{Type: "test_start", Model: model})
	return s.processOpenAIStream(c, resp.Body)
}
