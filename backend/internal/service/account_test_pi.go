package service

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

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
	runtimeAccount, resolveErr := ResolveNativePiRuntimeAccount(c.Request.Context(), s.accountRepo, account)
	if err := ValidateExecutionAccount(account); err != nil || resolveErr != nil || ValidateExecutionAccount(runtimeAccount) != nil {
		return s.sendErrorAndEnd(c, "Invalid Pi account binding")
	}
	if isOpenAIImageModel(model) {
		return s.sendErrorAndEnd(c, "Pi account tests support Responses text only")
	}
	if s.openaiGatewayService == nil || s.openaiGatewayService.openAITokenProvider == nil {
		return s.sendErrorAndEnd(c, "Pi token provider unavailable")
	}
	if model == "" { model = openai.DefaultTestModel }
	model = account.GetMappedModel(model)
	token, err := s.openaiGatewayService.openAITokenProvider.GetAccessToken(c.Request.Context(), runtimeAccount)
	if err != nil { return s.sendErrorAndEnd(c, "Pi credential unavailable; reauthorize this account") }
	owner, _ := strconv.ParseInt(runtimeAccount.GetCredential("pi_owner_user_id"), 10, 64)
	if mode == AccountTestModeCompact {
		return s.testNativePiCompactAccount(c, account, model, token, owner)
	}
	transport := account.GetCredential("pi_transport")
	if transport == "" { transport = "sse" }
	resp, err := piruntime.Do(c.Request.Context(), "/responses", map[string]any{
		"request": createOpenAITestPayload(model, true, prompt), "access_token": token,
		"owner_id": owner, "credential_id": runtimeAccount.ID, "account_id": runtimeAccount.GetCredential("chatgpt_account_id"),
		"session_id": "admin-test-" + uuid.NewString(), "transport": transport,
	})
	if err != nil { return s.sendErrorAndEnd(c, "Pi runtime unavailable") }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { return s.sendErrorAndEnd(c, "Pi runtime rejected the test (HTTP " + strconv.Itoa(resp.StatusCode) + ")") }
	s.sendEvent(c, TestEvent{Type: "test_start", Model: model})
	return s.processOpenAIStream(c, resp.Body)
}

func (s *AccountTestService) testNativePiCompactAccount(c *gin.Context, account *Account, model, token string, owner int64) error {
	runtimeAccount, resolveErr := ResolveNativePiRuntimeAccount(c.Request.Context(), s.accountRepo, account)
	if resolveErr != nil {
		return s.sendErrorAndEnd(c, "Invalid Pi account binding")
	}
	request := createOpenAITestPayload(model, true, "compact probe")
	delete(request, "stream")
	s.sendEvent(c, TestEvent{Type: "test_start", Model: model})
	resp, err := piruntime.Do(c.Request.Context(), "/compact", map[string]any{
		"request": request, "access_token": token,
		"owner_id": owner, "credential_id": runtimeAccount.ID,
		"account_id": runtimeAccount.GetCredential("chatgpt_account_id"),
	})
	if err != nil {
		return s.sendErrorAndEnd(c, "Pi compact runtime unavailable")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode != http.StatusOK {
		return s.sendErrorAndEnd(c, "Pi compact probe rejected (HTTP "+strconv.Itoa(resp.StatusCode)+")")
	}
	var result struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &result); err != nil || result.ID == "" {
		return s.sendErrorAndEnd(c, "Pi compact probe returned an invalid response")
	}
	if s.accountRepo != nil {
		updates := map[string]any{
			"openai_compact_supported": true,
			"openai_compact_last_status": http.StatusOK,
			"openai_compact_checked_at": time.Now().UTC().Format(time.RFC3339),
		}
		_ = s.accountRepo.UpdateExtra(c.Request.Context(), account.ID, updates)
		mergeAccountExtra(account, updates)
	}
	s.sendEvent(c, TestEvent{Type: "content", Text: "Compact probe succeeded (Pi standalone Responses compact)"})
	s.sendEvent(c, TestEvent{Type: "test_complete", Success: true})
	return nil
}
