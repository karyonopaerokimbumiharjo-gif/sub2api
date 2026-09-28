package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/piruntime"
	"github.com/google/uuid"
)

// Keep the original Images parsers, model selection and billing, but execute
// through the selected Pi credential and network route. Admin tests share this
// transport; public callers additionally pass the gateway's API-key group gate.
func (s *OpenAIGatewayService) openNativePiMediaResponse(ctx context.Context, account *Account, body []byte, targetURL string) (*http.Response, error) {
	runtimeAccount, err := ResolveNativePiRuntimeAccount(ctx, s.accountRepo, account)
	if err != nil || ValidateExecutionAccount(account) != nil || ValidateExecutionAccount(runtimeAccount) != nil {
		return nil, errors.New("Pi image credential binding is unavailable")
	}
	if s.openAITokenProvider == nil {
		return nil, errors.New("Pi token provider unavailable")
	}
	token, err := s.openAITokenProvider.GetAccessToken(ctx, runtimeAccount)
	if err != nil {
		return nil, errors.New("Pi credential unavailable; reauthorize this account")
	}
	owner, err := strconv.ParseInt(runtimeAccount.GetCredential("pi_owner_user_id"), 10, 64)
	if err != nil || owner <= 0 {
		return nil, errors.New("Pi credential owner is invalid")
	}
	var request map[string]any
	if json.Unmarshal(body, &request) != nil {
		return nil, errors.New("Invalid Pi image request")
	}
	path := "/responses"
	endpoint := ""
	if targetURL != chatgptCodexURL {
		base := strings.TrimSuffix(chatgptCodexURL, "/responses")
		for _, candidate := range []string{"/images/generations", "/images/edits"} {
			if targetURL == base+candidate {
				endpoint = candidate
			}
		}
		if endpoint == "" {
			return nil, errors.New("Unsupported Pi image endpoint")
		}
		path = "/images"
	}
	headerMS, idleMS := s.nativePiRuntimeTimeouts()
	return piruntime.Do(ctx, path, map[string]any{
		"request": request, "endpoint": endpoint, "access_token": token,
		"account_id": runtimeAccount.GetCredential("chatgpt_account_id"), "owner_id": owner, "credential_id": runtimeAccount.ID,
		"session_id": "images-" + uuid.NewString(), "transport": "sse",
		"response_header_timeout_ms": headerMS, "stream_idle_timeout_ms": idleMS,
	})
}
