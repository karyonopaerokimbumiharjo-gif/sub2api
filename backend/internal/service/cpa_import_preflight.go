package service

import (
	"context"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"net/http"
	"time"
)

// Retry only the read-only validation. Never upload an unverified credential.
func preflightCPAImport(ctx context.Context, config openAIQuotaBridgeConfig, accessToken, accountID, proxyURL string) error {
	payload := openAIQuotaBridgeAPICallRequest{Method: http.MethodGet, URL: chatGPTUsageURL,
		Header: buildCodexCommonHeaders(accessToken, accountID, false), ProxyURL: proxyURL}
	for attempt := 0; attempt < 2; attempt++ {
		var response openAIQuotaBridgeAPICallResponse
		err := callOpenAIQuotaBridgeManagement(ctx, config, http.MethodPost, "/v0/management/api-call", payload, &response)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil && response.StatusCode == http.StatusOK {
			return nil
		}
		status := response.StatusCode
		if err != nil {
			status, _ = infraerrors.ToHTTP(err)
		}
		if status < 500 && status != http.StatusTooManyRequests && status > 0 {
			if err != nil {
				return err
			}
			return infraerrors.BadRequest("OPENAI_CPA_IMPORT_CREDENTIAL_REJECTED", "CPA 未能验证此 OAuth 授权；现有账号池未修改，请重新授权后重试")
		}
		if attempt == 0 {
			timer := time.NewTimer(300 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return infraerrors.New(http.StatusServiceUnavailable, "OPENAI_CPA_IMPORT_PREFLIGHT_UNAVAILABLE", "授权已取得，但 CPA 出口暂时无法验证；现有账号池未修改，请重试导入，无需重复授权")
}
