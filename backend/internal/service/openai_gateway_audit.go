package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
)

const (
	openAIAuditDefaultMaxOutputTokens = 512
	openAIAuditMaxSSELineBytes        = 4 << 20
)

// GenerateText performs a small internal classifier request through an existing
// OpenAI account. It bypasses the public gateway, so prompt audit
// cannot recursively audit its own classifier call.
func (s *OpenAIGatewayService) GenerateText(
	ctx context.Context,
	account *Account,
	modelID string,
	systemPrompt string,
	userPrompt string,
	maxOutputTokens int,
) (*TestConnectionResult, error) {
	if s == nil || s.httpUpstream == nil || account == nil {
		return nil, errors.New("openai internal audit dependencies unavailable")
	}
	if account.Platform != PlatformOpenAI {
		return nil, fmt.Errorf("openai internal audit requires an OpenAI account")
	}
	mappedModel := account.GetMappedModel(strings.TrimSpace(modelID))
	if mappedModel == "" {
		return nil, errors.New("openai internal audit model is empty")
	}
	upstreamModel := mappedModel
	if account.Type == AccountTypeOAuth {
		upstreamModel = normalizeOpenAIModelForUpstream(account, mappedModel)
	}
	if maxOutputTokens <= 0 {
		maxOutputTokens = openAIAuditDefaultMaxOutputTokens
	}

	payload := map[string]any{
		"model":        upstreamModel,
		"instructions": strings.TrimSpace(systemPrompt),
		"input": []map[string]any{{
			"role": "user",
			"content": []map[string]any{{
				"type": "input_text",
				"text": userPrompt,
			}},
		}},
		"stream": true,
		// Spark currently accepts low/medium/high/xhigh. Use the least
		// expensive supported effort for the classifier.
		"reasoning": map[string]any{"effort": "low"},
	}
	if account.Type == AccountTypeOAuth {
		payload["store"] = false
	} else {
		payload["max_output_tokens"] = maxOutputTokens
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal openai internal audit payload: %w", err)
	}

	targetURL, err := s.openAIAuditTargetURL(account)
	if err != nil {
		return nil, err
	}
	token, _, err := s.GetAccessToken(ctx, account)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req = req.WithContext(WithHTTPUpstreamProfile(req.Context(), HTTPUpstreamProfileOpenAI))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	authHeaders, err := s.buildOpenAIAuthenticationHeaders(ctx, account, token)
	if err != nil {
		return nil, fmt.Errorf("build openai internal audit authentication: %w", err)
	}
	for key, values := range authHeaders {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	if account.Type == AccountTypeOAuth {
		req.Host = "chatgpt.com"
		if err := resolveAndSetOpenAIChatGPTAccountHeaders(ctx, s.accountRepo, req.Header, account); err != nil {
			return nil, fmt.Errorf("resolve openai internal audit account headers: %w", err)
		}
		req.Header.Set("OpenAI-Beta", "responses=experimental")
		req.Header.Set("originator", openai.CodexDefaultOriginator)
		req.Header.Set("version", codexCLIVersion)
		if customUA := strings.TrimSpace(account.GetOpenAIUserAgent()); customUA != "" {
			req.Header.Set("User-Agent", customUA)
		} else {
			req.Header.Set("User-Agent", codexCLIUserAgent)
		}
		enforceCodexIdentityHeadersWithUA(req.Header, s.codexIdentityOverrideUA(account))
	} else {
		applyOpenAICodexProbeHeaders(req.Header)
	}
	account.ApplyHeaderOverrides(req.Header)

	proxyURL := ""
	if account.ProxyID != nil && account.Proxy != nil {
		proxyURL = account.Proxy.URL()
	}
	resp, err := s.httpUpstream.Do(req, proxyURL, account.ID, account.Concurrency)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		errorBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		message := sanitizeUpstreamErrorMessage(strings.TrimSpace(string(errorBody)))
		if message == "" {
			message = http.StatusText(resp.StatusCode)
		}
		return nil, &UpstreamFailoverError{
			StatusCode:       resp.StatusCode,
			ResponseBody:     errorBody,
			ResponseHeaders:  resp.Header.Clone(),
			Reason:           GatewayFailureReason("prompt_audit_upstream"),
			ClientStatusCode: resp.StatusCode,
			ClientMessage:    message,
		}
	}
	text, usage, err := parseOpenAIAuditSSE(resp.Body)
	if err != nil {
		return nil, err
	}
	result := &TestConnectionResult{Text: text, MappedModel: upstreamModel, Usage: usage}
	if s.billingService != nil {
		tokens := UsageTokens{
			InputTokens:         max(usage.InputTokens-usage.CacheReadInputTokens-usage.CacheCreationInputTokens, 0),
			OutputTokens:        usage.OutputTokens,
			CacheCreationTokens: usage.CacheCreationInputTokens,
			CacheReadTokens:     usage.CacheReadInputTokens,
		}
		cost, pricingErr := s.billingService.CalculateCost(strings.TrimSpace(modelID), tokens, 1)
		if pricingErr != nil && upstreamModel != modelID {
			cost, pricingErr = s.billingService.CalculateCost(upstreamModel, tokens, 1)
		}
		if pricingErr == nil && cost != nil {
			result.EstimatedCostUSD = cost.TotalCost
			result.PricingKnown = true
		}
	}
	return result, nil
}

func (s *OpenAIGatewayService) openAIAuditTargetURL(account *Account) (string, error) {
	if account.Type == AccountTypeOAuth {
		return chatgptCodexURL, nil
	}
	if account.Type != AccountTypeAPIKey {
		return "", fmt.Errorf("unsupported OpenAI account type %q", account.Type)
	}
	baseURL := account.GetOpenAIBaseURL()
	if baseURL == "" {
		return openaiPlatformAPIURL, nil
	}
	normalized, err := s.validateUpstreamBaseURL(baseURL)
	if err != nil {
		return "", err
	}
	return buildOpenAIResponsesURL(normalized), nil
}

type openAIAuditSSEEvent struct {
	Type  string `json:"type"`
	Delta string `json:"delta"`
	Text  string `json:"text"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
	Response *struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
		Output []struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
	} `json:"response"`
}

func parseOpenAIAuditSSE(reader io.Reader) (string, OpenAIUsage, error) {
	if reader == nil {
		return "", OpenAIUsage{}, errors.New("openai internal audit response body is empty")
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), openAIAuditMaxSSELineBytes)
	var output strings.Builder
	var usage OpenAIUsage
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" {
			continue
		}
		if data == "[DONE]" {
			break
		}
		var event openAIAuditSSEEvent
		if err := json.Unmarshal([]byte(data), &event); err != nil {
			continue
		}
		if parsed, ok := extractOpenAIUsageFromJSONBytes([]byte(data)); ok {
			usage = parsed
		}
		switch event.Type {
		case "response.output_text.delta":
			_, _ = output.WriteString(event.Delta)
		case "response.output_text.done":
			if output.Len() == 0 {
				_, _ = output.WriteString(event.Text)
			}
		case "response.completed", "response.done":
			if output.Len() == 0 && event.Response != nil {
				for _, item := range event.Response.Output {
					for _, content := range item.Content {
						_, _ = output.WriteString(content.Text)
					}
				}
			}
			text := strings.TrimSpace(output.String())
			if text == "" {
				return "", usage, errors.New("openai internal audit response content is empty")
			}
			return text, usage, nil
		case "response.failed":
			if event.Response != nil && event.Response.Error != nil && event.Response.Error.Message != "" {
				return "", usage, errors.New(event.Response.Error.Message)
			}
			return "", usage, errors.New("openai internal audit response failed")
		case "error":
			if event.Error != nil && event.Error.Message != "" {
				return "", usage, errors.New(event.Error.Message)
			}
			return "", usage, errors.New("openai internal audit stream error")
		}
	}
	if err := scanner.Err(); err != nil {
		return "", usage, err
	}
	text := strings.TrimSpace(output.String())
	if text == "" {
		return "", usage, errors.New("openai internal audit stream ended without output")
	}
	return text, usage, nil
}
