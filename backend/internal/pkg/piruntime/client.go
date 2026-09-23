// Package piruntime connects the gateway to its private, pinned Pi SDK runtime.
package piruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var client = func() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil // Never send the private runtime bearer through an ambient proxy.
	return &http.Client{Transport: transport, Timeout: 130 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}()

func Do(ctx context.Context, path string, payload any) (*http.Response, error) {
	base := strings.TrimRight(os.Getenv("PI_RUNTIME_URL"), "/")
	parsed, err := url.Parse(base)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("Pi runtime is not configured")
	}
	if parsed.Scheme != "https" && (parsed.Scheme != "http" || (parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "localhost" && parsed.Hostname() != "pi-runtime")) {
		return nil, errors.New("Pi runtime requires HTTPS or private local transport")
	}
	file := os.Getenv("PI_RUNTIME_SECRET_FILE")
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("Pi runtime secret file must be private")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, errors.New("Pi runtime secret unavailable")
	}
	secret := strings.TrimSpace(string(raw))
	if len(secret) < 32 {
		return nil, errors.New("Pi runtime secret invalid")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.New("invalid Pi request")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")
	return client.Do(req)
}
func JSON(ctx context.Context, path string, payload, target any) error {
	resp, err := Do(ctx, path, payload)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var failure struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&failure)
		// Only expose stable codes we own, never a provider body or OAuth payload.
		switch failure.Error {
		case "oauth_session_mismatch", "oauth_callback_mismatch", "oauth_account_mismatch", "oauth_start_failed", "oauth_exchange_failed", "oauth_exchange_timeout", "oauth_login_in_progress", "oauth_access_rejected", "oauth_access_invalid_response", "pi_upstream_busy", "pi_upstream_rate_limited", "pi_upstream_authorization_rejected", "pi_upstream_failed":
			return &Error{Code: failure.Error}
		default:
			return &Error{Code: "pi_runtime_unavailable"}
		}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024+1))
	if err != nil || len(data) > 1024*1024 {
		return errors.New("invalid Pi runtime response")
	}
	return json.Unmarshal(data, target)
}

// Error carries a credential-free error code from the private runtime.
type Error struct{ Code string }

func (e *Error) Error() string { return e.Code }

// PublicMessage describes an actionable recovery without exposing credentials.
func PublicMessage(err error) string {
	var failure *Error
	if errors.As(err, &failure) {
		switch failure.Code {
		case "oauth_session_mismatch":
			return "Pi 授权会话已过期或归属用户不匹配，请重新生成授权链接并登录"
		case "oauth_callback_mismatch":
			return "回调地址与本次 Pi 授权不匹配，请粘贴本次登录的完整回调地址"
		case "oauth_exchange_failed":
			return "Pi 授权码交换失败，请重新生成授权链接；若仍失败，请检查 Pi 节点到授权服务的连接"
		case "oauth_exchange_timeout":
			return "Pi 授权服务连接超时，请检查节点网络后重新授权"
		case "oauth_login_in_progress":
			return "已有 Pi 授权正在进行，请先完成该次授权或等待其过期"
		case "oauth_account_mismatch":
			return "Pi 返回的账号身份与当前账号不一致，请使用同一账号重新授权"
		}
	}
	return "Pi 授权服务不可用，请检查 Pi 节点状态和网络后重试"
}
