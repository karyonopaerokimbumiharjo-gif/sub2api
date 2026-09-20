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
		return errors.New("Pi runtime request failed")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024+1))
	if err != nil || len(data) > 1024*1024 {
		return errors.New("invalid Pi runtime response")
	}
	return json.Unmarshal(data, target)
}
