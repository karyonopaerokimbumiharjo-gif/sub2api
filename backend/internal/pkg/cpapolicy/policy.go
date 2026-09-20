// Package cpapolicy defines the deployment's mandatory inference boundary.
// There is deliberately no direct-backend switch.
package cpapolicy

import (
	"net/http"
	"net/url"
	"strings"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

const BaseURL = "http://cpa:8317"

func Required() error {
	return infraerrors.BadRequest("CPA_BACKEND_REQUIRED", "所有账号和审计必须通过 CPA；请使用 CPA 账号导入入口")
}

func ValidateBaseURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !validOrigin(u) || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" {
		return Required()
	}
	if path := strings.TrimRight(u.Path, "/"); path != "" && path != "/v1" {
		return Required()
	}
	return nil
}

func validOrigin(u *url.URL) bool {
	return u != nil && u.Scheme == "http" && strings.EqualFold(u.Host, "cpa:8317") && u.User == nil && u.Opaque == ""
}

func ValidateRequest(req *http.Request) error {
	if req == nil || !validOrigin(req.URL) || (req.Host != "" && !strings.EqualFold(req.Host, "cpa:8317")) {
		return Required()
	}
	return nil
}

// NoRedirect prevents a trusted CPA response from forwarding prompts or keys
// to another destination, including same-host redirects with different ports.
func NoRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
