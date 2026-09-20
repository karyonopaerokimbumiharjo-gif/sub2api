package cpapolicy

import (
	"net/http"
	"testing"
)

func TestCPAOnlyDestination(t *testing.T) {
	for _, raw := range []string{BaseURL, BaseURL + "/", BaseURL + "/v1", BaseURL + "/v1/"} {
		if err := ValidateBaseURL(raw); err != nil {
			t.Fatalf("valid CPA URL rejected: %s", raw)
		}
	}
	for _, raw := range []string{"", "https://api.openai.com", "http://cpa:8317.evil", "http://cpa:8317@evil", "http://user@cpa:8317", "http://cpa:8318", "http://cpa:8317/v1/../proxy", "http://cpa:8317/%76%31", "http://cpa:8317?", "http://cpa:8317?url=https://example.org", "http://127.0.0.1:8080", "https://cpa:8317"} {
		if ValidateBaseURL(raw) == nil {
			t.Fatalf("non-CPA base accepted: %s", raw)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, BaseURL+"/v1/responses", nil)
	if err := ValidateRequest(req); err != nil {
		t.Fatal(err)
	}
	req.Host = "api.openai.com"
	if ValidateRequest(req) == nil {
		t.Fatal("Host override bypassed CPA boundary")
	}
	if NoRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("redirects must not be followed")
	}
}
