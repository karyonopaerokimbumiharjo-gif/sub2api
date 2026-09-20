package service

import (
	"context"
	"os"
	"strings"
)

func IsManagedCPABaseURL(base string) bool {
	normalize := func(v string) string { return strings.TrimSuffix(strings.TrimRight(strings.TrimSpace(v), "/"), "/v1") }
	configured := normalize(os.Getenv(openAIQuotaBridgeManagementURLKey))
	return configured != "" && normalize(base) == configured
}

// The audit scanner shares the business bridge's concurrency budget. It must
// not select an unrelated OAuth credential or skip a disabled bridge.
func (s *GatewayService) FindCPABridgeForAudit(ctx context.Context, base string) (*Account, error) {
	if !IsManagedCPABaseURL(base) || s == nil || s.accountRepo == nil {
		return nil, ErrNoAvailableAccounts
	}
	accounts, err := s.accountRepo.ListByPlatform(ctx, PlatformOpenAI)
	if err != nil {
		return nil, err
	}
	var selected *Account
	for i := range accounts {
		a := &accounts[i]
		if a.IsOpenAICompatibleQuotaBridge() && IsManagedCPABaseURL(a.GetCredential("base_url")) && a.IsSchedulable() {
			if selected != nil {
				return nil, ErrNoAvailableAccounts
			}
			selected = a
		}
	}
	if selected == nil {
		return nil, ErrNoAvailableAccounts
	}
	return selected, nil
}
