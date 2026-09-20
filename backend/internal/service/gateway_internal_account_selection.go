package service

import (
	"context"
	"fmt"
)

// SelectInternalAccountForModelWithExclusions selects from the trusted
// platform-wide account pool for internal service calls. It intentionally
// bypasses API-key group membership, while retaining model, health, quota,
// window-cost, and RPM checks.
func (s *GatewayService) SelectInternalAccountForModelWithExclusions(
	ctx context.Context,
	platform string,
	requestedModel string,
	excludedIDs map[int64]struct{},
) (*Account, error) {
	if s == nil || s.accountRepo == nil || platform == "" {
		return nil, ErrNoAvailableAccounts
	}
	accounts, err := s.accountRepo.ListSchedulableByPlatform(ctx, platform)
	if err != nil {
		return nil, fmt.Errorf("query internal account pool: %w", err)
	}
	ctx = s.withWindowCostPrefetch(ctx, accounts)
	ctx = s.withRPMPrefetch(ctx, accounts)

	var selected *Account
	for i := range accounts {
		account := &accounts[i]
		if _, excluded := excludedIDs[account.ID]; excluded {
			continue
		}
		if account.Platform != platform || (platform == PlatformOpenAI && account.Type != AccountTypeOAuth) || !s.isAccountSchedulableForSelection(account) {
			continue
		}
		if requestedModel != "" && !s.isModelSupportedByAccountWithContext(ctx, account, requestedModel) {
			continue
		}
		if !s.isAccountSchedulableForModelSelection(ctx, account, requestedModel) ||
			!s.isAccountSchedulableForQuota(account) ||
			!s.isAccountSchedulableForWindowCost(ctx, account, false) ||
			!s.isAccountSchedulableForRPM(ctx, account, false) {
			continue
		}
		if selected == nil || account.Priority < selected.Priority ||
			(account.Priority == selected.Priority && internalAccountLessRecentlyUsed(account, selected)) {
			selected = account
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("%w supporting model: %s", ErrNoAvailableAccounts, requestedModel)
	}
	return s.hydrateSelectedAccount(ctx, selected)
}

// SelectInternalOAuthAccountByIDForModel resolves one explicitly configured
// OAuth account for an internal service call. It never substitutes another
// account: an unavailable fixed account makes this audit endpoint fail so the
// caller can continue to the next configured audit node.
func (s *GatewayService) SelectInternalOAuthAccountByIDForModel(
	ctx context.Context,
	platform string,
	accountID int64,
	requestedModel string,
) (*Account, error) {
	if s == nil || s.accountRepo == nil || platform == "" || accountID <= 0 {
		return nil, ErrNoAvailableAccounts
	}
	account, err := s.accountRepo.GetByID(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("query fixed internal OAuth account: %w", err)
	}
	if account == nil || account.Platform != platform || account.Type != AccountTypeOAuth {
		return nil, fmt.Errorf("%w: fixed account %d is not a %s OAuth account", ErrNoAvailableAccounts, accountID, platform)
	}
	accounts := []Account{*account}
	ctx = s.withWindowCostPrefetch(ctx, accounts)
	ctx = s.withRPMPrefetch(ctx, accounts)
	if !s.isAccountSchedulableForSelection(account) ||
		(requestedModel != "" && !s.isModelSupportedByAccountWithContext(ctx, account, requestedModel)) ||
		!s.isAccountSchedulableForModelSelection(ctx, account, requestedModel) ||
		!s.isAccountSchedulableForQuota(account) ||
		!s.isAccountSchedulableForWindowCost(ctx, account, false) ||
		!s.isAccountSchedulableForRPM(ctx, account, false) {
		return nil, fmt.Errorf("%w: fixed account %d cannot serve model %s", ErrNoAvailableAccounts, accountID, requestedModel)
	}
	return s.hydrateSelectedAccount(ctx, account)
}

func internalAccountLessRecentlyUsed(candidate, selected *Account) bool {
	if candidate.LastUsedAt == nil {
		return selected.LastUsedAt != nil
	}
	if selected.LastUsedAt == nil {
		return false
	}
	return candidate.LastUsedAt.Before(*selected.LastUsedAt)
}
