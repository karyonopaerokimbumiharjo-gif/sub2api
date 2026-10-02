package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	PiNativeHarnessKind          = "pi"
	PiSharedHarnessKind          = "pi_shared"
	PiRuntimeAccountIDCredential = "pi_runtime_account_id"
)

// ResolveNativePiRuntimeAccount returns the account that owns the OAuth
// refresh/session state for a Pi request. A pi_shared account is a business
// alias: it keeps its own groups, name and billing settings, while reusing one
// already-authorized Pi credential. This prevents two rows from racing the
// same rotating refresh token.
type PiRuntimeAccountResolver interface {
	GetByID(context.Context, int64) (*Account, error)
}

func ResolveNativePiRuntimeAccount(ctx context.Context, repo PiRuntimeAccountResolver, account *Account) (*Account, error) {
	if account == nil {
		return nil, fmt.Errorf("Pi account is nil")
	}
	if account.GetCredential("harness_kind") != PiSharedHarnessKind {
		return account, nil
	}
	if repo == nil {
		return nil, fmt.Errorf("Pi shared account repository is unavailable")
	}
	raw := strings.TrimSpace(account.GetCredential(PiRuntimeAccountIDCredential))
	runtimeID, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || runtimeID <= 0 || runtimeID == account.ID {
		return nil, fmt.Errorf("Pi shared account runtime binding is invalid")
	}
	runtimeAccount, err := repo.GetByID(ctx, runtimeID)
	if err != nil || runtimeAccount == nil || !runtimeAccount.UsesNativePiRuntime() || runtimeAccount.GetCredential("harness_kind") != PiNativeHarnessKind {
		return nil, fmt.Errorf("Pi shared account runtime owner is unavailable")
	}
	if identity := strings.TrimSpace(account.GetCredential("chatgpt_account_id")); identity != "" && identity != runtimeAccount.GetCredential("chatgpt_account_id") {
		return nil, fmt.Errorf("Pi shared account identity does not match runtime owner")
	}
	if (OpenAIOAuthPrincipal(account.Credentials) != "" || OpenAIOAuthPrincipal(runtimeAccount.Credentials) != "") && !SameOpenAIOAuthIdentity(account.Credentials, runtimeAccount.Credentials) {
		return nil, fmt.Errorf("Pi shared account login does not match runtime owner")
	}
	if owner := strings.TrimSpace(account.GetCredential("pi_owner_user_id")); owner != "" && owner != runtimeAccount.GetCredential("pi_owner_user_id") {
		return nil, fmt.Errorf("Pi shared account owner does not match runtime owner")
	}
	return runtimeAccount, nil
}

var errNativePiDispatchUnavailable = errors.New("Pi credential owner is unavailable for dispatch")

// resolveNativePiDispatchAccount adds dispatch health checks to shared aliases.
// Management and reauthorization still use ResolveNativePiRuntimeAccount so an
// unavailable credential remains readable and repairable. Expiry is left to the
// token provider, which can refresh an otherwise healthy credential.
func (s *OpenAIGatewayService) resolveNativePiDispatchAccount(ctx context.Context, account *Account) (*Account, error) {
	if account == nil || s == nil {
		return nil, errNativePiDispatchUnavailable
	}
	owner, err := ResolveNativePiRuntimeAccount(ctx, s.accountRepo, account)
	if err != nil {
		return nil, errNativePiDispatchUnavailable
	}
	if account.GetCredential("harness_kind") != PiSharedHarnessKind {
		return owner, nil
	}
	if ValidateExecutionAccount(account) != nil || ValidateExecutionAccount(owner) != nil ||
		owner.Status != StatusActive || !owner.Schedulable ||
		(owner.TempUnschedulableUntil != nil && time.Now().Before(*owner.TempUnschedulableUntil)) ||
		s.isOpenAIAccountRuntimeBlocked(owner) {
		return nil, errNativePiDispatchUnavailable
	}
	return owner, nil
}
