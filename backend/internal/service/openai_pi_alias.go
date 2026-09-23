package service

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

const (
	PiNativeHarnessKind = "pi"
	PiSharedHarnessKind = "pi_shared"
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
	if owner := strings.TrimSpace(account.GetCredential("pi_owner_user_id")); owner != "" && owner != runtimeAccount.GetCredential("pi_owner_user_id") {
		return nil, fmt.Errorf("Pi shared account owner does not match runtime owner")
	}
	return runtimeAccount, nil
}
