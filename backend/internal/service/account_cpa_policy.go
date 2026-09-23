package service

import (
	"strconv"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/cpapolicy"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/tidwall/gjson"
)

// CPA already enforces cooldowns within its credential pool for each model.
// A model_cooldown response must not park the shared bridge account, which
// also serves other models and groups. Other upstream 429s keep their policy.
func isCPAModelCooldown(account *Account, responseBody []byte) bool {
	if ValidateCPAAccount(account) != nil {
		return false
	}
	return gjson.GetBytes(responseBody, "error.code").String() == "model_cooldown" ||
		gjson.GetBytes(responseBody, "error.type").String() == "model_cooldown"
}

// ValidateCPAAccount is shared by persistence and runtime scheduling so old
// imports, shadow accounts, and stale cache entries cannot restore direct OAuth.
func ValidateCPAAccount(a *Account) error {
	if a == nil || a.Platform != PlatformOpenAI || a.Type != AccountTypeAPIKey || a.ParentAccountID != nil || (a.ProxyID != nil && *a.ProxyID != 0) {
		return cpapolicy.Required()
	}
	return cpapolicy.ValidateBaseURL(a.GetCredential("base_url"))
}

// ValidateExecutionAccount permits only the configured CPA bridge or a native
// Pi credential with an explicit owner. CPA-specific checks remain separate.
func ValidateExecutionAccount(a *Account) error {
	if a != nil && a.UsesNativePiRuntime() {
		owner, err := strconv.ParseInt(a.GetCredential("pi_owner_user_id"), 10, 64)
		if err != nil || owner <= 0 || a.ParentAccountID != nil || a.ProxyID != nil ||
			strings.TrimSpace(a.GetCredential("chatgpt_account_id")) == "" ||
			strings.TrimSpace(a.GetCredential("base_url")) != "" {
			return infraerrors.BadRequest("PI_ACCOUNT_INVALID", "Pi 账号缺少独立凭据绑定或混入 CPA 配置")
		}
		if a.GetCredential("harness_kind") == PiSharedHarnessKind {
			runtimeID, runtimeErr := strconv.ParseInt(a.GetCredential(PiRuntimeAccountIDCredential), 10, 64)
			if runtimeErr != nil || runtimeID <= 0 || runtimeID == a.ID {
				return infraerrors.BadRequest("PI_ACCOUNT_INVALID", "Pi 共享账号缺少有效的运行时授权绑定")
			}
		} else if strings.TrimSpace(a.GetCredential("access_token")) == "" || strings.TrimSpace(a.GetCredential("refresh_token")) == "" {
			return infraerrors.BadRequest("PI_ACCOUNT_INVALID", "Pi 账号缺少独立凭据绑定或混入 CPA 配置")
		}
		switch a.GetCredential("pi_transport") {
		case "", "sse", "auto", "websocket", "websocket-cached":
		default:
			return infraerrors.BadRequest("PI_TRANSPORT_INVALID", "Pi 账号传输模式无效")
		}
		return nil
	}
	return ValidateCPAAccount(a)
}
