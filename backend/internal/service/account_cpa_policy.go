package service

import (
	"github.com/Wei-Shaw/sub2api/internal/pkg/cpapolicy"
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
