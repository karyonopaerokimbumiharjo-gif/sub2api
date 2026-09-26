package service

import (
    "strings"
    infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

const BasisPointsEnabledExtraKey = "openai_basispoints_enabled"
const BasisPointsHeader = "X-Sub2API-BasisPoints"

func (a *Account) UsesBasisPoints() bool {
    if a == nil || ValidateCPAAccount(a) != nil || strings.TrimSpace(a.GetExtraString("cpa_auth_id")) == "" { return false }
    enabled, _ := a.Extra[BasisPointsEnabledExtraKey].(bool)
    return enabled
}

func validateBasisPointsExtra(a *Account, extra map[string]any) error {
    raw, exists := extra[BasisPointsEnabledExtraKey]
    if !exists { return nil }
    enabled, ok := raw.(bool)
    if !ok { return infraerrors.BadRequest("INVALID_BASISPOINTS_ENABLED", "Basis Points 开关必须是布尔值") }
    if enabled && (ValidateCPAAccount(a) != nil || strings.TrimSpace(a.GetExtraString("cpa_auth_id")) == "") {
        return infraerrors.BadRequest("BASISPOINTS_REQUIRES_CPA_AUTH", "请先使用 CPA OAuth 授权并导入绑定账号；Pi 账号不支持此插件")
    }
    return nil
}
