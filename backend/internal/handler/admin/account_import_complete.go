package admin

import (
	"context"
	"net/http"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

// Group IDs opt the account-import UI into one server-side completion flow.
// Legacy credential-only clients keep their existing API contract.
func (h *OpenAIOAuthHandler) validateImportGroups(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	if h.adminService == nil || h.cpaRuntimeService == nil || len(ids) > 100 {
		return infraerrors.BadRequest("ACCOUNT_IMPORT_UNAVAILABLE", "账号导入暂不可用")
	}
	for _, id := range ids {
		group, err := h.adminService.GetGroup(ctx, id)
		if err != nil || group == nil || group.Platform != service.PlatformOpenAI || group.Status != service.StatusActive {
			return infraerrors.BadRequest("ACCOUNT_IMPORT_GROUP_INVALID", "请选择已启用的 OpenAI 分组")
		}
	}
	return nil
}

func (h *OpenAIOAuthHandler) completeAccountImport(ctx context.Context, name string, groupIDs []int64, runtime *service.CPACredentialUpdate) ([]int64, error) {
	if len(groupIDs) == 0 {
		return nil, nil
	}
	result, err := h.cpaRuntimeService.SyncCPAAccounts(ctx, []string{name})
	if err != nil {
		return nil, err
	}
	if len(result.AccountIDs) != 1 || result.AccountIDs[0] <= 0 {
		return nil, infraerrors.New(http.StatusBadGateway, "ACCOUNT_IMPORT_INCOMPLETE", "未能确认导入的账号，请重试")
	}
	id := result.AccountIDs[0]
	account, err := h.adminService.GetAccount(ctx, id)
	if err != nil {
		return nil, err
	}
	if account == nil || account.Platform != service.PlatformOpenAI || account.GetExtraString("cpa_auth_id") == "" {
		return nil, infraerrors.New(http.StatusConflict, "ACCOUNT_IMPORT_BINDING_INVALID", "导入账号的授权绑定不一致")
	}
	groups := append([]int64(nil), account.GroupIDs...)
	seen := make(map[int64]bool, len(groups)+len(groupIDs))
	for _, group := range groups {
		seen[group] = true
	}
	for _, group := range groupIDs {
		if !seen[group] {
			groups = append(groups, group)
			seen[group] = true
		}
	}
	enabled := runtime == nil || !runtime.Disabled
	status := service.StatusActive
	if !enabled {
		status = "inactive"
	}
	if _, err := h.adminService.UpdateAccount(ctx, id, &service.UpdateAccountInput{GroupIDs: &groups, Status: status}); err != nil {
		return nil, err
	}
	account, err = h.adminService.SetAccountSchedulable(ctx, id, enabled)
	if err != nil {
		return nil, err
	}
	if account == nil || account.ID != id || account.Schedulable != enabled || account.Status != status {
		return nil, infraerrors.New(http.StatusBadGateway, "ACCOUNT_IMPORT_INCOMPLETE", "账号设置尚未完成，请重试导入")
	}
	actualGroups := make(map[int64]bool, len(account.GroupIDs))
	for _, group := range account.GroupIDs {
		actualGroups[group] = true
	}
	for _, group := range groups {
		if !actualGroups[group] {
			return nil, infraerrors.New(http.StatusBadGateway, "ACCOUNT_IMPORT_INCOMPLETE", "账号分组尚未保存，请重试导入")
		}
	}
	return result.AccountIDs, nil
}
