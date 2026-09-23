package admin

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/handler/dto"
	"github.com/Wei-Shaw/sub2api/internal/pkg/cpapolicy"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/piruntime"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

type switchOpenAIBackendRequest struct {
	Backend       string `json:"backend" binding:"required"`
	PiOwnerUserID int64  `json:"pi_owner_user_id"`
}

const (
	cpaSavedAutoResetEnabledKey     = "cpa_saved_auto_reset_credit_enabled"
	cpaSavedAutoReset5hThresholdKey = "cpa_saved_auto_reset_credit_5h_threshold"
	cpaSavedAutoReset7dThresholdKey = "cpa_saved_auto_reset_credit_7d_threshold"
)

// SwitchExecutionBackend changes only the transport harness of one OpenAI
// business account. The OAuth material is reused and verified in place; no new
// authorization flow is started and group bindings are never changed.
// POST /api/v1/admin/openai/accounts/:id/switch-backend
func (h *OpenAIOAuthHandler) SwitchExecutionBackend(c *gin.Context) {
	accountID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || accountID <= 0 {
		response.BadRequest(c, "Invalid account ID")
		return
	}
	var req switchOpenAIBackendRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "请选择 CPA 或 Pi 执行后端")
		return
	}
	req.Backend = strings.ToLower(strings.TrimSpace(req.Backend))
	if req.Backend != "pi" && req.Backend != "cpa" {
		response.BadRequest(c, "执行后端只能是 cpa 或 pi")
		return
	}
	account, err := h.adminService.GetAccount(c.Request.Context(), accountID)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	if account == nil || account.Platform != service.PlatformOpenAI || account.ParentAccountID != nil {
		response.BadRequest(c, "只能切换 OpenAI 主账号，影子账号不能单独切换")
		return
	}
	if req.Backend == "pi" {
		updated, err := h.switchCPAAccountToPi(c, account, req.PiOwnerUserID)
		if err != nil {
			response.ErrorFrom(c, err)
			return
		}
		response.Success(c, dto.AccountFromService(updated))
		return
	}
	updated, err := h.switchPiAccountToCPA(c, account)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, dto.AccountFromService(updated))
}

func (h *OpenAIOAuthHandler) switchCPAAccountToPi(c *gin.Context, account *service.Account, requestedOwner int64) (*service.Account, error) {
	if account.UsesNativePiRuntime() {
		return account, nil
	}
	if h.cpaRuntimeService == nil {
		return nil, infraerrors.New(http.StatusServiceUnavailable, "OPENAI_CPA_SWITCH_UNAVAILABLE", "CPA 执行服务不可用")
	}
	if service.ValidateCPAAccount(account) != nil {
		return nil, infraerrors.New(http.StatusBadRequest, "OPENAI_CPA_ACCOUNT_INVALID", "当前账号不是有效的 CPA OpenAI 业务账号")
	}
	ownerID := requestedOwner
	if ownerID <= 0 {
		if subject, ok := middleware.GetAuthSubjectFromContext(c); ok {
			ownerID = subject.UserID
		}
	}
	owner, err := h.adminService.GetUser(c.Request.Context(), ownerID)
	if err != nil || owner == nil || !owner.IsActive() {
		return nil, infraerrors.New(http.StatusBadRequest, "PI_OWNER_REQUIRED", "切换到 Pi 需要一个有效的归属用户")
	}
	oauth, err := h.cpaRuntimeService.LoadCPAOAuthCredentials(c.Request.Context(), account)
	if err != nil {
		return nil, err
	}
	accountID := strings.TrimSpace(valueString(oauth["chatgpt_account_id"]))
	accessToken := strings.TrimSpace(valueString(oauth["access_token"]))
	var verified struct {
		ChatGPTAccountID string `json:"chatgpt_account_id"`
		HarnessKind      string `json:"harness_kind"`
		PiOwnerUserID    string `json:"pi_owner_user_id"`
	}
	if err := piruntime.JSON(c.Request.Context(), "/oauth/validate", map[string]any{
		"owner_id": ownerID, "account_id": accountID, "access_token": accessToken,
	}, &verified); err != nil {
		return nil, infraerrors.New(http.StatusBadRequest, "PI_AUTH_VERIFY_FAILED", "Pi 无法验证 CPA 当前授权，请先在 CPA 中恢复该授权状态")
	}
	if verified.HarnessKind != "pi" || verified.ChatGPTAccountID != accountID || verified.PiOwnerUserID != strconv.FormatInt(ownerID, 10) {
		return nil, infraerrors.New(http.StatusBadRequest, "PI_AUTH_BINDING_INVALID", "Pi 返回的授权绑定无效")
	}

	credentials := cloneCredentialMap(oauth)
	runtimeOwnerID := ownerID
	var sharedRuntime *service.Account
	if candidates, _, listErr := h.adminService.ListAccounts(c.Request.Context(), 1, 1000, service.PlatformOpenAI, service.AccountTypeOAuth, "", "", -1, "", "id", "asc"); listErr == nil {
		for i := range candidates {
			candidate := &candidates[i]
			if candidate.ID == account.ID || candidate.GetCredential("harness_kind") != service.PiNativeHarnessKind || candidate.GetCredential("chatgpt_account_id") != accountID {
				continue
			}
			sharedRuntime = candidate
			if parsed, parseErr := strconv.ParseInt(candidate.GetCredential("pi_owner_user_id"), 10, 64); parseErr == nil && parsed > 0 {
				runtimeOwnerID = parsed
			}
			break
		}
	}
	if sharedRuntime != nil && ownerID != runtimeOwnerID {
		return nil, infraerrors.New(http.StatusConflict, "PI_OWNER_CONFLICT", "该 ChatGPT 授权已经绑定到另一个 Pi 归属用户")
	}
	if sharedRuntime != nil {
		credentials["harness_kind"] = service.PiSharedHarnessKind
		credentials[service.PiRuntimeAccountIDCredential] = strconv.FormatInt(sharedRuntime.ID, 10)
		credentials["pi_owner_user_id"] = strconv.FormatInt(runtimeOwnerID, 10)
		// The alias deliberately carries no rotating OAuth secret. Requests and
		// refreshes resolve the existing Pi owner row under one cache/lock.
		credentials["access_token"] = nil
		credentials["refresh_token"] = nil
		credentials["id_token"] = nil
	} else {
		credentials["harness_kind"] = service.PiNativeHarnessKind
		credentials["pi_owner_user_id"] = strconv.FormatInt(ownerID, 10)
	}
	// Keep the CPA route internally so switching back can restore the exact
	// bridge without another upload or authorization. These keys are redacted.
	credentials["cpa_bridge_api_key"] = account.GetOpenAIApiKey()
	credentials["cpa_bridge_base_url"] = account.GetCredential("base_url")
	credentials["api_key"] = nil
	delete(credentials, "base_url")
	extra := cloneAnyMap(account.Extra)
	restoreAutoResetExtra(extra)
	zeroProxy := int64(0)
	updated, err := h.adminService.UpdateAccount(c.Request.Context(), account.ID, &service.UpdateAccountInput{
		Type: service.AccountTypeOAuth, Credentials: credentials, Extra: extra, ProxyID: &zeroProxy,
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

func (h *OpenAIOAuthHandler) switchPiAccountToCPA(c *gin.Context, account *service.Account) (*service.Account, error) {
	if !account.UsesNativePiRuntime() {
		if account.Type == service.AccountTypeAPIKey && service.ValidateCPAAccount(account) == nil {
			return account, nil
		}
		return nil, infraerrors.New(http.StatusBadRequest, "OPENAI_CPA_SWITCH_UNSUPPORTED", "当前账号没有可切换的 OpenAI OAuth 授权")
	}
	if h.cpaRuntimeService == nil {
		return nil, infraerrors.New(http.StatusServiceUnavailable, "OPENAI_CPA_SWITCH_UNAVAILABLE", "CPA 执行服务不可用")
	}
	runtimeAccount := account
	if account.GetCredential("harness_kind") == service.PiSharedHarnessKind {
		runtimeID, parseErr := strconv.ParseInt(account.GetCredential(service.PiRuntimeAccountIDCredential), 10, 64)
		if parseErr != nil || runtimeID <= 0 {
			return nil, infraerrors.New(http.StatusConflict, "PI_RUNTIME_OWNER_UNAVAILABLE", "当前 Pi 共享账号的运行时授权已不可用")
		}
		var resolveErr error
		runtimeAccount, resolveErr = h.adminService.GetAccount(c.Request.Context(), runtimeID)
		if resolveErr != nil || runtimeAccount == nil || runtimeAccount.GetCredential("harness_kind") != service.PiNativeHarnessKind {
			return nil, infraerrors.New(http.StatusConflict, "PI_RUNTIME_OWNER_UNAVAILABLE", "当前 Pi 共享账号的运行时授权已不可用")
		}
	}
	credentials := cloneCredentialMap(runtimeAccount.Credentials)
	// The business row owns the CPA bridge metadata, including the exact auth
	// file to reuse. Keep it when the runtime credentials come from a shared Pi
	// owner row.
	for _, key := range []string{"cpa_bridge_api_key", "cpa_bridge_base_url"} {
		if value, ok := account.Credentials[key]; ok {
			credentials[key] = value
		}
	}
	if authName := strings.TrimSpace(account.GetExtraString(service.OpenAIQuotaBridgeAuthNameExtraKey)); authName != "" {
		// Consumed only by the server-side importer to make a switch
		// round-trip idempotent; it is never stored as a token.
		credentials["_sub2api_cpa_reuse_auth_name"] = authName
	}
	// Import/verify the same OAuth identity in CPA before changing the durable
	// account type. A failed import leaves the working Pi account untouched.
	imported, err := h.cpaRuntimeService.ImportOAuthCredentialsToCPA(c.Request.Context(), credentials)
	if err != nil {
		return nil, err
	}
	items, err := h.cpaRuntimeService.ListCPACredentials(c.Request.Context())
	if err != nil {
		return nil, err
	}
	var binding *service.CPACredentialSettings
	for i := range items {
		if items[i].Name == imported.AuthName {
			binding = &items[i]
			break
		}
	}
	if binding == nil || binding.AuthID == "" || binding.Identity == "" {
		return nil, infraerrors.New(http.StatusBadGateway, "OPENAI_CPA_SWITCH_VERIFY_FAILED", "CPA 未返回可用的授权绑定")
	}
	apiKey := strings.TrimSpace(valueString(credentials["cpa_bridge_api_key"]))
	baseURL := strings.TrimSpace(valueString(credentials["cpa_bridge_base_url"]))
	if apiKey == "" {
		provision, provisionErr := h.cpaRuntimeService.PrepareCPABridgeProvisioning(c.Request.Context(), imported.AuthName)
		if provisionErr != nil {
			return nil, provisionErr
		}
		apiKey = provision.APIKey
	}
	if baseURL == "" {
		baseURL = cpapolicy.BaseURL
	}
	extra := cloneAnyMap(account.Extra)
	extra["cpa_auth_id"] = binding.AuthID
	extra["cpa_identity"] = binding.Identity
	extra[service.OpenAIQuotaBridgeAuthNameExtraKey] = imported.AuthName
	extra[service.OpenAIQuotaBridgeAuthEmailExtraKey] = imported.Email
	extra[service.OpenAIQuotaViaCompatibleUpstreamExtraKey] = true
	// Credit-reset controls are valid only on OAuth parent accounts. They are
	// intentionally removed while the account runs through CPA; the operator
	// can configure them again when switching back to Pi.
	for _, key := range []string{
		service.OpenAIAutoResetCreditEnabledExtraKey,
		service.OpenAIAutoResetCredit5hThresholdExtraKey,
		service.OpenAIAutoResetCredit7dThresholdExtraKey,
	} {
		if value, exists := extra[key]; exists {
			extra[autoResetSavedKey(key)] = value
		}
		delete(extra, key)
	}
	newCredentials := map[string]any{"api_key": apiKey, "base_url": baseURL}
	for _, key := range []string{"access_token", "refresh_token", "id_token", "cpa_bridge_api_key", "cpa_bridge_base_url"} {
		newCredentials[key] = nil
	}
	updated, err := h.adminService.UpdateAccount(c.Request.Context(), account.ID, &service.UpdateAccountInput{
		Type: service.AccountTypeAPIKey, Credentials: newCredentials, Extra: extra,
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}


func autoResetSavedKey(key string) string {
	switch key {
	case service.OpenAIAutoResetCreditEnabledExtraKey:
		return cpaSavedAutoResetEnabledKey
	case service.OpenAIAutoResetCredit5hThresholdExtraKey:
		return cpaSavedAutoReset5hThresholdKey
	case service.OpenAIAutoResetCredit7dThresholdExtraKey:
		return cpaSavedAutoReset7dThresholdKey
	default:
		return ""
	}
}

func restoreAutoResetExtra(extra map[string]any) {
	for _, key := range []string{
		service.OpenAIAutoResetCreditEnabledExtraKey,
		service.OpenAIAutoResetCredit5hThresholdExtraKey,
		service.OpenAIAutoResetCredit7dThresholdExtraKey,
	} {
		saved := autoResetSavedKey(key)
		if _, exists := extra[key]; !exists {
			if value, savedExists := extra[saved]; savedExists {
				extra[key] = value
			}
		}
		delete(extra, saved)
	}
}

func cloneCredentialMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in)+8)
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneAnyMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in)+8)
	for key, value := range in {
		out[key] = value
	}
	return out
}

func valueString(value any) string {
	switch value := value.(type) {
	case string:
		return value
	default:
		return ""
	}
}
