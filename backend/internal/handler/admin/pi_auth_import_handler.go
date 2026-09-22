package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/handler/dto"
	"github.com/Wei-Shaw/sub2api/internal/pkg/openai"
	"github.com/Wei-Shaw/sub2api/internal/pkg/piruntime"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// piAuthImportLimit bounds both the JSON envelope and the untrusted auth file.
const piAuthImportLimit = 4 << 20

type piAuthImportRequest struct {
	Content     string  `json:"content"`
	OwnerUserID int64   `json:"pi_owner_user_id"`
	GroupIDs    []int64 `json:"group_ids"`
}

type piCodexAuth struct {
	AuthMode string `json:"auth_mode"`
	Tokens   struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		AccountID    string `json:"account_id"`
	} `json:"tokens"`
}

// parsePiCodexAuth checks the local auth.json shape and the unverified JWT
// account identity. The Pi runtime's read-only upstream check proves current access.
func parsePiCodexAuth(content string) (*piCodexAuth, int64, error) {
	var auth piCodexAuth
	if len(content) == 0 || len(content) > piAuthImportLimit || json.Unmarshal([]byte(content), &auth) != nil || auth.AuthMode != "chatgpt" {
		return nil, 0, errors.New("expected one Codex ChatGPT auth.json file")
	}
	accountID := strings.TrimSpace(auth.Tokens.AccountID)
	if accountID == "" || strings.TrimSpace(auth.Tokens.AccessToken) == "" || strings.TrimSpace(auth.Tokens.RefreshToken) == "" {
		return nil, 0, errors.New("ChatGPT access token, refresh token and account ID are required")
	}
	accessClaims, err := openai.DecodeIDToken(auth.Tokens.AccessToken)
	if err != nil || accessClaims.OpenAIAuth == nil || accessClaims.OpenAIAuth.ChatGPTAccountID != accountID {
		return nil, 0, errors.New("access token account ID does not match auth.json")
	}
	if accessClaims.Exp <= time.Now().Add(time.Minute).Unix() {
		return nil, 0, errors.New("Codex access token has expired; refresh the local auth.json before importing")
	}
	if auth.Tokens.IDToken != "" {
		idClaims, err := openai.DecodeIDToken(auth.Tokens.IDToken)
		if err != nil || idClaims.OpenAIAuth == nil || idClaims.OpenAIAuth.ChatGPTAccountID != accountID {
			return nil, 0, errors.New("ID token account ID does not match auth.json")
		}
	}
	return &auth, accessClaims.Exp, nil
}

// ImportPiAuth imports a local Codex auth.json directly into a dedicated Pi
// business account. It never stores the file in CPA or returns token values.
func (h *OpenAIOAuthHandler) ImportPiAuth(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, piAuthImportLimit)
	var req piAuthImportRequest
	if c.ShouldBindJSON(&req) != nil || req.OwnerUserID <= 0 || len(req.GroupIDs) != 1 {
		response.BadRequest(c, "Provide one auth.json file, an active Pi owner and one dedicated OpenAI group")
		return
	}
	auth, expiresAt, err := parsePiCodexAuth(req.Content)
	if err != nil {
		response.BadRequest(c, err.Error())
		return
	}
	ctx := c.Request.Context()
	owner, err := h.adminService.GetUser(ctx, req.OwnerUserID)
	if err != nil || owner == nil || !owner.IsActive() {
		response.BadRequest(c, "Pi credential owner must be an active user")
		return
	}
	groupID := req.GroupIDs[0]
	if groupID <= 0 {
		response.BadRequest(c, "Choose a dedicated OpenAI group for Pi")
		return
	}
	group, err := h.adminService.GetGroup(ctx, groupID)
	if err != nil || group == nil || group.Platform != service.PlatformOpenAI || !group.IsActive() || !group.IsExclusive || !owner.CanBindGroup(groupID, true) {
		response.BadRequest(c, "Pi requires an active exclusive OpenAI group assigned to its owner")
		return
	}
	// Check all accounts, including disabled ones. A dormant CPA account still
	// makes this group mixed, and a second Pi import must not duplicate identity.
	accounts, err := h.adminService.ListAccountsForSchedulerScoreFilter(ctx, service.PlatformOpenAI, "", "", "", 0, "")
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	for i := range accounts {
		account := &accounts[i]
		if account.UsesNativePiRuntime() && account.GetCredential("chatgpt_account_id") == auth.Tokens.AccountID {
			response.Error(c, http.StatusConflict, "This ChatGPT identity already has a Pi account; reauthorize that account instead")
			return
		}
		for _, binding := range account.AccountGroups {
			if binding.GroupID == groupID && !account.UsesNativePiRuntime() {
				response.BadRequest(c, "CPA and Pi accounts must use separate groups")
				return
			}
		}
	}
	// Use the same group membership check as OAuth import, in case this service
	// returns account group bindings separately from the global account listing.
	members, err := h.adminService.ListAccountsForSchedulerScoreFilter(ctx, service.PlatformOpenAI, "", "", "", groupID, "")
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	for i := range members {
		if !members[i].UsesNativePiRuntime() {
			response.BadRequest(c, "CPA and Pi accounts must use separate groups")
			return
		}
	}
	verifyCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var verified struct {
		HarnessKind      string `json:"harness_kind"`
		PiOwnerUserID    string `json:"pi_owner_user_id"`
		ChatGPTAccountID string `json:"chatgpt_account_id"`
	}
	if err := piruntime.JSON(verifyCtx, "/oauth/validate", map[string]any{
		"owner_id": req.OwnerUserID, "account_id": auth.Tokens.AccountID, "access_token": auth.Tokens.AccessToken,
	}, &verified); err != nil {
		response.BadRequest(c, "Pi runtime could not verify this ChatGPT authorization")
		return
	}
	ownerID := strconv.FormatInt(req.OwnerUserID, 10)
	if verified.HarnessKind != "pi" || verified.PiOwnerUserID != ownerID || verified.ChatGPTAccountID != auth.Tokens.AccountID {
		response.BadRequest(c, "Pi runtime returned an invalid account binding")
		return
	}
	token := service.OpenAITokenInfo{
		HarnessKind: "pi", PiOwnerUserID: ownerID, ChatGPTAccountID: auth.Tokens.AccountID,
		AccessToken: auth.Tokens.AccessToken, RefreshToken: auth.Tokens.RefreshToken,
		ExpiresAt: expiresAt,
	}
	shortID := auth.Tokens.AccountID
	if len(shortID) > 8 {
		shortID = shortID[len(shortID)-8:]
	}
	name := "Pi OpenAI · " + shortID
	account, err := h.adminService.CreateAccount(ctx, &service.CreateAccountInput{
		Name: name, Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth,
		Credentials: h.openaiOAuthService.BuildAccountCredentials(&token), Concurrency: 1,
		GroupIDs: req.GroupIDs, SkipDefaultGroupBind: true, InitiallyUnschedulable: true, InitiallyDisabled: true,
	})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, dto.AccountFromService(account))
}
