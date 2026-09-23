package securityaudit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/gin-gonic/gin"
)

type ResearchApproval struct {
	UserID       int64     `json:"user_id"`
	APIKeyID     int64     `json:"api_key_id"`
	Organization string    `json:"organization"`
	Purpose      string    `json:"purpose"`
	Verification string    `json:"verification_reference"`
	Projects     []string  `json:"projects"`
	Resources    []string  `json:"resources"`
	Tools        []string  `json:"tools"`
	ExpiresAt    time.Time `json:"expires_at"`
}
type ResearchProfile struct {
	ResearchApproval
	ID           int64      `json:"id"`
	ApprovedBy   int64      `json:"approved_by"`
	ApprovedAt   time.Time  `json:"approved_at"`
	RevokedAt    *time.Time `json:"revoked_at"`
	RevokedBy    *int64     `json:"revoked_by"`
	RevokeReason string     `json:"revoke_reason"`
}

func validateResearchApproval(v ResearchApproval, now time.Time) error {
	if v.UserID <= 0 || v.APIKeyID <= 0 || !v.ExpiresAt.After(now) || v.ExpiresAt.After(now.Add(90*24*time.Hour)) {
		return infraerrors.BadRequest("research_profile_invalid", "用户、Key 或有效期无效（最多 90 天）")
	}
	for _, v := range []string{v.Organization, v.Purpose, v.Verification} {
		if strings.TrimSpace(v) == "" || len(v) > 2048 {
			return infraerrors.BadRequest("research_profile_invalid", "必须填写组织、用途和核验记录（每项最多 2048 字节）")
		}
	}
	for _, list := range [][]string{v.Projects, v.Resources, v.Tools} {
		if len(list) == 0 || len(list) > 32 {
			return infraerrors.BadRequest("research_profile_invalid", "项目、资源和工具范围必须逐项明确填写")
		}
		for _, v := range list {
			if strings.TrimSpace(v) == "" || strings.Contains(v, "*") || len(v) > 512 {
				return infraerrors.BadRequest("research_profile_invalid", "范围不得留空、使用通配符或超过 512 字节")
			}
		}
	}
	return nil
}

const researchColumns = `id,user_id,api_key_id,organization,purpose,verification_reference,projects,resources,tools,approved_by,approved_at,expires_at,revoked_at,revoked_by,COALESCE(revoke_reason,'')`

func scanResearch(row interface{ Scan(...any) error }) (ResearchProfile, error) {
	var p ResearchProfile
	var projects, resources, tools []byte
	err := row.Scan(&p.ID, &p.UserID, &p.APIKeyID, &p.Organization, &p.Purpose, &p.Verification, &projects, &resources, &tools, &p.ApprovedBy, &p.ApprovedAt, &p.ExpiresAt, &p.RevokedAt, &p.RevokedBy, &p.RevokeReason)
	if err == nil {
		for _, v := range []struct {
			raw []byte
			dst *[]string
		}{{projects, &p.Projects}, {resources, &p.Resources}, {tools, &p.Tools}} {
			if e := json.Unmarshal(v.raw, v.dst); e != nil {
				return p, e
			}
		}
	}
	return p, err
}
func (s *PromptService) ListResearchProfiles(ctx context.Context) ([]ResearchProfile, error) {
	rows, err := s.repo.db.QueryContext(ctx, `SELECT `+researchColumns+` FROM safety_research_profiles ORDER BY id DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ResearchProfile{}
	for rows.Next() {
		p, err := scanResearch(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func (s *PromptService) ApproveResearchProfile(ctx context.Context, v ResearchApproval, admin int64) (ResearchProfile, error) {
	if err := validateResearchApproval(v, time.Now()); err != nil {
		return ResearchProfile{}, err
	}
	projects, _ := json.Marshal(v.Projects)
	resources, _ := json.Marshal(v.Resources)
	tools, _ := json.Marshal(v.Tools)
	p, err := scanResearch(s.repo.db.QueryRowContext(ctx, `INSERT INTO safety_research_profiles(user_id,api_key_id,organization,purpose,verification_reference,projects,resources,tools,approved_by,expires_at)
 SELECT $1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8::jsonb,$9,$10 WHERE EXISTS(SELECT 1 FROM api_keys WHERE id=$2 AND user_id=$1 AND deleted_at IS NULL AND status='active') AND EXISTS(SELECT 1 FROM users WHERE id=$9 AND role='admin' AND deleted_at IS NULL)
 RETURNING `+researchColumns, v.UserID, v.APIKeyID, v.Organization, v.Purpose, v.Verification, projects, resources, tools, admin, v.ExpiresAt))
	if err == sql.ErrNoRows {
		err = infraerrors.BadRequest("research_profile_binding_invalid", "用户和启用的 Key 不匹配，或审批者无管理员权限")
	}
	return p, err
}
func (s *PromptService) RevokeResearchProfile(ctx context.Context, id, admin int64, reason string) (ResearchProfile, error) {
	if strings.TrimSpace(reason) == "" || len(reason) > 2048 {
		return ResearchProfile{}, infraerrors.BadRequest("research_profile_reason_required", "必须填写撤销原因")
	}
	p, err := scanResearch(s.repo.db.QueryRowContext(ctx, `UPDATE safety_research_profiles SET revoked_at=now(),revoked_by=$2,revoke_reason=$3 WHERE id=$1 AND revoked_at IS NULL RETURNING `+researchColumns, id, admin, reason))
	if err == sql.ErrNoRows {
		err = infraerrors.NotFound("research_profile_not_active", "档案不存在或已撤销")
	}
	return p, err
}

// This server-owned annotation is evidence only. An approval never overrides a
// scanner, hard rule, tool grant or output gate. Scope changes need new approval.
func (s *PromptService) activeResearchProfile(ctx context.Context, user, key int64) int64 {
	if s.repo == nil || s.repo.db == nil {
		return 0
	}
	ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	var id int64
	if s.repo.db.QueryRowContext(ctx, `SELECT id FROM safety_research_profiles WHERE user_id=$1 AND api_key_id=$2 AND revoked_at IS NULL AND expires_at>now() ORDER BY id DESC LIMIT 1`, user, key).Scan(&id) != nil {
		return 0
	}
	return id
}

type researchAdmin interface {
	ListResearchProfiles(context.Context) ([]ResearchProfile, error)
	ApproveResearchProfile(context.Context, ResearchApproval, int64) (ResearchProfile, error)
	RevokeResearchProfile(context.Context, int64, int64, string) (ResearchProfile, error)
}

func (h *PromptAdminHandler) BioCatalog(c *gin.Context) {
	response.Success(c, gin.H{"version": BioPolicyVersion, "tiers": BioPolicyCatalog, "research_profile_bypass": false})
}
func (h *PromptAdminHandler) ResearchProfiles(c *gin.Context) {
	s, ok := h.service.(researchAdmin)
	if !ok {
		response.ErrorFrom(c, infraerrors.ServiceUnavailable("research_profiles_unavailable", "科研档案暂不可用"))
		return
	}
	switch c.Request.Method {
	case "GET":
		p, e := s.ListResearchProfiles(c.Request.Context())
		if e != nil {
			response.ErrorFrom(c, e)
			return
		}
		response.Success(c, p)
	case "POST":
		var v ResearchApproval
		if c.ShouldBindJSON(&v) != nil {
			response.ErrorFrom(c, infraerrors.BadRequest("research_profile_invalid", "档案无效"))
			return
		}
		p, e := s.ApproveResearchProfile(c.Request.Context(), v, adminID(c))
		if e != nil {
			response.ErrorFrom(c, e)
			return
		}
		setPromptAdminAudit(c, "success", "", map[string]any{"action": "research_profile_approved", "profile_id": p.ID, "user_id": v.UserID, "api_key_id": v.APIKeyID})
		response.Success(c, p)
	case "DELETE":
		id, e := strconv.ParseInt(c.Param("id"), 10, 64)
		var v struct {
			Reason string `json:"reason"`
		}
		if e != nil || id <= 0 || c.ShouldBindJSON(&v) != nil {
			response.ErrorFrom(c, infraerrors.BadRequest("research_profile_invalid", "档案 ID 或原因无效"))
			return
		}
		p, e := s.RevokeResearchProfile(c.Request.Context(), id, adminID(c), v.Reason)
		if e != nil {
			response.ErrorFrom(c, e)
			return
		}
		setPromptAdminAudit(c, "success", "", map[string]any{"action": "research_profile_revoked", "profile_id": fmt.Sprint(id)})
		response.Success(c, p)
	}
}
