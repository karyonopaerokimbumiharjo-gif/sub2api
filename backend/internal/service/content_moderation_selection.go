package service

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Wei-Shaw/sub2api/internal/pkg/auditpolicy"
	"strings"
)

func applyModerationPolicySelection(cfg *ContentModerationConfig, selected, legacy []string, operatorEnabled bool) {
	cfg.PolicyScanners = append([]string(nil), legacy...)
	cfg.PolicyCategories = auditpolicy.CloneCategories(selected)
	cfg.OperatorPolicyEnabled = operatorEnabled
	for _, id := range auditpolicy.ResolveNativeCategories(selected, legacy, operatorEnabled) {
		if _, ok := auditpolicy.IntentRubrics[id]; ok {
			cfg.Thresholds["intent_"+id] = 0.90
		}
		if id == "operator_ctf" || id == "operator_repository" {
			cfg.Thresholds[id] = 0.90
		}
	}
}

func (s *ContentModerationService) applySavedNativePolicyForTest(ctx context.Context, cfg *ContentModerationConfig) error {
	if s.settingRepo == nil {
		return nil
	}
	raw, err := s.settingRepo.GetValue(ctx, "prompt_audit_config")
	if errors.Is(err, ErrSettingNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var policy struct {
		Categories []string `json:"native_risk_categories"`
		Scanners   []string `json:"scanners"`
		Operator   *bool    `json:"operator_policy_enabled"`
	}
	if err = json.Unmarshal([]byte(raw), &policy); err != nil {
		return err
	}
	if !auditpolicy.ValidNativeCategories(policy.Categories) {
		return errors.New("invalid saved audit category")
	}
	enabled := policy.Operator == nil || *policy.Operator
	applyModerationPolicySelection(cfg, policy.Categories, policy.Scanners, enabled)
	return nil
}
