package securityaudit

import (
	"context"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

type localAuditControls interface {
	CheckLocalKeywords(context.Context, Request) (*LegacyDecision, error)
	LocalBlockResponse(context.Context) (int, string)
}

func moderationInput(req Request) service.ContentModerationCheckInput {
	return service.ContentModerationCheckInput{RequestID: req.RequestID, UserID: req.UserID, UserEmail: req.UserEmail,
		NativeAuditProfile: req.NativeAuditProfile,
		APIKeyID:           req.APIKeyID, APIKeyName: req.APIKeyName, GroupID: req.GroupID, GroupName: req.GroupName,
		Endpoint: req.Endpoint, Provider: req.Provider, Model: req.Model, Protocol: req.Protocol, Body: req.Body}
}

func (a *LegacyModerationAdapter) CheckLocalKeywords(ctx context.Context, req Request) (*LegacyDecision, error) {
	if a == nil || a.service == nil {
		return nil, nil
	}
	snapshot, err := ExtractPromptSnapshot(req)
	if err != nil {
		return nil, nil
	}
	d, err := a.service.CheckLocalKeywords(ctx, moderationInput(req), snapshot.FullPrompt)
	if d == nil {
		return nil, err
	}
	return &LegacyDecision{Allowed: d.Allowed, Blocked: d.Blocked, Flagged: d.Flagged, Message: d.Message, StatusCode: d.StatusCode, ErrorCode: ErrorCodeBlocked, Action: d.Action}, err
}

func (a *LegacyModerationAdapter) LocalBlockResponse(ctx context.Context) (int, string) {
	if a == nil || a.service == nil {
		return 0, ""
	}
	return a.service.LocalBlockResponse(ctx)
}

func (c *Coordinator) localResponse(ctx context.Context, d Decision) Decision {
	if d.Kind == DecisionBlock && c != nil {
		if controls, ok := c.legacy.(localAuditControls); ok {
			status, message := controls.LocalBlockResponse(ctx)
			if status >= 400 && status <= 599 {
				d.HTTPStatus = status
			}
			if message != "" {
				d.ClientMessage = message
			}
		}
	}
	return d
}

func (a *LegacyModerationAdapter) RecordPromptResult(ctx context.Context, snapshot PromptSnapshot, result *NormalizedResult) {
	if a == nil || a.service == nil || result == nil || result.Decision == EventReviewRequired {
		return
	}
	source := "legacy"
	if snapshot.Stage == "native_hard_rules" || snapshot.Stage == "native_output" {
		source = "native"
	}
	a.service.RecordLocalAuditHit(ctx, moderationInput(requestFromSnapshot(snapshot)), snapshot.FullPrompt,
		snapshot.AuditedPrompt, source, result.ScannerBackend, result.ScannerScores, result.Action == ActionBlock)
}
