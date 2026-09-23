package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Wei-Shaw/sub2api/internal/jruntime"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

func (h *OpenAIGatewayHandler) installJSafety(c *gin.Context, key *service.APIKey, body []byte, engine *jruntime.Engine) {
	req := buildSecurityAuditRequest(c, key, middleware2.AuthSubject{UserID: key.UserID}, "openai_chat_completions", "", nil, "http")
	check := func(ctx context.Context, b jruntime.Binding, call jruntime.Call, stage string, details any) error {
		if h.securityAuditCoordinator == nil {
			return nil
		}
		evidence, err := json.Marshal(map[string]any{"stage": stage, "tool": call.Name, "details": details})
		if err != nil {
			return err
		}
		request := req.Clone()
		request.Model = b.BaseModel
		request.RequestID = fmt.Sprintf("%s:%s:%s", req.RequestID, stage, call.ID)
		// Both task context and the exact proposed action/result are untrusted evidence.
		request.Body, _ = json.Marshal(map[string]any{"messages": []map[string]string{{"role": "user", "content": "Task context: " + string(body)}, {"role": "assistant", "content": string(evidence)}}})
		decision := h.securityAuditCoordinator.Check(ctx, request)
		outcome := "allowed"
		if !decision.AllowNextStage {
			outcome = "rejected"
		}
		if err = h.jStore.Record(ctx, b, jruntime.Event{Stage: stage, Actor: "safety", CallID: call.ID, Tool: call.Name, Outcome: outcome}); err != nil {
			return err
		}
		if !decision.AllowNextStage {
			return fmt.Errorf("%w: %s", jruntime.ErrSafety, stage)
		}
		return nil
	}
	engine.GuardCall = func(ctx context.Context, b jruntime.Binding, t jruntime.Tool, call jruntime.Call) error {
		return check(ctx, b, call, "action_guard", map[string]any{"declaration": t, "arguments": call.Arguments})
	}
	engine.GuardResult = func(ctx context.Context, b jruntime.Binding, call jruntime.Call, out json.RawMessage) error {
		return check(ctx, b, call, "result_guard", out)
	}
}
