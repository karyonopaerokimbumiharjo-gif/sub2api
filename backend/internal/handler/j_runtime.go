package handler

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/jruntime"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ip"
	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func (h *OpenAIGatewayHandler) forwardJ(c *gin.Context, key *service.APIKey, account *service.Account, body []byte, mode gpt6JRequestMode) (*service.OpenAIForwardResult, error) {
	fail := func(code int, message string) (*service.OpenAIForwardResult, error) {
		h.errorResponse(c, code, "j_execution_error", message)
		return nil, errors.New(message)
	}
	if h.jStore == nil {
		return fail(503, "J execution storage is unavailable")
	}
	enabled, err := h.jStore.Enabled(c.Request.Context(), key.UserID, key.ID)
	if err != nil {
		return fail(503, "J settings are unavailable")
	}
	if !enabled {
		return fail(403, "Enable J execution for this API key first")
	}
	session := jSession(c, body)
	taskID := strings.TrimSpace(c.GetHeader("Idempotency-Key"))
	if taskID == "" {
		taskID = uuid.NewString()
	}
	if len(taskID) > 128 {
		return fail(400, "J idempotency key exceeds 128 bytes")
	}
	publicModel := mode.PublicModel
	if publicModel == "" {
		publicModel = mode.BaseModel
	}
	b := jruntime.Binding{UserID: key.UserID, KeyID: key.ID, AccountID: account.ID, SessionID: session, TaskID: taskID, BaseModel: mode.BaseModel}
	grant := strings.TrimSpace(c.GetHeader("X-Sub2API-Tool-Grant"))
	fingerprint, _ := json.Marshal(struct {
		Body  json.RawMessage
		Grant string
	}{body, grant})
	stored, err := h.jStore.Begin(c.Request.Context(), b, fingerprint)
	if err != nil {
		return fail(409, err.Error())
	}
	c.Header("X-Sub2API-J-Task", taskID)
	if stored != nil {
		if err := writeJResponse(c, stored.Response, publicModel, gjson.GetBytes(body, "stream").Bool()); err != nil {
			return nil, err
		}
		return &service.OpenAIForwardResult{UsageRecordedInternally: true, Model: mode.BaseModel, UpstreamResponseModel: mode.BaseModel}, nil
	}
	actor, err := h.jStore.Phase(c.Request.Context(), b, body)
	if err != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), 3*time.Second)
		defer cancel()
		_ = h.jStore.Finish(cleanup, b, jruntime.Result{}, err)
		return fail(409, "J continuation does not match this key, session, account and model")
	}
	engine := jruntime.Engine{InitialActor: actor, Record: h.jStore.Record}
	if token := h.securityAuditCoordinator.JevDecisionToken(); token != "" {
		client := jruntime.JevClient{Token: token}
		engine.Choose = client.Choose
	}
	if grant != "" {
		engine.Tools = &jruntime.BridgeRunner{Store: h.jStore, GrantID: grant}
	}
	c.Request.Header.Del("X-Sub2API-Tool-Grant")
	subscription, _ := middleware2.GetSubscriptionFromContext(c)
	blocked := false
	engine.Base = func(ctx context.Context, b jruntime.Binding, request json.RawMessage) (jruntime.BaseResult, error) {
		if err := h.billingCacheService.CheckBillingEligibility(ctx, key.User, key, key.Group, subscription, service.QuotaPlatform(ctx, key)); err != nil {
			return jruntime.BaseResult{}, errors.New("j_billing_limit_reached")
		}
		childID := uuid.NewString()
		childCtx := context.WithValue(context.WithValue(ctx, ctxkey.ClientRequestID, ""), ctxkey.RequestID, childID)
		child := c.Copy()
		child.Request = c.Request.Clone(childCtx)
		child.Request.Header.Del("Idempotency-Key")
		writer := newJBufferWriter()
		child.Writer = writer
		res, forwardErr := h.gatewayService.Forward(childCtx, child, account, request)
		out := jruntime.BaseResult{RequestID: "local:" + childID, Body: append([]byte(nil), writer.body.Bytes()...)}
		if res != nil {
			out.ActualModel = res.UpstreamResponseModel
			out.InputTokens = int64(res.Usage.InputTokens)
			out.OutputTokens = int64(res.Usage.OutputTokens)
			// Each real child is billed once using its own request ID. Replays and
			// the outer virtual request never add a second usage charge.
			billingCtx, done := context.WithTimeout(context.WithoutCancel(childCtx), 10*time.Second)
			billErr := h.gatewayService.RecordUsage(billingCtx, &service.OpenAIRecordUsageInput{Result: res, APIKey: key, User: key.User, Account: account, Subscription: subscription, InboundEndpoint: GetInboundEndpoint(c), UpstreamEndpoint: res.UpstreamEndpoint, UserAgent: c.GetHeader("User-Agent"), IPAddress: ip.GetClientIP(c), SessionID: session, RequestPayloadHash: service.HashUsageRequestPayload(request), APIKeyService: h.apiKeyService, QuotaPlatform: service.QuotaPlatform(ctx, key), PricingAt: time.Now()})
			done()
			if billErr != nil {
				return out, errors.New("j_child_billing_failed")
			}
		}
		h.recordBioPolicyIfMarked(child, key, account, mode.BaseModel)
		if writer.Status() == 403 {
			blocked = true
		}
		if forwardErr != nil || writer.Status() >= 400 {
			return out, errors.New("j_child_request_failed")
		}
		return out, nil
	}
	result, runErr := engine.Run(c.Request.Context(), b, body)
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), 5*time.Second)
	defer cancel()
	if finishErr := h.jStore.Finish(cleanup, b, result, runErr); finishErr != nil {
		return fail(503, "J execution result could not be persisted; do not repeat tool side effects")
	}
	if runErr != nil {
		status := 502
		if blocked {
			status = 403
		}
		if c.Request.Context().Err() != nil {
			return nil, runErr
		}
		return fail(status, runErr.Error())
	}
	if err := writeJResponse(c, result.Response, publicModel, gjson.GetBytes(body, "stream").Bool()); err != nil {
		return nil, err
	}
	return &service.OpenAIForwardResult{UsageRecordedInternally: true, Model: mode.BaseModel, UpstreamResponseModel: mode.BaseModel, Stream: gjson.GetBytes(body, "stream").Bool()}, nil
}

func normalizeJBody(body []byte, mode gpt6JRequestMode) []byte {
	updated, err := sjson.SetBytes(body, "model", mode.BaseModel)
	if err != nil {
		return body
	}
	return updated
}

func jSession(c *gin.Context, body []byte) string {
	session := strings.TrimSpace(service.ExtractClientSessionID(c))
	if session == "" {
		session = strings.TrimSpace(gjson.GetBytes(body, "prompt_cache_key").String())
	}
	if session == "" {
		session = "responses-default"
	}
	return session
}
