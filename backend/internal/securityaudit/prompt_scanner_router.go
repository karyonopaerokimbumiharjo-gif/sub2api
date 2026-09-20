package securityaudit

import (
	"context"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/cpapolicy"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

// RoutingPromptScanner uses the internal CPA endpoint for normal audit nodes
// and the explicitly scoped OpenCode DeepSeek fallback when configured.
type cpaBridgeSelector interface {
	FindCPABridgeForAudit(context.Context, string) (*service.Account, error)
}
type accountSlotAcquirer interface {
	AcquireAccountSlot(context.Context, int64, int) (*service.AcquireResult, error)
}
type RoutingPromptScanner struct {
	accounts    cpaBridgeSelector
	concurrency accountSlotAcquirer
	openAI      *OpenAICompatibleScanner
	invocations promptInvocationRecorder
	billing     auditCostCalculator
}

func NewRoutingPromptScanner(
	openAI *OpenAICompatibleScanner,
	accounts *service.GatewayService,
	concurrency *service.ConcurrencyService,
	_ *service.AntigravityGatewayService,
	_ *service.OpenAIGatewayService,
	invocations *PostgreSQLRepository,
	billing *service.BillingService,
) *RoutingPromptScanner {
	var calculator auditCostCalculator
	if billing != nil {
		calculator = billing
	}
	return &RoutingPromptScanner{openAI: openAI, accounts: accounts, concurrency: concurrency, invocations: invocations, billing: calculator}
}

func (s *RoutingPromptScanner) Scan(ctx context.Context, endpoint ActiveEndpoint, chunk string, enabledScanners []string) (*NormalizedResult, error) {
	if endpoint.Protocol == JevProtocol {
		if s == nil || s.openAI == nil || endpoint.AccountID != 0 {
			return nil, &GuardError{Code: ErrorCodeUnavailable}
		}
		return s.openAI.scanJev(ctx, endpoint, chunk, enabledScanners)
	}
	if (endpoint.Protocol != "" && endpoint.Protocol != EndpointProtocolOpenAICompatible) || endpoint.AccountID != 0 {
		return nil, &GuardError{Code: ErrorCodeUnavailable, Cause: cpapolicy.Required()}
	}
	if _, err := NormalizeBaseURL(endpoint.BaseURL); err != nil {
		return nil, &GuardError{Code: ErrorCodeUnavailable, Cause: cpapolicy.Required()}
	}
	if s == nil || s.openAI == nil {
		return nil, &GuardError{Code: ErrorCodeUnavailable}
	}
	started := time.Now()
	timeout := time.Duration(endpoint.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = DefaultTimeoutMS * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var release func()
	if !isOpenCodeAuditBaseURL(endpoint.BaseURL) {
		var err error
		release, err = s.acquireCPABridgeSlot(ctx, endpoint)
		if err != nil {
			s.recordCompatibleInvocation(ctx, endpoint, nil, err, time.Since(started))
			return nil, err
		}
	}
	if release != nil {
		defer release()
	}
	result, usage, err := s.openAI.scanWithUsage(ctx, endpoint, chunk, enabledScanners)
	s.recordCompatibleInvocation(ctx, endpoint, usage, err, time.Since(started))
	return result, err
}
