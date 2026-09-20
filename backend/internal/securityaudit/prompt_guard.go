package securityaudit

import (
	"context"
	"errors"
	"sync"
	"time"
)

type GuardEvaluator struct {
	scanner PromptScanner
	repo    JobRepository
	metrics Metrics
	clock   Clock

	global           chan struct{}
	perNodeLimit     int
	chunkConcurrency int
	nodeMu           sync.Mutex
	nodes            map[string]chan struct{}
}

func NewGuardEvaluator(scanner PromptScanner, repo JobRepository, metrics Metrics) *GuardEvaluator {
	return newGuardEvaluatorWithChunkConcurrency(scanner, repo, metrics, 64, 16, DefaultPromptChunkConcurrency)
}

func newGuardEvaluator(scanner PromptScanner, repo JobRepository, metrics Metrics, globalLimit, perNodeLimit int) *GuardEvaluator {
	return newGuardEvaluatorWithChunkConcurrency(scanner, repo, metrics, globalLimit, perNodeLimit, DefaultPromptChunkConcurrency)
}

func newGuardEvaluatorWithChunkConcurrency(scanner PromptScanner, repo JobRepository, metrics Metrics, globalLimit, perNodeLimit, chunkConcurrency int) *GuardEvaluator {
	if globalLimit < 1 {
		globalLimit = 64
	}
	if perNodeLimit < 1 {
		perNodeLimit = 16
	}
	if chunkConcurrency < 1 {
		chunkConcurrency = DefaultPromptChunkConcurrency
	}
	return &GuardEvaluator{scanner: scanner, repo: repo, metrics: metrics, clock: realClock{},
		global: make(chan struct{}, globalLimit), perNodeLimit: perNodeLimit,
		chunkConcurrency: chunkConcurrency, nodes: map[string]chan struct{}{}}
}

func (g *GuardEvaluator) Evaluate(ctx context.Context, cfg ActiveConfig, snapshot PromptSnapshot) (*PromptDecision, error) {
	return g.evaluate(ctx, cfg, snapshot, cfg.EnabledEndpoints(), true)
}

// EvaluateShadow runs one explicitly selected endpoint without writing a
// second enforcement event. Adaptive samples are persisted separately so a
// shadow disagreement cannot be mistaken for an actual user block.
func (g *GuardEvaluator) EvaluateShadow(ctx context.Context, cfg ActiveConfig, snapshot PromptSnapshot, endpoint ActiveEndpoint) (*PromptDecision, error) {
	return g.evaluate(ctx, cfg, snapshot, []ActiveEndpoint{endpoint}, false)
}

func (g *GuardEvaluator) evaluate(ctx context.Context, cfg ActiveConfig, snapshot PromptSnapshot, endpoints []ActiveEndpoint, persistEvent bool) (*PromptDecision, error) {
	if g == nil || g.scanner == nil {
		if g != nil && g.metrics != nil {
			g.metrics.Observe(DecisionUnavailable, 0)
		}
		logGuardFailure(snapshot, cfg, DecisionUnavailable, ErrorCodeUnavailable, "", 0)
		return nil, &GuardError{Code: ErrorCodeUnavailable}
	}
	start := g.clock.Now()
	ctx = withPromptInvocationContext(ctx, snapshot.RequestID, cfg.ConfigVersion)
	baseFields := snapshotLogFields(snapshot)
	baseFields["config_version"] = cfg.ConfigVersion
	// Enforcement evaluations get a deterministic repository guard before any
	// model invocation. Shadow reviews deliberately skip this shortcut so they
	// still measure the selected model's independent classification quality.
	if persistEvent {
		if result := MatchExplicitBypassSnapshotPolicy(snapshot, cfg.Scanners); result != nil {
			result.LatencyMS = int(g.clock.Now().Sub(start).Milliseconds())
			LogInfo(EventEvaluationStarted, mergeLogFields(baseFields, map[string]any{
				"chunk_total": 1, "status": "started", "scanner_backend": result.ScannerBackend,
			}))
			return g.finishEvaluation(ctx, cfg, snapshot, result, persistEvent, start, baseFields)
		}
		if result := MatchKnownRepositorySnapshotPolicy(snapshot, cfg.Scanners); result != nil {
			result.LatencyMS = int(g.clock.Now().Sub(start).Milliseconds())
			LogInfo(EventEvaluationStarted, mergeLogFields(baseFields, map[string]any{
				"chunk_total": 1, "status": "started", "scanner_backend": result.ScannerBackend,
			}))
			return g.finishEvaluation(ctx, cfg, snapshot, result, persistEvent, start, baseFields)
		}
	}
	if len(endpoints) == 0 {
		if g.metrics != nil {
			g.metrics.Observe(DecisionUnavailable, g.clock.Now().Sub(start))
		}
		logGuardFailure(snapshot, cfg, DecisionUnavailable, ErrorCodeUnavailable, "", g.clock.Now().Sub(start))
		return nil, &GuardError{Code: ErrorCodeUnavailable}
	}
	select {
	case g.global <- struct{}{}:
		defer func() { <-g.global }()
	default:
		if g.metrics != nil {
			g.metrics.IncBulkheadFull()
			g.metrics.Observe(DecisionUnavailable, g.clock.Now().Sub(start))
		}
		logGuardFailure(snapshot, cfg, DecisionUnavailable, ErrorCodeUnavailable, "", g.clock.Now().Sub(start))
		return nil, &GuardError{Code: ErrorCodeUnavailable}
	}
	inputLimit := minimumInputLimit(endpoints)
	chunks := SplitRunes(snapshot.ScanText, inputLimit)
	if len(chunks) == 0 {
		if g.metrics != nil {
			g.metrics.Observe(DecisionAllow, g.clock.Now().Sub(start))
		}
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	LogInfo(EventEvaluationStarted, mergeLogFields(baseFields, map[string]any{"chunk_total": len(chunks), "status": "started"}))
	chunkConcurrency := cfg.PromptChunkConcurrency
	if chunkConcurrency < MinPromptChunkConcurrency || chunkConcurrency > MaxPromptChunkConcurrency {
		chunkConcurrency = g.chunkConcurrency
	}
	results, err := scanChunksConcurrently(ctx, chunks, chunkConcurrency, func(scanCtx context.Context, index int, chunk string) (*NormalizedResult, error) {
		chunkStarted := g.clock.Now()
		LogInfo(EventChunkStarted, mergeLogFields(baseFields, map[string]any{
			"chunk_index": index + 1, "chunk_total": len(chunks),
			"chunk_chars": len([]rune(chunk)), "input_chars": snapshot.PromptLength, "input_limit": inputLimit,
			"status": "started",
		}))
		// Each chunk gets a fresh failover budget. Sharing one deadline across all
		// chunks makes later chunks inherit time already spent scanning earlier
		// ones, which can cause an immediate fail-closed result on long prompts.
		chunkCtx, cancel := context.WithTimeout(scanCtx, failoverTimeout(endpoints))
		result, scanErr := g.scanChunk(chunkCtx, cfg, endpoints, chunk)
		cancel()
		if scanErr != nil {
			code := guardErrorCode(scanErr)
			LogWarn(EventChunkFailed, mergeLogFields(baseFields, map[string]any{
				"chunk_index": index + 1, "chunk_total": len(chunks),
				"chunk_chars": len([]rune(chunk)), "input_chars": snapshot.PromptLength, "input_limit": inputLimit,
				"latency_ms": g.clock.Now().Sub(chunkStarted).Milliseconds(), "error_code": code, "status": "failed",
			}))
			return nil, scanErr
		}
		result.ChunkTotal = len(chunks)
		LogInfo(EventChunkCompleted, mergeLogFields(baseFields, map[string]any{
			"chunk_index": index + 1, "chunk_total": len(chunks),
			"chunk_chars": len([]rune(chunk)), "input_chars": snapshot.PromptLength, "input_limit": inputLimit,
			"guard_endpoint_id": result.GuardEndpointID, "action": result.Action,
			"latency_ms": g.clock.Now().Sub(chunkStarted).Milliseconds(), "status": "completed",
		}))
		return result, nil
	})
	if err != nil {
		code := guardErrorCode(err)
		kind := DecisionUnavailable
		if code == ErrorCodeInvalidResponse {
			kind = DecisionInvalid
		}
		if g.metrics != nil {
			g.metrics.Observe(kind, g.clock.Now().Sub(start))
			var guardErr *GuardError
			if errors.As(err, &guardErr) && guardErr.Timeout {
				g.metrics.IncTimeout()
			}
		}
		logGuardFailure(snapshot, cfg, kind, code, "", g.clock.Now().Sub(start))
		return nil, err
	}
	aggregated, err := AggregateResults(results, g.clock.Now().Sub(start))
	if err != nil {
		if g.metrics != nil {
			g.metrics.Observe(DecisionInvalid, g.clock.Now().Sub(start))
		}
		logGuardFailure(snapshot, cfg, DecisionInvalid, ErrorCodeInvalidResponse, "", g.clock.Now().Sub(start))
		return nil, &GuardError{Code: ErrorCodeInvalidResponse, Cause: err}
	}
	aggregated.ChunkTotal = len(chunks)
	return g.finishEvaluation(ctx, cfg, snapshot, aggregated, persistEvent, start, baseFields)
}

func (g *GuardEvaluator) finishEvaluation(ctx context.Context, cfg ActiveConfig, snapshot PromptSnapshot, result *NormalizedResult, persistEvent bool, start time.Time, baseFields map[string]any) (*PromptDecision, error) {
	kind := decisionKindForResult(result)
	decision := &PromptDecision{Kind: kind, Result: result, AllowNextStage: kind == DecisionAllow || kind == DecisionFlag}
	if kind == DecisionBlock {
		decision.ErrorCode = ErrorCodeBlocked
	}
	if g.metrics != nil {
		g.metrics.Observe(kind, g.clock.Now().Sub(start))
	}
	LogInfo(EventChunksAggregated, mergeLogFields(baseFields, map[string]any{
		"decision":   kind,
		"risk_level": result.RiskLevel, "action": result.Action, "chunk_total": result.ChunkTotal,
		"latency_ms": result.LatencyMS, "guard_endpoint_id": result.GuardEndpointID, "stage": snapshot.Stage,
		"status": "completed",
	}))
	if persistEvent && g.repo != nil {
		if _, recordErr := g.repo.RecordBlocking(ctx, snapshot.Redacted(), cfg.ConfigVersion, result, cfg.StorePassEvents); recordErr != nil {
			if g.metrics != nil {
				g.metrics.IncRecordFailed()
			}
			LogWarn(EventResultRecordFailed, mergeLogFields(baseFields, map[string]any{
				"decision": kind, "error_code": "result_record_failed", "stage": snapshot.Stage,
				"status": "failed",
			}))
		}
	}
	if kind == DecisionBlock {
		LogWarn(EventGuardBlocked, mergeLogFields(baseFields, map[string]any{
			"guard_endpoint_id": result.GuardEndpointID,
			"decision":          kind, "risk_level": result.RiskLevel, "action": result.Action, "chunk_total": result.ChunkTotal,
			"latency_ms": result.LatencyMS, "status": "blocked", "error_code": ErrorCodeBlocked,
			"stage": snapshot.Stage, "upstream_dispatched": false, "billing_preconsumed": false,
		}))
	} else {
		LogInfo(EventGuardAllowed, mergeLogFields(baseFields, map[string]any{
			"decision": kind, "risk_level": result.RiskLevel, "action": result.Action,
			"guard_endpoint_id": result.GuardEndpointID, "chunk_total": result.ChunkTotal,
			"latency_ms": result.LatencyMS, "stage": snapshot.Stage, "status": "allowed",
		}))
	}
	return decision, nil
}

func logGuardFailure(snapshot PromptSnapshot, cfg ActiveConfig, kind DecisionKind, code, guardEndpointID string, latency time.Duration) {
	fields := snapshotLogFields(snapshot)
	fields["config_version"] = cfg.ConfigVersion
	LogWarn(EventGuardFailed, mergeLogFields(fields, map[string]any{
		"decision": kind, "guard_endpoint_id": guardEndpointID, "latency_ms": latency.Milliseconds(),
		"status": "failed", "error_code": code, "upstream_dispatched": false, "billing_preconsumed": false,
	}))
}

func (g *GuardEvaluator) scanChunk(ctx context.Context, cfg ActiveConfig, endpoints []ActiveEndpoint, chunk string) (*NormalizedResult, error) {
	var lastErr error
	for index, endpoint := range endpoints {
		semaphore := g.nodeSemaphore(endpoint.ID)
		select {
		case semaphore <- struct{}{}:
		case <-ctx.Done():
			return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true, Timeout: errors.Is(ctx.Err(), context.DeadlineExceeded), Cause: ctx.Err()}
		default:
			if g.metrics != nil {
				g.metrics.IncBulkheadFull()
			}
			lastErr = &GuardError{Code: ErrorCodeUnavailable, Retryable: true}
			if index < len(endpoints)-1 && g.metrics != nil {
				g.metrics.IncFailover()
			}
			continue
		}
		result, err := callPromptScanner(ctx, g.scanner, endpoint, chunk, cfg.Scanners)
		<-semaphore
		if err == nil && result != nil {
			return result, nil
		}
		if err == nil {
			err = &GuardError{Code: ErrorCodeInvalidResponse, Retryable: false}
		}
		lastErr = err
		if index < len(endpoints)-1 && g.metrics != nil {
			g.metrics.IncFailover()
		}
		if index < len(endpoints)-1 && ctx.Err() == nil {
			continue
		}
		return nil, err
	}
	if lastErr == nil {
		lastErr = &GuardError{Code: ErrorCodeUnavailable}
	}
	return nil, lastErr
}

func callPromptScanner(ctx context.Context, scanner PromptScanner, endpoint ActiveEndpoint, chunk string, scanners []string) (result *NormalizedResult, err error) {
	defer func() {
		if recover() != nil {
			result = nil
			err = &GuardError{Code: ErrorCodeUnavailable, Retryable: false}
		}
	}()
	return scanner.Scan(ctx, endpoint, chunk, scanners)
}

func (g *GuardEvaluator) nodeSemaphore(id string) chan struct{} {
	g.nodeMu.Lock()
	defer g.nodeMu.Unlock()
	semaphore := g.nodes[id]
	if semaphore == nil {
		semaphore = make(chan struct{}, g.perNodeLimit)
		g.nodes[id] = semaphore
	}
	return semaphore
}

func minimumInputLimit(endpoints []ActiveEndpoint) int {
	limit := DefaultInputLimit
	for index, endpoint := range endpoints {
		value := endpoint.InputLimit
		if value <= 0 {
			value = DefaultInputLimit
		}
		if index == 0 || value < limit {
			limit = value
		}
	}
	return limit
}

func failoverTimeout(endpoints []ActiveEndpoint) time.Duration {
	total := time.Duration(0)
	for _, endpoint := range endpoints {
		timeout := time.Duration(endpoint.TimeoutMS) * time.Millisecond
		if timeout <= 0 {
			timeout = DefaultTimeoutMS * time.Millisecond
		}
		total += timeout
	}
	if total <= 0 {
		total = DefaultTimeoutMS * time.Millisecond
	}
	// Keep a blocking audit bounded while still allowing the configured primary
	// and fallback endpoint budgets to run.
	if total > 60*time.Second {
		total = 60 * time.Second
	}
	return total
}

func guardErrorCode(err error) string {
	var guardErr *GuardError
	if errors.As(err, &guardErr) && guardErr.Code != "" {
		return guardErr.Code
	}
	return ErrorCodeUnavailable
}

func pointerLogID(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}
