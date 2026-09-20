package securityaudit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

type PromptService struct {
	config       ConfigStore
	repo         *PostgreSQLRepository
	payload      *RedisPayloadStore
	enqueuer     *Enqueuer
	runner       *Runner
	evaluator    *GuardEvaluator
	scanner      PromptScanner
	segmentCache PromptSegmentAllowCache
	blockCache   PromptBlockCache
	metrics      *AtomicMetrics
	clock        Clock

	lifecycleMu   sync.Mutex
	cancel        context.CancelFunc
	background    context.Context
	enqueueWG     sync.WaitGroup
	enqueueSlots  chan struct{}
	adaptiveSlots chan struct{}
	outputSlots   chan struct{}
	probeMu       sync.RWMutex
	probes        map[string]ProbeResult
}

func NewPromptService(
	config ConfigStore,
	repo *PostgreSQLRepository,
	payload *RedisPayloadStore,
	scanner PromptScanner,
	metrics *AtomicMetrics,
) *PromptService {
	enqueuer := NewEnqueuer(config, repo, payload, metrics)
	evaluator := NewGuardEvaluator(scanner, repo, metrics)
	runner := NewRunner(config, repo, payload, scanner, metrics)
	service := &PromptService{
		config: config, repo: repo, payload: payload, scanner: scanner, metrics: metrics,
		segmentCache: payload,
		blockCache:   payload,
		enqueuer:     enqueuer, evaluator: evaluator, runner: runner, clock: realClock{},
		enqueueSlots: make(chan struct{}, 128), adaptiveSlots: make(chan struct{}, 64), outputSlots: make(chan struct{}, 64), probes: map[string]ProbeResult{},
	}
	// Async jobs and blocking requests share the same adaptive pipeline. The
	// callback keeps Runner independent from the concrete PostgreSQL repository
	// while preserving the exact endpoint order captured in each job config.
	runner.adaptiveReview = service.scheduleAdaptiveReview
	runner.auditComplete = service.onBackgroundAuditComplete
	return service
}

func (s *PromptService) Start(ctx context.Context) error {
	if s == nil || s.config == nil || s.runner == nil {
		return errors.New("prompt audit service unavailable")
	}
	s.lifecycleMu.Lock()
	if s.cancel != nil {
		s.lifecycleMu.Unlock()
		return nil
	}
	background, cancel := context.WithCancel(ctx)
	s.background, s.cancel = background, cancel
	s.lifecycleMu.Unlock()
	configErr := s.config.Start(background)
	workerErr := s.runner.Start(background)
	return errors.Join(configErr, workerErr)
}

func (s *PromptService) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.lifecycleMu.Lock()
	cancel := s.cancel
	s.cancel = nil
	s.lifecycleMu.Unlock()
	if cancel != nil {
		cancel()
	}
	var workerErr error
	if s.runner != nil {
		workerErr = s.runner.Shutdown(ctx)
	}
	done := make(chan struct{})
	go func() { s.enqueueWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		if workerErr == nil {
			workerErr = ctx.Err()
		}
	}
	var configErr error
	if s.config != nil {
		configErr = s.config.Shutdown(ctx)
	}
	if workerErr != nil {
		return workerErr
	}
	return configErr
}

func (s *PromptService) EffectiveMode() Mode {
	if s == nil || s.config == nil {
		return ModeOff
	}
	return s.config.EffectiveMode()
}

func (s *PromptService) HasBackgroundAudit() bool {
	if s == nil || s.config == nil {
		return false
	}
	cfg, ok := s.config.Active()
	return ok && cfg.RiskControlEnabled && cfg.Enabled && cfg.EffectiveBackgroundAuditMode() != BackgroundAuditModeOff
}

// CaptureAuditGap records a complete received prompt when the prompt-audit
// switch is off. It never invokes a classifier and never replays the gap after
// auditing is enabled again.
func (s *PromptService) CaptureAuditGap(_ context.Context, req Request) {
	if s == nil || s.config == nil || s.repo == nil {
		return
	}
	cfg, ok := s.config.Active()
	if !ok || cfg.Enabled || !cfg.IncludesGroup(req.GroupID) {
		return
	}
	select {
	case s.enqueueSlots <- struct{}{}:
	default:
		LogWarn("prompt_audit.gap_capture_dropped", map[string]any{"request_id": req.RequestID, "status": "dropped", "error_code": "local_capture_busy"})
		return
	}
	s.lifecycleMu.Lock()
	background := s.background
	s.lifecycleMu.Unlock()
	if background == nil {
		<-s.enqueueSlots
		return
	}
	requestCopy := req.Clone()
	s.enqueueWG.Add(1)
	go func() {
		defer s.enqueueWG.Done()
		defer func() { <-s.enqueueSlots }()
		snapshot, err := ExtractPromptSnapshot(requestCopy)
		if err != nil {
			return
		}
		snapshot.Stage = "audit_gap"
		snapshot.AuditedPrompt = ""
		snapshot.ScanText = ""
		snapshot.SegmentFingerprints = nil
		ctx, cancel := context.WithTimeout(background, 2*time.Second)
		defer cancel()
		if _, err := s.repo.RecordAuditGap(ctx, snapshot, cfg.ConfigVersion); err != nil {
			LogWarn("prompt_audit.gap_capture_failed", map[string]any{"request_id": req.RequestID, "status": "failed", "error_code": "database_unavailable"})
		}
	}()
}

func (s *PromptService) ShouldBypass(req Request) bool {
	if req.RequireJev {
		return false
	}
	return s != nil && req.PromptAuditBypass
}

// RecordUserBypass is intentionally asynchronous: explicitly released users
// must not wait for prompt extraction or PostgreSQL. The marker remains visible
// to administrators without invoking any classifier or writing risk caches.
func (s *PromptService) RecordUserBypass(_ context.Context, req Request) {
	if s == nil || s.config == nil || s.repo == nil || !s.ShouldBypass(req) {
		return
	}
	cfg, ok := s.config.Active()
	if !ok {
		return
	}
	LogInfo(EventUserBypass, map[string]any{
		"request_id": req.RequestID, "user_id": req.UserID,
		"config_version": cfg.ConfigVersion, "status": "allowed", "upstream_dispatched": true,
	})
	select {
	case s.enqueueSlots <- struct{}{}:
	default:
		LogWarn(EventUserBypassDropped, map[string]any{"request_id": req.RequestID, "status": "dropped", "error_code": "local_capture_busy"})
		return
	}
	s.lifecycleMu.Lock()
	background := s.background
	s.lifecycleMu.Unlock()
	if background == nil {
		<-s.enqueueSlots
		return
	}
	requestCopy := req.Clone()
	s.enqueueWG.Add(1)
	go func() {
		defer s.enqueueWG.Done()
		defer func() { <-s.enqueueSlots }()
		snapshot, err := ExtractPromptSnapshot(requestCopy)
		if err != nil {
			LogWarn(EventUserBypassFailed, map[string]any{"request_id": req.RequestID, "status": "failed", "error_code": "prompt_extract_failed"})
			return
		}
		snapshot.Stage = "user_bypass"
		snapshot.AuditSubject = "user_bypass"
		snapshot.AuditedPrompt = ""
		snapshot.ScanText = ""
		snapshot.SegmentFingerprints = nil
		ctx, cancel := context.WithTimeout(background, 2*time.Second)
		defer cancel()
		if _, err := s.repo.RecordUserBypass(ctx, snapshot, cfg.ConfigVersion); err != nil {
			LogWarn(EventUserBypassFailed, map[string]any{"request_id": req.RequestID, "status": "failed", "error_code": "database_unavailable"})
		}
	}()
}

func (s *PromptService) Enqueue(_ context.Context, req Request) error {
	if s == nil || s.enqueuer == nil {
		return nil
	}
	if !req.RequireJev && s.ShouldBypass(req) {
		return nil
	}
	cfg, ok := s.config.Active()
	if !ok || !cfg.RiskControlEnabled || !cfg.Enabled || cfg.EffectiveBackgroundAuditMode() == BackgroundAuditModeOff {
		return nil
	}
	select {
	case s.enqueueSlots <- struct{}{}:
	default:
		if s.metrics != nil {
			s.metrics.IncDropped()
		}
		LogWarn(EventEnqueueDropped, map[string]any{"request_id": req.RequestID, "status": "dropped", "error_code": "local_enqueue_busy"})
		return nil
	}
	s.lifecycleMu.Lock()
	background := s.background
	s.lifecycleMu.Unlock()
	if background == nil {
		<-s.enqueueSlots
		return errors.New("prompt audit service not started")
	}
	requestCopy := req.Clone()
	s.enqueueWG.Add(1)
	go func() {
		defer s.enqueueWG.Done()
		defer func() { <-s.enqueueSlots }()
		ctx, cancel := context.WithTimeout(background, 2*time.Second)
		defer cancel()
		_ = s.enqueuer.Enqueue(ctx, requestCopy)
	}()
	return nil
}

func (s *PromptService) Evaluate(ctx context.Context, req Request) (*PromptDecision, error) {
	if s == nil || s.config == nil || s.evaluator == nil {
		return nil, &GuardError{Code: ErrorCodeUnavailable}
	}
	if s.config.BlockingActivationDegraded() {
		return nil, &GuardError{Code: ErrorCodeUnavailable}
	}
	if !req.RequireJev && s.ShouldBypass(req) {
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	cfg, ok := s.config.Active()
	if !ok {
		if s.config.EffectiveMode() == ModeBlocking {
			return nil, &GuardError{Code: ErrorCodeUnavailable}
		}
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	if req.RequireJev && (cfg.EffectiveMode() != ModeBlocking || !cfg.IncludesGroup(req.GroupID) || !jevEndpointsReady(cfg)) {
		return nil, &GuardError{Code: ErrorCodeUnavailable}
	}
	if cfg.EffectiveMode() != ModeBlocking || !cfg.IncludesGroup(req.GroupID) {
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	auditMode := cfg.EffectiveBlockingAuditMode()
	if req.RequireJev {
		auditMode = BlockingAuditModeFull
	}
	snapshot, err := buildScopedPromptSnapshot(ctx, req, cfg, auditMode, s.segmentCache)
	if errors.Is(err, ErrNoPromptText) {
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	if err != nil {
		return nil, &GuardError{Code: ErrorCodeInvalidResponse, Cause: err}
	}
	if cached, matched := s.matchCachedBlock(ctx, req, cfg, snapshot); matched {
		return cached, nil
	}
	decision, err := s.evaluator.Evaluate(ctx, cfg, snapshot)
	if err != nil || decision == nil {
		return decision, err
	}
	if decision.Kind == DecisionAllow && len(snapshot.SegmentFingerprints) > 0 && s.segmentCache != nil {
		cacheCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		cacheErr := s.segmentCache.RememberAllowed(cacheCtx, req, cfg.ConfigVersion, snapshot.SegmentFingerprints)
		cancel()
		if cacheErr != nil {
			LogWarn("prompt_audit.segment_cache_write_failed", map[string]any{"request_id": req.RequestID, "status": "failed", "error_code": "segment_cache_unavailable"})
		}
	}
	correlationSnapshot := snapshot
	correlationSnapshot.ScanText = ""
	decision.Snapshot = &correlationSnapshot
	s.scheduleAdaptiveReview(cfg, snapshot, decision)
	if decision.Kind == DecisionBlock {
		s.rememberBlocked(ctx, req, cfg, snapshot)
	}
	return decision, nil
}

// EvaluateKnownRisk is used only when the normal foreground gate is disabled.
// It is normally a single bounded Redis lookup. A cached fingerprint blocks
// immediately; a temporarily escalated user is rechecked synchronously with
// incremental scope so a new branch cannot evade a background finding.
func (s *PromptService) EvaluateKnownRisk(ctx context.Context, req Request) (*PromptDecision, error) {
	if s == nil || s.config == nil || s.evaluator == nil {
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	if !req.RequireJev && s.ShouldBypass(req) {
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	cfg, ok := s.config.Active()
	if !ok || !cfg.RiskControlEnabled || !cfg.Enabled || cfg.BlockingEnabled || !cfg.IncludesGroup(req.GroupID) {
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	fullSnapshot, err := ExtractPromptSnapshot(req)
	if errors.Is(err, ErrNoPromptText) {
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	if err != nil {
		return nil, &GuardError{Code: ErrorCodeInvalidResponse, Cause: err}
	}
	if cached, matched := s.matchCachedBlock(ctx, req, cfg, fullSnapshot); matched {
		return cached, nil
	}
	if s.blockCache == nil {
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	cacheCtx, cancel := context.WithTimeout(ctx, 75*time.Millisecond)
	riskActive, cacheErr := s.blockCache.RiskActive(cacheCtx, req)
	cancel()
	if cacheErr != nil || !riskActive {
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	snapshot, err := buildScopedPromptSnapshot(ctx, req, cfg, BlockingAuditModeIncrementalFull, s.segmentCache)
	if errors.Is(err, ErrNoPromptText) {
		return &PromptDecision{Kind: DecisionAllow, AllowNextStage: true}, nil
	}
	if err != nil {
		return nil, &GuardError{Code: ErrorCodeInvalidResponse, Cause: err}
	}
	decision, err := s.evaluator.Evaluate(ctx, cfg, snapshot)
	if err != nil || decision == nil {
		return decision, err
	}
	if decision.Kind == DecisionBlock {
		s.rememberBlocked(ctx, req, cfg, snapshot)
	}
	correlationSnapshot := snapshot
	correlationSnapshot.ScanText = ""
	correlationSnapshot.SegmentFingerprints = nil
	decision.Snapshot = &correlationSnapshot
	return decision, nil
}

func (s *PromptService) matchCachedBlock(ctx context.Context, req Request, cfg ActiveConfig, snapshot PromptSnapshot) (*PromptDecision, bool) {
	if s == nil || s.blockCache == nil {
		return nil, false
	}
	cacheCtx, cancel := context.WithTimeout(ctx, 75*time.Millisecond)
	reason, matched, err := s.blockCache.MatchBlocked(cacheCtx, req, snapshot)
	cancel()
	if err != nil || !matched {
		return nil, false
	}
	result := &NormalizedResult{
		Decision: EventCritical, RiskLevel: RiskCritical, Action: ActionBlock, Safety: "Unsafe",
		ScannerScores: map[string]float64{}, ScannerEvidence: map[string]string{"local_cache": reason},
		ScannerBackend: "prompt-audit-local-cache", ScannerVersion: "v1", GuardEndpointID: "local-risk-cache",
		PolicyID: "prompt-audit-background-block", PolicyVersion: 1, ChunkTotal: 1,
	}
	if s.repo != nil {
		storedSnapshot := snapshot
		storedSnapshot.Stage = "local_policy_cache"
		storedSnapshot.AuditSubject = "local_cache"
		_, _ = s.repo.RecordBlocking(ctx, storedSnapshot.Redacted(), cfg.ConfigVersion, result, true)
	}
	correlationSnapshot := snapshot
	correlationSnapshot.ScanText = ""
	correlationSnapshot.SegmentFingerprints = nil
	return &PromptDecision{Kind: DecisionBlock, Result: result, Snapshot: &correlationSnapshot, AllowNextStage: false}, true
}

func (s *PromptService) rememberBlocked(ctx context.Context, req Request, cfg ActiveConfig, snapshot PromptSnapshot) {
	if s == nil || s.blockCache == nil {
		return
	}
	cacheCtx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	if err := s.blockCache.RememberBlocked(cacheCtx, req, snapshot); err != nil {
		LogWarn("prompt_audit.block_cache_write_failed", map[string]any{"request_id": req.RequestID, "status": "failed", "error_code": "block_cache_unavailable"})
		return
	}
	if s.payload != nil {
		_ = s.payload.ForgetAllowed(cacheCtx, req, cfg.ConfigVersion, snapshot.SegmentFingerprints)
	}
}

func (s *PromptService) onBackgroundAuditComplete(cfg ActiveConfig, snapshot PromptSnapshot, decision *PromptDecision) {
	if s == nil || decision == nil {
		return
	}
	req := requestFromSnapshot(snapshot)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if decision.Kind == DecisionAllow && s.segmentCache != nil && len(snapshot.SegmentFingerprints) > 0 {
		_ = s.segmentCache.RememberAllowed(ctx, req, cfg.ConfigVersion, snapshot.SegmentFingerprints)
		return
	}
	if decision.Kind == DecisionBlock {
		s.rememberBlocked(ctx, req, cfg, snapshot)
	}
}

func (s *PromptService) ShouldAuditOutput(req Request, inputDecision DecisionKind) bool {
	if s == nil || s.config == nil || inputDecision == DecisionBlock || inputDecision == DecisionUnavailable || inputDecision == DecisionInvalid {
		return false
	}
	if !req.RequireJev && s.ShouldBypass(req) {
		return false
	}
	cfg, ok := s.config.Active()
	if !ok || !cfg.Enabled || !cfg.OutputAuditEnabled || !cfg.IncludesGroup(req.GroupID) {
		return false
	}
	rate := cfg.OutputAllowSampleRate
	if inputDecision == DecisionFlag {
		rate = cfg.OutputRiskSampleRate
	}
	return deterministicAuditSample(req.RequestID+"|"+req.Model+"|output", rate)
}

// ObserveOutput is intentionally fire-and-forget. It records a sampled output
// finding after the response has already been delivered and never changes the
// user-visible status or stream timing.
func (s *PromptService) ObserveOutput(_ context.Context, req Request, inputDecision DecisionKind, responseBody []byte, streaming bool) {
	if s == nil || !s.ShouldAuditOutput(req, inputDecision) || len(responseBody) == 0 {
		return
	}
	select {
	case s.outputSlots <- struct{}{}:
	default:
		LogWarn("prompt_audit.output_dropped", map[string]any{"request_id": req.RequestID, "status": "dropped", "error_code": "output_queue_busy"})
		return
	}
	s.lifecycleMu.Lock()
	background := s.background
	s.lifecycleMu.Unlock()
	if background == nil {
		<-s.outputSlots
		return
	}
	requestCopy := req.Clone()
	bodyCopy := append([]byte(nil), responseBody...)
	s.enqueueWG.Add(1)
	go func() {
		defer s.enqueueWG.Done()
		defer func() { <-s.outputSlots }()
		text := ExtractAssistantOutput(bodyCopy, streaming)
		if strings.TrimSpace(text) == "" {
			return
		}
		cfg, ok := s.config.Active()
		if !ok || !cfg.Enabled || !cfg.OutputAuditEnabled || !cfg.IncludesGroup(requestCopy.GroupID) {
			return
		}
		snapshot, err := BuildOutputPromptSnapshot(requestCopy, text)
		if err != nil {
			return
		}
		// Sampled output observations are useful only when visible in the event
		// workspace, including safe observations used to estimate false positives.
		cfg.StorePassEvents = true
		ctx, cancel := context.WithTimeout(background, failoverTimeout(cfg.EnabledEndpoints()))
		decision, err := s.evaluator.Evaluate(ctx, cfg, snapshot)
		cancel()
		if err == nil && decision != nil && decision.Result != nil {
			s.scheduleAdaptiveReview(cfg, snapshot, decision)
		}
	}()
}

func (s *PromptService) scheduleAdaptiveReview(cfg ActiveConfig, snapshot PromptSnapshot, decision *PromptDecision) {
	if s == nil || s.repo == nil || s.evaluator == nil || decision == nil || decision.Result == nil {
		return
	}
	if !cfg.AdaptiveEnabled && !cfg.AdaptiveCollectWhenDisabled {
		return
	}
	rate := cfg.AdaptiveAllowSampleRate
	if decision.Kind != DecisionAllow {
		rate = cfg.AdaptiveRiskSampleRate
	}
	if cfg.AdaptiveEnabled && !deterministicAuditSample(snapshot.RequestID+"|"+snapshot.PromptHash+"|"+snapshot.Stage, rate) {
		return
	}
	select {
	case s.adaptiveSlots <- struct{}{}:
	default:
		LogWarn("prompt_audit.adaptive_dropped", map[string]any{"request_id": snapshot.RequestID, "status": "dropped", "error_code": "adaptive_queue_busy"})
		return
	}
	s.lifecycleMu.Lock()
	background := s.background
	s.lifecycleMu.Unlock()
	if background == nil {
		<-s.adaptiveSlots
		return
	}
	requestSnapshot := snapshot
	if snapshot.GroupID != nil {
		value := *snapshot.GroupID
		requestSnapshot.GroupID = &value
	}
	primary := cloneNormalizedResult(decision.Result)
	s.enqueueWG.Add(1)
	go func() {
		defer s.enqueueWG.Done()
		defer func() { <-s.adaptiveSlots }()
		if !cfg.AdaptiveEnabled {
			ctx, cancel := context.WithTimeout(background, 2*time.Second)
			defer cancel()
			_ = s.repo.UpsertAdaptiveSample(ctx, AdaptiveSampleRecord{
				Snapshot: requestSnapshot.Redacted(), ConfigVersion: cfg.ConfigVersion,
				Primary: primary, Status: "pending",
			})
			return
		}
		shadowEndpoint, ok := nextShadowEndpoint(cfg.EnabledEndpoints(), primary.GuardEndpointID)
		if !ok {
			ctx, cancel := context.WithTimeout(background, 2*time.Second)
			defer cancel()
			_ = s.repo.UpsertAdaptiveSample(ctx, AdaptiveSampleRecord{
				Snapshot: requestSnapshot.Redacted(), ConfigVersion: cfg.ConfigVersion,
				Primary: primary, Status: "pending",
			})
			return
		}
		shadowSnapshot := requestSnapshot
		shadowSnapshot.Stage = "adaptive_shadow"
		timeout := time.Duration(shadowEndpoint.TimeoutMS)*time.Millisecond + time.Second
		if timeout < 2*time.Second {
			timeout = 2 * time.Second
		}
		ctx, cancel := context.WithTimeout(background, timeout)
		shadowDecision, err := s.evaluator.EvaluateShadow(ctx, cfg, shadowSnapshot, shadowEndpoint)
		cancel()
		sample := AdaptiveSampleRecord{
			Snapshot: requestSnapshot.Redacted(), ConfigVersion: cfg.ConfigVersion,
			Primary: primary, ShadowEndpoint: shadowEndpoint.ID,
		}
		if err != nil || shadowDecision == nil || shadowDecision.Result == nil {
			sample.Status = "shadow_failed"
			sample.ErrorCode = guardErrorCode(err)
		} else {
			sample.Shadow = cloneNormalizedResult(shadowDecision.Result)
			sample.Status = "disagreement"
			if adaptiveResultsAgree(primary, sample.Shadow) {
				sample.Status = "shadow_match"
			}
		}
		writeCtx, writeCancel := context.WithTimeout(background, 2*time.Second)
		defer writeCancel()
		if err := s.repo.UpsertAdaptiveSample(writeCtx, sample); err != nil {
			LogWarn("prompt_audit.adaptive_record_failed", map[string]any{"request_id": requestSnapshot.RequestID, "status": "failed", "error_code": "adaptive_record_failed"})
		}
	}()
}

func cloneNormalizedResult(result *NormalizedResult) *NormalizedResult {
	if result == nil {
		return nil
	}
	copyResult := *result
	copyResult.Categories = append([]string(nil), result.Categories...)
	copyResult.IntentCategories = append([]string(nil), result.IntentCategories...)
	copyResult.ContentCategories = append([]string(nil), result.ContentCategories...)
	copyResult.MatchedScanners = append([]string(nil), result.MatchedScanners...)
	copyResult.UnknownCategories = append([]string(nil), result.UnknownCategories...)
	copyResult.ScannerScores = make(map[string]float64, len(result.ScannerScores))
	for key, value := range result.ScannerScores {
		copyResult.ScannerScores[key] = value
	}
	copyResult.ScannerEvidence = make(map[string]string, len(result.ScannerEvidence))
	for key, value := range result.ScannerEvidence {
		copyResult.ScannerEvidence[key] = value
	}
	return &copyResult
}

// RecordUpstreamPolicyFeedback persists a provider safety rejection alongside
// the local classifier result without rewriting or deleting that original
// verdict. This makes a local Allow followed by an upstream block auditable.
func (s *PromptService) RecordUpstreamPolicyFeedback(ctx context.Context, snapshot PromptSnapshot, code, message string) error {
	return s.recordBioPolicyEvent(ctx, snapshot, "upstream_feedback", "upstream_feedback", "openai-upstream-feedback", code, message)
}

func (s *PromptService) RecordLocalPolicyCacheBlock(ctx context.Context, snapshot PromptSnapshot, code, message string) error {
	return s.recordBioPolicyEvent(ctx, snapshot, "local_policy_cache", "local_cache", "gateway-policy-cache", code, message)
}

func (s *PromptService) recordBioPolicyEvent(ctx context.Context, snapshot PromptSnapshot, stage, subject, backend, code, message string) error {
	if s == nil || s.repo == nil || strings.TrimSpace(snapshot.PromptHash) == "" {
		return nil
	}
	code = strings.ToLower(strings.TrimSpace(code))
	if code != "bio_policy" {
		return nil
	}
	configVersion := int64(1)
	if s.config != nil {
		if cfg, ok := s.config.Active(); ok && cfg.ConfigVersion > 0 {
			configVersion = cfg.ConfigVersion
		}
	}
	snapshot.Stage = stage
	snapshot.AuditSubject = subject
	if strings.TrimSpace(snapshot.TaskFingerprint) == "" {
		snapshot.TaskFingerprint = TaskFingerprintForText(snapshot.FullPrompt)
	}
	snapshot.ScanText = ""
	result := &NormalizedResult{
		Decision: EventCritical, RiskLevel: RiskCritical, Action: ActionBlock, Safety: "Unsafe",
		Categories: []string{"biological_risk"}, MatchedScanners: []string{"biological_risk"},
		ScannerScores:   map[string]float64{"biological_risk": 1},
		ScannerEvidence: map[string]string{"biological_risk": "bio_policy feedback: " + strings.TrimSpace(message)},
		ScannerBackend:  backend, ScannerVersion: code,
		GuardEndpointID: backend, PolicyID: "provider-policy-feedback", PolicyVersion: 1, ChunkTotal: 1,
	}
	_, err := s.repo.RecordBlocking(ctx, snapshot, configVersion, result, true)
	return err
}

func (s *PromptService) GetConfig() (PublicConfig, error) { return s.config.Public() }

func (s *PromptService) SaveConfig(ctx context.Context, req UpdateConfigRequest, actorID int64) (PublicConfig, error) {
	return s.config.Save(ctx, req, actorID)
}

func (s *PromptService) ListPolicyVersions(ctx context.Context, limit int) ([]PromptPolicyVersion, error) {
	return s.config.ListPolicyVersions(ctx, limit)
}

func (s *PromptService) RollbackPolicy(ctx context.Context, targetConfigVersion, expectedConfigVersion, actorID int64) (PublicConfig, error) {
	return s.config.RollbackPolicy(ctx, targetConfigVersion, expectedConfigVersion, actorID)
}

func (s *PromptService) Runtime(ctx context.Context) RuntimeSnapshot {
	expected, activeVersion, loadedAt, loadError := s.config.RuntimeState()
	cfg, hasConfig := s.config.Active()
	mode := s.EffectiveMode()
	workerTotal, queueCapacity := 0, 0
	if hasConfig {
		workerTotal, queueCapacity = cfg.WorkerCount, cfg.QueueCapacity
	}
	runtime := RuntimeSnapshot{
		ProcessStatus: "disabled", EffectiveMode: mode, ExpectedConfigVersion: expected,
		ActiveConfigVersion: activeVersion, ConfigLoadedAt: loadedAt, ConfigLoadError: loadError,
		WorkerTotal: workerTotal, QueueCapacity: queueCapacity, DatabaseStatus: "ok", RedisStatus: "ok",
		Endpoints: s.probeSnapshot(), GuardMetrics: s.metrics.Snapshot(),
	}
	if s.repo != nil {
		stats, err := s.repo.QueueStats(ctx)
		if err != nil {
			runtime.DatabaseStatus = "error"
			runtime.LastErrorCode = "database_unavailable"
		} else {
			runtime.Queue = stats
		}
		if usage, err := s.repo.UsageOverview(ctx, s.clock.Now()); err == nil {
			runtime.AuditUsage = usage
		} else {
			runtime.DatabaseStatus = "error"
			if runtime.LastErrorCode == "" {
				runtime.LastErrorCode = "audit_usage_unavailable"
			}
		}
		if adaptive, err := s.repo.AdaptiveStats(ctx); err == nil {
			runtime.Adaptive = adaptive
		} else if runtime.LastErrorCode == "" {
			runtime.LastErrorCode = "adaptive_stats_unavailable"
		}
	} else {
		runtime.DatabaseStatus = "error"
	}
	if s.payload == nil || s.payload.Ping(ctx) != nil {
		runtime.RedisStatus = "error"
		if runtime.LastErrorCode == "" {
			runtime.LastErrorCode = "payload_store_unavailable"
		}
	}
	activeWorkers, processed, failed, heartbeat, lastProcessed, workerCode, workerMessage := s.runner.Snapshot()
	runtime.WorkerActive, runtime.ProcessedTotal, runtime.FailedTotal = activeWorkers, processed, failed
	if s.metrics != nil {
		auditMetrics := s.metrics.AuditSnapshot()
		runtime.EnqueuedTotal, runtime.DroppedTotal = auditMetrics.Enqueued, auditMetrics.Dropped
	}
	runtime.WorkerHeartbeatAt, runtime.LastProcessedAt = heartbeat, lastProcessed
	if workerCode != "" {
		runtime.LastErrorCode, runtime.LastErrorMessage = workerCode, workerMessage
	}
	if mode != ModeOff {
		runtime.ProcessStatus = "running"
		if loadError != "" || runtime.DatabaseStatus != "ok" || runtime.RedisStatus != "ok" || activeVersion != expected {
			runtime.ProcessStatus = "degraded"
		}
		if heartbeat == nil || s.clock.Now().Sub(*heartbeat) > 10*time.Second {
			runtime.ProcessStatus = "degraded"
		}
	}
	return runtime
}

type ProbeRequest struct {
	Endpoint UpdateEndpoint `json:"endpoint"`
}

func (s *PromptService) Probe(ctx context.Context, request ProbeRequest) ProbeResult {
	started := s.clock.Now()
	endpoint, tokenApplied, err := s.resolveProbeEndpoint(request.Endpoint)
	if err != nil {
		return s.finishProbe(request.Endpoint.ID, started, ProbeResult{Status: "failed", ErrorCode: "endpoint_invalid", Message: "审计节点配置无效"})
	}
	LogInfo(EventProbeStarted, map[string]any{"guard_endpoint_id": endpoint.ID, "status": "started"})
	if endpoint.Protocol == JevProtocol {
		// Jev readiness uses its native structured evaluation endpoint. Never send
		// user content as a health probe and never pretend /chat/completions works.
		result, scanErr := callPromptScanner(ctx, s.scanner, endpoint, "Hello", AllScannerIDs)
		if scanErr == nil && result != nil && result.Action == ActionAllow {
			return s.finishProbe(endpoint.ID, started, ProbeResult{OK: true, Status: "healthy", Message: "Jev 结构化接口已验证；不代表策略准确率已验收", HTTPStatus: http.StatusOK, TokenApplied: tokenApplied})
		}
		status, retryable := 0, false
		code := guardErrorCode(scanErr)
		var guardErr *GuardError
		if errors.As(scanErr, &guardErr) {
			status, retryable = guardErr.HTTPStatus, guardErr.Retryable
		}
		if code == "" {
			code = ErrorCodeInvalidResponse
		}
		return s.finishProbe(endpoint.ID, started, ProbeResult{Status: "failed", ErrorCode: code, Message: "Jev 合成探测未通过，禁止视为已就绪", HTTPStatus: status, Retryable: retryable, TokenApplied: tokenApplied})
	}
	if s.scanner == nil {
		return s.finishProbe(endpoint.ID, started, ProbeResult{Status: "failed", ErrorCode: ErrorCodeUnavailable, Message: "审计扫描器不可用", Retryable: true, TokenApplied: tokenApplied})
	}
	result, scanErr := s.scanner.Scan(ctx, endpoint, "Hello, have a nice day.", AllScannerIDs)
	if scanErr == nil && result != nil {
		return s.finishProbe(endpoint.ID, started, ProbeResult{OK: true, Status: "healthy", Message: "审计节点模型调用及输出校验正常", HTTPStatus: http.StatusOK, TokenApplied: tokenApplied})
	}
	code, status, retryable := guardErrorCode(scanErr), 0, false
	var guardErr *GuardError
	if errors.As(scanErr, &guardErr) {
		status, retryable = guardErr.HTTPStatus, guardErr.Retryable
	}
	if code == "" {
		code = ErrorCodeInvalidResponse
	}
	return s.finishProbe(endpoint.ID, started, ProbeResult{Status: "failed", ErrorCode: code, Message: "审计节点模型调用或输出校验失败", HTTPStatus: status, Retryable: retryable, TokenApplied: tokenApplied})
}

func (s *PromptService) resolveProbeEndpoint(input UpdateEndpoint) (ActiveEndpoint, bool, error) {
	protocol := strings.TrimSpace(input.Protocol)
	if protocol == "" {
		protocol = EndpointProtocolOpenAICompatible
	}
	adapter := strings.TrimSpace(input.Adapter)
	if adapter == "" {
		if isInternalEndpointProtocol(protocol) {
			adapter = EndpointAdapterGenericLLM
		} else {
			adapter = EndpointAdapterQwen3Guard
		}
	}
	baseURL := ""
	if protocol == EndpointProtocolOpenAICompatible || protocol == JevProtocol {
		var err error
		baseURL, err = normalizeAuditEndpointURL(protocol, input.BaseURL)
		if err != nil {
			return ActiveEndpoint{}, false, err
		}
	}
	token := strings.TrimSpace(input.Token)
	if input.ClearToken || isInternalEndpointProtocol(protocol) {
		token = ""
	} else if token == "" {
		if cfg, ok := s.config.Active(); ok {
			for _, endpoint := range cfg.Endpoints {
				if endpoint.ID != strings.TrimSpace(input.ID) {
					continue
				}
				// Reuse a stored credential only when the probe targets the same
				// normalized base URL. Otherwise an admin probe could exfiltrate
				// the Guard token to an attacker-controlled HTTPS host.
				storedProtocol := strings.TrimSpace(endpoint.Protocol)
				if storedProtocol == "" {
					storedProtocol = "openai_compatible"
				}
				if endpoint.BaseURL == baseURL && storedProtocol == protocol {
					token = endpoint.Token
				}
				break
			}
		}
	}
	model := strings.TrimSpace(input.Model)
	if model == "" {
		switch protocol {
		case JevProtocol:
			model = DefaultJevModel
		case EndpointProtocolAntigravityInternal:
			model = DefaultAntigravityAuditModel
		case EndpointProtocolOpenAIInternal:
			model = DefaultOpenAIInternalAuditModel
		default:
			model = DefaultGuardModel
		}
	}
	timeout := input.TimeoutMS
	if timeout == 0 {
		timeout = DefaultTimeoutMS
	}
	limit := input.InputLimit
	if limit == 0 {
		limit = DefaultInputLimit
	}
	storage := storageConfig{Enabled: false, BlockingAuditMode: BlockingAuditModeFull, BackgroundAuditMode: BackgroundAuditModeOff, Strategy: "priority", WorkerCount: DefaultWorkerCount, PromptChunkConcurrency: DefaultPromptChunkConcurrency, QueueCapacity: DefaultQueueCapacity, Scanners: append([]string(nil), AllScannerIDs...), AllGroups: true,
		Endpoints: []StorageEndpoint{{ID: strings.TrimSpace(input.ID), Name: strings.TrimSpace(input.Name), Protocol: protocol, Adapter: adapter, BaseURL: baseURL, Model: model, AccountID: input.AccountID, TimeoutMS: timeout, InputLimit: limit}}}
	if storage.Endpoints[0].ID == "" {
		storage.Endpoints[0].ID = "probe"
	}
	if storage.Endpoints[0].Name == "" {
		storage.Endpoints[0].Name = "Probe"
	}
	if err := validateStorageConfig(storage); err != nil {
		return ActiveEndpoint{}, false, err
	}
	return ActiveEndpoint{ID: storage.Endpoints[0].ID, Name: storage.Endpoints[0].Name, Protocol: protocol, Adapter: adapter, BaseURL: baseURL, Model: model, AccountID: input.AccountID, Token: token, TimeoutMS: timeout, InputLimit: limit, Enabled: true}, token != "", nil
}

func (s *PromptService) finishProbe(id string, started time.Time, result ProbeResult) ProbeResult {
	result.CheckedAt = s.clock.Now()
	result.LatencyMS = int(result.CheckedAt.Sub(started).Milliseconds())
	if result.OK {
		LogInfo(EventProbeFinished, map[string]any{"guard_endpoint_id": id, "status": result.Status, "latency_ms": result.LatencyMS, "http_status": result.HTTPStatus})
	} else {
		LogWarn(EventProbeFailed, map[string]any{"guard_endpoint_id": id, "status": result.Status, "latency_ms": result.LatencyMS, "http_status": result.HTTPStatus, "error_code": result.ErrorCode, "retryable": result.Retryable})
	}
	s.probeMu.Lock()
	s.probes[id] = result
	s.probeMu.Unlock()
	return result
}

func (s *PromptService) probeSnapshot() map[string]ProbeResult {
	s.probeMu.RLock()
	defer s.probeMu.RUnlock()
	result := make(map[string]ProbeResult, len(s.probes))
	for id, probe := range s.probes {
		result[id] = probe
	}
	return result
}

func (s *PromptService) ListEvents(ctx context.Context, filter EventFilter, page, pageSize int) (*EventPage, error) {
	return s.repo.ListEvents(ctx, filter, page, pageSize)
}
func (s *PromptService) GetEvent(ctx context.Context, id int64) (*Event, error) {
	return s.repo.GetEvent(ctx, id)
}

func (s *PromptService) ListAdaptiveSamples(ctx context.Context, status string, page, pageSize int) (*AdaptiveSamplePage, error) {
	return s.repo.ListAdaptiveSamples(ctx, status, page, pageSize)
}

func (s *PromptService) ReviewAdaptiveSample(ctx context.Context, id, actorID int64, request AdaptiveReviewRequest) (*AdaptiveSample, error) {
	return s.repo.ReviewAdaptiveSample(ctx, id, actorID, request)
}

func (s *PromptService) DeleteEvent(ctx context.Context, id int64) (*DeleteResult, error) {
	result, err := s.repo.DeleteEvent(ctx, id)
	if err == nil {
		s.deletePayloads(ctx, result.JobIDs)
	}
	return result, err
}
func (s *PromptService) DeleteEventsByIDs(ctx context.Context, ids []int64) (*DeleteResult, error) {
	result, err := s.repo.DeleteEventsByIDs(ctx, ids)
	if err == nil {
		s.deletePayloads(ctx, result.JobIDs)
	}
	return result, err
}

type deleteClaims struct {
	FilterHash    string    `json:"filter_hash"`
	SnapshotMaxID int64     `json:"snapshot_max_id"`
	AdminID       int64     `json:"admin_id"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func (s *PromptService) PreviewDelete(ctx context.Context, filter EventFilter, adminID int64) (*DeletePreview, error) {
	preview, err := s.repo.PreviewDelete(ctx, filter)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	expires := now.Add(5 * time.Minute)
	claimsRaw, _ := json.Marshal(deleteClaims{FilterHash: preview.FilterHash, SnapshotMaxID: preview.SnapshotMaxID, AdminID: adminID, IssuedAt: now, ExpiresAt: expires})
	token, err := s.config.Encrypt(string(claimsRaw))
	if err != nil {
		return nil, err
	}
	preview.ConfirmationToken, preview.ExpiresAt = token, expires
	LogInfo(EventDeletePreviewed, map[string]any{"user_id": adminID, "status": "previewed"})
	return preview, nil
}

type DeleteByFilterRequest struct {
	Filter            EventFilter `json:"filter"`
	SnapshotMaxID     int64       `json:"snapshot_max_id"`
	FilterHash        string      `json:"filter_hash"`
	ConfirmationToken string      `json:"confirmation_token"`
	Confirm           bool        `json:"confirm"`
}

func (s *PromptService) DeleteByFilter(ctx context.Context, request DeleteByFilterRequest, adminID int64) (*DeleteResult, error) {
	if !request.Confirm {
		return nil, errors.New("prompt audit filter delete requires confirm=true")
	}
	plain, err := s.config.Decrypt(strings.TrimSpace(request.ConfirmationToken))
	if err != nil {
		return nil, errors.New("prompt audit confirmation token invalid")
	}
	var claims deleteClaims
	if json.Unmarshal([]byte(plain), &claims) != nil {
		return nil, errors.New("prompt audit confirmation token invalid")
	}
	computed := FilterHash(request.Filter, request.SnapshotMaxID)
	if claims.AdminID != adminID || claims.SnapshotMaxID != request.SnapshotMaxID || claims.FilterHash != request.FilterHash || request.FilterHash != computed || !s.clock.Now().Before(claims.ExpiresAt) {
		return nil, errors.New("prompt audit confirmation token does not match deletion request")
	}
	result, err := s.repo.DeleteEventsByFilter(ctx, request.Filter, request.SnapshotMaxID, 200)
	if err == nil {
		s.deletePayloads(ctx, result.JobIDs)
		LogWarn(EventEventsFilterDeleted, map[string]any{"user_id": adminID, "status": "deleted"})
	}
	return result, err
}

func (s *PromptService) deletePayloads(ctx context.Context, jobIDs []int64) {
	for _, id := range jobIDs {
		_ = s.payload.Delete(ctx, id)
	}
}

func parseTimeQuery(value string) *time.Time {
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return nil
	}
	parsed = parsed.UTC()
	return &parsed
}
