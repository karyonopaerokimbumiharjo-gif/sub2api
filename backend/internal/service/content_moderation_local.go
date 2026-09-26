package service

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"
)

// Shared response controls do not invoke the native model when local auditing
// owns a request. Local hits retain their original event source.
func (s *ContentModerationService) LocalBlockResponse(ctx context.Context) (int, string) {
	if s == nil {
		return 0, ""
	}
	snapshot, err := s.loadRuntimeSnapshot(ctx)
	if err != nil {
		return 0, ""
	}
	return snapshot.config.BlockStatus, snapshot.config.BlockMessage
}

func (s *ContentModerationService) CheckLocalKeywords(ctx context.Context, input ContentModerationCheckInput, text string) (*ContentModerationDecision, error) {
	if s == nil {
		return nil, nil
	}
	snapshot, err := s.loadRuntimeSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	cfg := snapshot.config
	if cfg.KeywordBlockingMode == ContentModerationKeywordModeAPIOnly {
		return nil, nil
	}
	keyword, hit := snapshot.matchBlockedKeyword(text)
	if !hit {
		if cfg.KeywordBlockingMode == ContentModerationKeywordModeKeywordOnly {
			if cfg.RecordNonHits {
				log := s.buildLog(input, cfg, ContentModerationActionAllow, false, "", 0, nil, text, nil, nil, "")
				log.EngineMeta = &ContentModerationEngineMeta{Engine: "local-keyword", AuditSource: "legacy", RulesVersion: "literal-keywords-v1"}
				s.enqueueRecord(input, cfg, log, "", false, false)
			}
			return &ContentModerationDecision{Allowed: true, Action: "keyword_only"}, nil
		}
		return nil, nil
	}
	scores := map[string]float64{contentModerationKeywordCategory: 1}
	log := s.buildLog(input, cfg, ContentModerationActionKeywordBlock, true, contentModerationKeywordCategory, 1, scores, text, nil, nil, "")
	log.MatchedKeyword = keyword
	log.EngineMeta = &ContentModerationEngineMeta{Engine: "local-keyword", AuditSource: "legacy", RulesVersion: "literal-keywords-v1"}
	s.enqueueRecord(input, cfg, log, "", false, true)
	return &ContentModerationDecision{Blocked: true, Flagged: true, StatusCode: cfg.BlockStatus, Message: cfg.BlockMessage, Action: ContentModerationActionKeywordBlock}, nil
}

// Enforcement events already live in prompt_audit_events. This companion row
// is used only for shared notification/violation accounting, never a second
// audit event in the unified feed. Concurrent foreground/background findings
// of the same request/content notify and count once.
func (s *ContentModerationService) RecordLocalAuditHit(ctx context.Context, input ContentModerationCheckInput, full, audited, source, backend string, scores map[string]float64, blocked bool) {
	if s == nil || s.repo == nil {
		return
	}
	snapshot, err := s.loadRuntimeSnapshot(ctx)
	if err != nil {
		return
	}
	dedupe := fmt.Sprintf("%d:%d:%s:%x", input.UserID, input.APIKeyID, input.RequestID, sha256.Sum256([]byte(full)))
	now := time.Now()
	s.localHitMu.Lock()
	if s.localHits == nil {
		s.localHits = map[string]time.Time{}
	}
	for key, until := range s.localHits {
		if until.Before(now) {
			delete(s.localHits, key)
		}
	}
	if until, ok := s.localHits[dedupe]; ok && until.After(now) {
		s.localHitMu.Unlock()
		return
	}
	if len(s.localHits) < 4096 {
		s.localHits[dedupe] = now.Add(10 * time.Minute)
	}
	s.localHitMu.Unlock()
	category := "local_policy"
	highest := 0.0
	for key, score := range scores {
		if score > highest {
			category, highest = key, score
		}
	}
	action := ContentModerationActionAllow
	if blocked {
		action = ContentModerationActionBlock
	}
	log := s.buildLog(input, snapshot.config, action, true, category, highest, scores, audited, nil, nil, "")
	log.FullPrompt = trimRunes(redactContentModerationSecrets(full), maxNativeAuditEvidenceRunes)
	log.EngineMeta = &ContentModerationEngineMeta{Engine: backend, AuditSource: source, EventRole: "notification"}
	s.enqueueRecord(input, snapshot.config, log, "", false, true)
}

// Configuration/unavailable failures are events too, but never violations.
func (s *ContentModerationService) RecordNativeUnavailable(ctx context.Context, input ContentModerationCheckInput) {
	if s == nil || s.repo == nil {
		return
	}
	cfg, err := s.loadConfig(ctx)
	if err != nil {
		cfg = defaultContentModerationConfig()
	}
	cfg = cfg.effectiveEngine(cfg.Engine)
	log := s.buildLog(input, cfg, ContentModerationActionError, false, "", 0, nil, "", nil, nil, "native_audit_unavailable")
	log.EngineMeta = &ContentModerationEngineMeta{Engine: cfg.Engine, AuditSource: "native"}
	s.enqueueRecord(input, cfg, log, "", false, false)
}
