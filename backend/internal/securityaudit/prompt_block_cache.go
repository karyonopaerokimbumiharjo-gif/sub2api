package securityaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	promptBlockKeyPrefix = "sub2api:prompt_audit:block:v1:"
	promptRiskKeyPrefix  = "sub2api:prompt_audit:risk:v1:"
	promptBlockTTL       = 30 * 24 * time.Hour
	promptRiskTTL        = 24 * time.Hour
)

type PromptBlockCache interface {
	MatchBlocked(ctx context.Context, req Request, snapshot PromptSnapshot) (string, bool, error)
	RememberBlocked(ctx context.Context, req Request, snapshot PromptSnapshot) error
	RiskActive(ctx context.Context, req Request) (bool, error)
}

func (s *RedisPayloadStore) MatchBlocked(ctx context.Context, req Request, snapshot PromptSnapshot) (string, bool, error) {
	if s == nil || s.client == nil {
		return "", false, fmt.Errorf("prompt block cache unavailable")
	}
	fields := make([]string, 0, len(snapshot.SegmentFingerprints)+1)
	if snapshot.PromptHash != "" {
		fields = append(fields, "full:"+snapshot.PromptHash)
	}
	for _, fingerprint := range snapshot.SegmentFingerprints {
		if fingerprint != "" {
			fields = append(fields, "segment:"+fingerprint)
		}
	}
	if len(fields) == 0 {
		return "", false, nil
	}
	values, err := s.client.HMGet(ctx, promptBlockCacheKey(req), fields...).Result()
	if err != nil {
		return "", false, err
	}
	for index, value := range values {
		if value == nil {
			continue
		}
		if strings.HasPrefix(fields[index], "full:") {
			return "full_prompt_fingerprint", true, nil
		}
		return "violating_segment_fingerprint", true, nil
	}
	return "", false, nil
}

func (s *RedisPayloadStore) RememberBlocked(ctx context.Context, req Request, snapshot PromptSnapshot) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("prompt block cache unavailable")
	}
	fields := make(map[string]any, len(snapshot.SegmentFingerprints)+1)
	if snapshot.PromptHash != "" {
		fields["full:"+snapshot.PromptHash] = "1"
	}
	// Mark a segment only when the classifier saw exactly one logical segment.
	// Marking every segment of a multi-message prompt would poison benign system
	// or assistant context and create broad false positives. Multi-segment Blocks
	// still get exact-prompt protection plus the temporary user risk state.
	if len(snapshot.SegmentFingerprints) == 1 && snapshot.SegmentFingerprints[0] != "" {
		fields["segment:"+snapshot.SegmentFingerprints[0]] = "1"
	}
	if len(fields) == 0 {
		return nil
	}
	_, err := s.client.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		blockKey := promptBlockCacheKey(req)
		pipe.HSet(ctx, blockKey, fields)
		pipe.Expire(ctx, blockKey, promptBlockTTL)
		pipe.Set(ctx, promptRiskCacheKey(req), "1", promptRiskTTL)
		return nil
	})
	return err
}

func (s *RedisPayloadStore) RiskActive(ctx context.Context, req Request) (bool, error) {
	if s == nil || s.client == nil {
		return false, fmt.Errorf("prompt risk cache unavailable")
	}
	count, err := s.client.Exists(ctx, promptRiskCacheKey(req)).Result()
	return count > 0, err
}

func (s *RedisPayloadStore) ForgetAllowed(ctx context.Context, req Request, configVersion int64, fingerprints []string) error {
	if s == nil || s.client == nil || len(fingerprints) == 0 {
		return nil
	}
	return s.client.HDel(ctx, promptSegmentAllowCacheKey(req, configVersion), fingerprints...).Err()
}

func promptBlockCacheKey(req Request) string {
	return promptBlockKeyPrefix + promptRiskScopeDigest(req)
}

func promptRiskCacheKey(req Request) string {
	return promptRiskKeyPrefix + promptRiskScopeDigest(req)
}

func promptRiskScopeDigest(req Request) string {
	principal := "anonymous"
	switch {
	case req.UserID > 0:
		principal = "user:" + strconv.FormatInt(req.UserID, 10)
	case strings.TrimSpace(req.UserEmail) != "":
		principal = "email:" + strings.ToLower(strings.TrimSpace(req.UserEmail))
	case req.APIKeyID > 0:
		principal = "key:" + strconv.FormatInt(req.APIKeyID, 10)
	}
	scope := principal + "|provider:" + strings.ToLower(strings.TrimSpace(req.Provider))
	digest := sha256.Sum256([]byte(scope))
	return hex.EncodeToString(digest[:])
}

func requestFromSnapshot(snapshot PromptSnapshot) Request {
	return Request{
		RequestID: snapshot.RequestID, UserID: snapshot.UserID, Username: snapshot.UsernameSnapshot,
		UserEmail: snapshot.UserEmailSnapshot, APIKeyID: snapshot.APIKeyID, APIKeyName: snapshot.APIKeyNameSnapshot,
		GroupID: cloneInt64Ptr(snapshot.GroupID), GroupName: snapshot.GroupName, Provider: snapshot.Provider,
		Endpoint: snapshot.Endpoint, Protocol: snapshot.Protocol, Model: snapshot.Model, Stage: snapshot.Stage,
	}
}
