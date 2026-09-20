package securityaudit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	promptSegmentAllowKeyPrefix = "sub2api:prompt_audit:segment_allow:v1:"
	promptSegmentAllowTTL       = 30 * 24 * time.Hour
)

// PromptSegmentAllowCache stores only Allow results. Cache failure is handled
// by scanning all candidate context again; it can never make the audit narrower.
type PromptSegmentAllowCache interface {
	KnownAllowed(ctx context.Context, req Request, configVersion int64, fingerprints []string) (map[string]struct{}, error)
	RememberAllowed(ctx context.Context, req Request, configVersion int64, fingerprints []string) error
}

func (s *RedisPayloadStore) KnownAllowed(ctx context.Context, req Request, configVersion int64, fingerprints []string) (map[string]struct{}, error) {
	known := make(map[string]struct{}, len(fingerprints))
	if len(fingerprints) == 0 {
		return known, nil
	}
	if s == nil || s.client == nil {
		return nil, fmt.Errorf("prompt segment allow cache unavailable")
	}
	values, err := s.client.HMGet(ctx, promptSegmentAllowCacheKey(req, configVersion), fingerprints...).Result()
	if err != nil {
		return nil, err
	}
	for index, value := range values {
		if value != nil {
			known[fingerprints[index]] = struct{}{}
		}
	}
	return known, nil
}

func (s *RedisPayloadStore) RememberAllowed(ctx context.Context, req Request, configVersion int64, fingerprints []string) error {
	if len(fingerprints) == 0 {
		return nil
	}
	if s == nil || s.client == nil {
		return fmt.Errorf("prompt segment allow cache unavailable")
	}
	fields := make(map[string]any, len(fingerprints))
	for _, fingerprint := range fingerprints {
		if fingerprint = strings.TrimSpace(fingerprint); fingerprint != "" {
			fields[fingerprint] = "1"
		}
	}
	if len(fields) == 0 {
		return nil
	}
	key := promptSegmentAllowCacheKey(req, configVersion)
	_, err := s.client.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.HSet(ctx, key, fields)
		pipe.Expire(ctx, key, promptSegmentAllowTTL)
		return nil
	})
	return err
}

func promptSegmentAllowCacheKey(req Request, configVersion int64) string {
	scope := fmt.Sprintf("user=%d|key=%d|email=%s|provider=%s|model=%s|config=%d",
		req.UserID, req.APIKeyID, strings.ToLower(strings.TrimSpace(req.UserEmail)),
		strings.ToLower(strings.TrimSpace(req.Provider)), strings.ToLower(strings.TrimSpace(req.Model)), configVersion)
	digest := sha256.Sum256([]byte(scope))
	return promptSegmentAllowKeyPrefix + hex.EncodeToString(digest[:])
}
