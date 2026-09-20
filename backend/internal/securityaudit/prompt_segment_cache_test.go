package securityaudit

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestPromptSegmentAllowCacheScopesAndExpiresAllowFingerprints(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	store := NewRedisPayloadStore(client)
	ctx := context.Background()
	req := Request{UserID: 7, APIKeyID: 9, UserEmail: "audit@example.test", Provider: "openai", Model: "gpt-audit"}
	fingerprints := []string{"segment-a", "segment-b"}

	require.NoError(t, store.RememberAllowed(ctx, req, 11, fingerprints))
	known, err := store.KnownAllowed(ctx, req, 11, append(fingerprints, "missing"))
	require.NoError(t, err)
	require.Equal(t, map[string]struct{}{"segment-a": {}, "segment-b": {}}, known)

	ttl := server.TTL(promptSegmentAllowCacheKey(req, 11))
	require.Greater(t, ttl, 29*24*time.Hour)
	require.LessOrEqual(t, ttl, promptSegmentAllowTTL)

	for name, changed := range map[string]Request{
		"user":     {UserID: 8, APIKeyID: 9, UserEmail: req.UserEmail, Provider: req.Provider, Model: req.Model},
		"api key":  {UserID: 7, APIKeyID: 10, UserEmail: req.UserEmail, Provider: req.Provider, Model: req.Model},
		"provider": {UserID: 7, APIKeyID: 9, UserEmail: req.UserEmail, Provider: "other", Model: req.Model},
		"model":    {UserID: 7, APIKeyID: 9, UserEmail: req.UserEmail, Provider: req.Provider, Model: "other"},
	} {
		t.Run(name, func(t *testing.T) {
			isolated, err := store.KnownAllowed(ctx, changed, 11, fingerprints)
			require.NoError(t, err)
			require.Empty(t, isolated)
		})
	}
	changedVersion, err := store.KnownAllowed(ctx, req, 12, fingerprints)
	require.NoError(t, err)
	require.Empty(t, changedVersion)
}

func TestPromptBlockCacheScopesExactSegmentAndTemporaryRisk(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	store := NewRedisPayloadStore(client)
	ctx := context.Background()
	req := Request{UserID: 7, Provider: "openai"}
	snapshot := PromptSnapshot{PromptHash: "full-a", SegmentFingerprints: []string{"segment-a"}}

	require.NoError(t, store.RememberBlocked(ctx, req, snapshot))
	reason, matched, err := store.MatchBlocked(ctx, req, snapshot)
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "full_prompt_fingerprint", reason)

	reason, matched, err = store.MatchBlocked(ctx, req, PromptSnapshot{PromptHash: "other", SegmentFingerprints: []string{"segment-a"}})
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "violating_segment_fingerprint", reason)
	risk, err := store.RiskActive(ctx, req)
	require.NoError(t, err)
	require.True(t, risk)
	require.Greater(t, server.TTL(promptRiskCacheKey(req)), 23*time.Hour)

	_, matched, err = store.MatchBlocked(ctx, Request{UserID: 8, Provider: "openai"}, snapshot)
	require.NoError(t, err)
	require.False(t, matched)
	_, matched, err = store.MatchBlocked(ctx, Request{UserID: 7, Provider: "other"}, snapshot)
	require.NoError(t, err)
	require.False(t, matched)
}

func TestPromptBlockCacheDoesNotPoisonEverySegmentOfMultiSegmentBlock(t *testing.T) {
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	store := NewRedisPayloadStore(client)
	ctx := context.Background()
	req := Request{UserID: 7, Provider: "openai"}
	require.NoError(t, store.RememberBlocked(ctx, req, PromptSnapshot{PromptHash: "full-a", SegmentFingerprints: []string{"benign", "unknown-risk-segment"}}))

	_, matched, err := store.MatchBlocked(ctx, req, PromptSnapshot{PromptHash: "different", SegmentFingerprints: []string{"benign"}})
	require.NoError(t, err)
	require.False(t, matched)
}
