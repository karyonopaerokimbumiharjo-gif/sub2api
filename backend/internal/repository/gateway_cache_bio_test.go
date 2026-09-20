package repository

import (
	"context"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestGatewayCacheBioPromptBlockUsesRollingTTL(t *testing.T) {
	redisServer := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	store, ok := NewGatewayCache(client).(service.BioPromptBlockStore)
	require.True(t, ok)

	ctx := context.Background()
	key := "user:1:provider:openai:policy:bio_policy:prompt:test"
	redisKey := bioPromptBlockPrefix + key
	require.NoError(t, store.SetBioPromptBlocked(ctx, key, 30*24*time.Hour))
	value, err := redisServer.Get(redisKey)
	require.NoError(t, err)
	require.Equal(t, "1", value)
	require.Equal(t, 30*24*time.Hour, redisServer.TTL(redisKey))

	require.NoError(t, store.SetBioPromptBlocked(ctx, key, 30*24*time.Hour))
	value, err = redisServer.Get(redisKey)
	require.NoError(t, err)
	require.Equal(t, "2", value)
	require.Equal(t, 90*24*time.Hour, redisServer.TTL(redisKey))
}
