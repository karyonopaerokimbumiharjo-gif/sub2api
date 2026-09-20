package repository

import (
	"context"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCPASchedulerMetadataRetainsDestination(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()
	cache := NewSchedulerCache(client)
	bucket := service.SchedulerBucket{GroupID: 17, Platform: service.PlatformOpenAI, Mode: service.SchedulerModeSingle}
	token, err := cache.CaptureBucketWriteToken(ctx, bucket)
	require.NoError(t, err)
	account := service.Account{ID: 30, Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey, Status: service.StatusActive, Schedulable: true, Credentials: map[string]any{"base_url": "http://cpa:8317"}}
	require.NoError(t, cache.SetSnapshot(ctx, bucket, token, []service.Account{account}))
	accounts, hit, err := cache.GetSnapshot(ctx, bucket)
	require.NoError(t, err)
	require.True(t, hit)
	require.Len(t, accounts, 1)
	require.True(t, accounts[0].IsSchedulable(), "CPA account must remain eligible after the cache projection")
	account.Credentials["base_url"] = "https://api.openai.com"
	require.NoError(t, cache.SetSnapshot(ctx, bucket, token, []service.Account{account}))
	accounts, hit, err = cache.GetSnapshot(ctx, bucket)
	require.NoError(t, err)
	require.True(t, hit)
	require.False(t, accounts[0].IsSchedulable())
	// Old metadata does not contain the destination. Force a cache miss so the
	// caller reloads the database instead of misclassifying a valid account.
	value, err := client.Get(ctx, "sched:meta:cpa-v1:30").Result()
	require.NoError(t, err)
	require.NoError(t, client.Set(ctx, "sched:meta:30", value, 0).Err())
	require.NoError(t, client.Del(ctx, "sched:meta:cpa-v1:30").Err())
	_, hit, err = cache.GetSnapshot(ctx, bucket)
	require.NoError(t, err)
	require.False(t, hit)
}
