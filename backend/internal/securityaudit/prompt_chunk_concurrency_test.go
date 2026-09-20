package securityaudit

import (
	"context"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestScanChunksConcurrentlyUsesBoundedParallelismAndStableOrder(t *testing.T) {
	chunks := []string{"a", "b", "c", "d", "e"}
	release := make(chan struct{})
	started := make(chan struct{}, len(chunks))
	var active atomic.Int32
	var maximum atomic.Int32
	done := make(chan struct {
		results []*NormalizedResult
		err     error
	}, 1)

	go func() {
		results, err := scanChunksConcurrently(context.Background(), chunks, 4, func(ctx context.Context, index int, _ string) (*NormalizedResult, error) {
			current := active.Add(1)
			for {
				seen := maximum.Load()
				if current <= seen || maximum.CompareAndSwap(seen, current) {
					break
				}
			}
			started <- struct{}{}
			defer active.Add(-1)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true, Cause: ctx.Err()}
			}
			return &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow, GuardEndpointID: strconv.Itoa(index)}, nil
		})
		done <- struct {
			results []*NormalizedResult
			err     error
		}{results: results, err: err}
	}()

	for index := 0; index < 4; index++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("bounded worker pool did not start four chunks")
		}
	}
	require.Equal(t, int32(4), maximum.Load())
	close(release)

	select {
	case outcome := <-done:
		require.NoError(t, outcome.err)
		require.Len(t, outcome.results, len(chunks))
		for index, result := range outcome.results {
			require.Equal(t, strconv.Itoa(index), result.GuardEndpointID)
		}
	case <-time.After(time.Second):
		t.Fatal("concurrent chunk scan did not finish")
	}
}

func TestScanChunksConcurrentlyKeepsBlockWhenCancellingSiblings(t *testing.T) {
	results, err := scanChunksConcurrently(context.Background(), []string{"block", "sibling-1", "sibling-2", "sibling-3"}, 4, func(ctx context.Context, index int, _ string) (*NormalizedResult, error) {
		if index == 0 {
			return &NormalizedResult{Decision: EventCritical, RiskLevel: RiskCritical, Action: ActionBlock}, nil
		}
		<-ctx.Done()
		return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true, Cause: ctx.Err()}
	})

	require.NoError(t, err)
	require.Len(t, results, 1)
	require.Equal(t, ActionBlock, results[0].Action)
}
