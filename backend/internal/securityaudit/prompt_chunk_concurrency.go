package securityaudit

import (
	"context"
	"errors"
	"sort"
	"sync"
)

type chunkScanOutcome struct {
	index  int
	result *NormalizedResult
	err    error
}

// scanChunksConcurrently runs one bounded worker pool for the chunks of one
// prompt. Results are returned in chunk order even though the scanners finish
// in arbitrary order. A block cancels remaining work but is retained as the
// decisive result; any scanner error still fails closed when no block exists.
func scanChunksConcurrently(
	ctx context.Context,
	chunks []string,
	concurrency int,
	scan func(context.Context, int, string) (*NormalizedResult, error),
) ([]*NormalizedResult, error) {
	if len(chunks) == 0 {
		return nil, nil
	}
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > len(chunks) {
		concurrency = len(chunks)
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan int)
	outcomes := make(chan chunkScanOutcome, len(chunks))
	var workers sync.WaitGroup
	for worker := 0; worker < concurrency; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case <-runCtx.Done():
					return
				case index, ok := <-jobs:
					if !ok {
						return
					}
					result, err := scan(runCtx, index, chunks[index])
					outcomes <- chunkScanOutcome{index: index, result: result, err: err}
					if err != nil || (result != nil && result.Action == ActionBlock) {
						cancel()
					}
				}
			}
		}()
	}

dispatch:
	for index := range chunks {
		select {
		case <-runCtx.Done():
			break dispatch
		case jobs <- index:
		}
	}
	close(jobs)
	workers.Wait()
	close(outcomes)

	collected := make([]chunkScanOutcome, 0, len(chunks))
	var firstErr error
	blocked := false
	for outcome := range outcomes {
		if outcome.err != nil {
			// Cancellation is expected for siblings after a block or the first
			// scanner error. Keep the original non-cancellation error.
			if firstErr == nil && !errors.Is(outcome.err, context.Canceled) {
				firstErr = outcome.err
			}
			continue
		}
		if outcome.result == nil {
			if firstErr == nil {
				firstErr = &GuardError{Code: ErrorCodeInvalidResponse}
			}
			continue
		}
		collected = append(collected, outcome)
		if outcome.result.Action == ActionBlock {
			blocked = true
		}
	}

	sort.Slice(collected, func(left, right int) bool {
		return collected[left].index < collected[right].index
	})
	results := make([]*NormalizedResult, 0, len(collected))
	for _, outcome := range collected {
		results = append(results, outcome.result)
	}
	if blocked {
		return results, nil
	}
	if firstErr != nil {
		return nil, firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true, Timeout: errors.Is(err, context.DeadlineExceeded), Cause: err}
	}
	if len(results) != len(chunks) {
		return nil, &GuardError{Code: ErrorCodeUnavailable, Retryable: true}
	}
	return results, nil
}
