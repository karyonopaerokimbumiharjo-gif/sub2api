package service

import "context"

type vpsLatencyContextKey struct{}

// VPS latency is request-handler entry to the FIRST upstream dispatch, including
// authentication, synchronous audit and queueing. It excludes upstream inference,
// browser/Cloudflare RTT and retries after the first dispatch.
func WithVPSLatency(ctx context.Context, milliseconds int) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if milliseconds < 0 {
		return ctx
	}
	return context.WithValue(ctx, vpsLatencyContextKey{}, milliseconds)
}

func VPSLatencyFromContext(ctx context.Context) *int {
	if ctx == nil {
		return nil
	}
	value, ok := ctx.Value(vpsLatencyContextKey{}).(int)
	if !ok || value < 0 {
		return nil
	}
	return &value
}
