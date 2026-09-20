package securityaudit

import "context"

type promptInvocationContextKey struct{}

type promptInvocationContext struct {
	RequestID     string
	ConfigVersion int64
}

func withPromptInvocationContext(ctx context.Context, requestID string, configVersion int64) context.Context {
	return context.WithValue(ctx, promptInvocationContextKey{}, promptInvocationContext{
		RequestID: requestID, ConfigVersion: configVersion,
	})
}

func promptInvocationContextFrom(ctx context.Context) (promptInvocationContext, bool) {
	if ctx == nil {
		return promptInvocationContext{}, false
	}
	value, ok := ctx.Value(promptInvocationContextKey{}).(promptInvocationContext)
	return value, ok
}
