package service

import "context"

type cpaUserImportContextKey struct{}

// WithCPAUserImport marks an explicit user import. Unlike an internal token
// refresh or backend switch, an import without a selected proxy must not
// restore a historical credential-specific proxy override.
func WithCPAUserImport(ctx context.Context) context.Context {
	return context.WithValue(ctx, cpaUserImportContextKey{}, true)
}

func isCPAUserImport(ctx context.Context) bool {
	marked, _ := ctx.Value(cpaUserImportContextKey{}).(bool)
	return marked
}

func applyCPAUserImportProxyDefault(ctx context.Context, payload map[string]any, runtime *CPACredentialUpdate) {
	if !isCPAUserImport(ctx) || (runtime != nil && runtime.ProxyID != nil && *runtime.ProxyID > 0) {
		return
	}
	// Empty means use CPA's configured default route. It deliberately does
	// not mean forced direct access or an implicit choice of another proxy.
	payload["proxy_url"] = ""
	payload["sub2_proxy_id"] = nil
}
