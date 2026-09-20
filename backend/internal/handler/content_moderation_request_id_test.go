package handler

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/stretchr/testify/require"
)

func TestContentModerationRequestIDMatchesUsageBillingKey(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxkey.RequestID, "server-request-1")
	ctx = context.WithValue(ctx, ctxkey.ClientRequestID, "client-request-1")
	require.Equal(t, "client:client-request-1", contentModerationRequestID(ctx))

	serverOnly := context.WithValue(context.Background(), ctxkey.RequestID, "server-request-2")
	require.Equal(t, "local:server-request-2", contentModerationRequestID(serverOnly))
	require.Empty(t, contentModerationRequestID(context.Background()))
}
