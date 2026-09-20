package repository

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyRepository_GetByKeyForAuth_PreservesPromptAuditBypass_SQLite(t *testing.T) {
	repo, client := newAPIKeyRepoSQLite(t)
	ctx := context.Background()

	user, err := client.User.Create().
		SetEmail("getbykey-auth-prompt-bypass-unit@test.com").
		SetPasswordHash("test-password-hash").
		SetRole(service.RoleUser).
		SetStatus(service.StatusActive).
		SetPromptAuditBypass(true).
		Save(ctx)
	require.NoError(t, err)

	key := &service.APIKey{
		UserID: user.ID,
		Key:    "sk-getbykey-auth-prompt-bypass-unit",
		Name:   "Prompt Audit Bypass Key Unit",
		Status: service.StatusActive,
	}
	require.NoError(t, repo.Create(ctx, key))

	got, err := repo.GetByKeyForAuth(ctx, key.Key)
	require.NoError(t, err)
	require.NotNil(t, got.User)
	require.True(t, got.User.PromptAuditBypass,
		"the authentication projection must carry the administrator-managed bypass flag")
}
