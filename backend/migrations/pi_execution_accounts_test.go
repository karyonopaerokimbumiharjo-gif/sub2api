package migrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

// Exercise PostgreSQL's real CHECK/NULL semantics: mocked account repositories
// cannot catch a stale production constraint rejecting a valid OAuth exchange.
func TestPiExecutionAccountMigration(t *testing.T) {
	dsn := os.Getenv("PROMPT_AUDIT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PROMPT_AUDIT_TEST_POSTGRES_DSN is not set")
	}
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := db.Conn(ctx)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.ExecContext(ctx, `CREATE TEMP TABLE accounts (
		id BIGSERIAL PRIMARY KEY, platform TEXT, type TEXT, parent_account_id BIGINT,
		proxy_id BIGINT, credentials JSONB, deleted_at TIMESTAMPTZ,
		CONSTRAINT accounts_cpa_backend_required CHECK (deleted_at IS NOT NULL OR (
		platform='openai' AND type='apikey' AND parent_account_id IS NULL AND proxy_id IS NULL
		AND credentials->>'base_url' IN ('http://cpa:8317','http://cpa:8317/','http://cpa:8317/v1','http://cpa:8317/v1/')) IS TRUE))`)
	require.NoError(t, err)
	pi := map[string]any{"harness_kind": "pi", "pi_owner_user_id": "1", "access_token": "synthetic-access", "refresh_token": "synthetic-refresh", "chatgpt_account_id": "synthetic-account"}
	insert := func(kind string, creds map[string]any) error {
		raw, e := json.Marshal(creds)
		require.NoError(t, e)
		_, e = conn.ExecContext(ctx, `INSERT INTO accounts(platform,type,credentials) VALUES('openai',$1,$2)`, kind, string(raw))
		return e
	}
	// Reproduce the exact live failure before migration.
	require.ErrorContains(t, insert("oauth", pi), "accounts_cpa_backend_required")
	migration, err := FS.ReadFile("244_allow_native_pi_accounts.sql")
	require.NoError(t, err)
	for i := 0; i < 2; i++ {
		_, err = conn.ExecContext(ctx, string(migration))
		require.NoError(t, err)
	}
	require.NoError(t, insert("oauth", pi))
	require.ErrorContains(t, insert("oauth", pi), "accounts_native_pi_identity_unique")
	_, err = conn.ExecContext(ctx, `DELETE FROM accounts WHERE type='oauth'`)
	require.NoError(t, err)
	require.NoError(t, insert("apikey", map[string]any{"base_url": "http://cpa:8317"}))
	for _, field := range []string{"harness_kind", "pi_owner_user_id", "access_token", "refresh_token", "chatgpt_account_id"} {
		for _, value := range []any{nil, "", " "} {
			bad := map[string]any{}
			for k, v := range pi {
				bad[k] = v
			}
			bad[field] = value
			require.Error(t, insert("oauth", bad), "field %s must fail closed", field)
		}
	}
	for _, owner := range []string{"0", "-1", "not-a-user", "9223372036854775808"} {
		bad := map[string]any{}
		for k, v := range pi {
			bad[k] = v
		}
		bad["pi_owner_user_id"] = owner
		require.Error(t, insert("oauth", bad))
	}
	pi["base_url"] = "https://untrusted.invalid"
	require.Error(t, insert("oauth", pi))
	require.Error(t, insert("apikey", map[string]any{"base_url": "https://untrusted.invalid"}))
	require.Error(t, insert("oauth", map[string]any{"access_token": "direct"}))
	delete(pi, "base_url")
	require.NoError(t, insert("oauth", pi))
	_, err = conn.ExecContext(ctx, `UPDATE accounts SET proxy_id=1 WHERE type='oauth'`)
	require.Error(t, err)
	_, err = conn.ExecContext(ctx, `UPDATE accounts SET parent_account_id=1 WHERE type='oauth'`)
	require.Error(t, err)
}
