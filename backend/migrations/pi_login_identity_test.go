package migrations

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
)

func TestPiLoginIdentitySeparatesTeamMembers(t *testing.T) {
	dsn := os.Getenv("PROMPT_AUDIT_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("test PostgreSQL is not configured")
	}
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := db.Conn(ctx)
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.ExecContext(ctx, `CREATE TEMP TABLE accounts(id BIGSERIAL PRIMARY KEY,platform text,type text,credentials jsonb,deleted_at timestamptz)`)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, `CREATE UNIQUE INDEX accounts_native_pi_identity_unique ON accounts((credentials->>'chatgpt_account_id'))`)
	require.NoError(t, err)
	migration, err := FS.ReadFile("253_pi_login_identity.sql")
	require.NoError(t, err)
	for i := 0; i < 2; i++ {
		_, err = conn.ExecContext(ctx, string(migration))
		require.NoError(t, err)
	}
	insert := func(user, email string) error {
		claims, _ := json.Marshal(map[string]any{"https://api.openai.com/auth": map[string]any{"chatgpt_user_id": user}, "sub": user})
		creds, _ := json.Marshal(map[string]any{"harness_kind": "pi", "chatgpt_account_id": "shared-team", "email": email, "access_token": "e30." + base64.RawURLEncoding.EncodeToString(claims) + ".fixture"})
		_, err := conn.ExecContext(ctx, `INSERT INTO accounts(platform,type,credentials) VALUES('openai','oauth',$1)`, string(creds))
		return err
	}
	require.NoError(t, insert("gpt-member", "gpt@example.com"))
	require.NoError(t, insert("use-member", "use@example.com"))
	require.ErrorContains(t, insert("gpt-member", "renamed@example.com"), "accounts_native_pi_login_identity_unique")
	var count int
	require.NoError(t, conn.QueryRowContext(ctx, `SELECT count(*) FROM accounts`).Scan(&count))
	require.Equal(t, 2, count)
}
