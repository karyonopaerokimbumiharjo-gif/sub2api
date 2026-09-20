package repository

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/stretchr/testify/require"
)

// Opt-in against a disposable database after the production schema rehearsal.
// The database name guard prevents accidental use against the live service.
func TestSecurityAuditRevocationPostgresPersistence(t *testing.T) {
	dsn := os.Getenv("SUB2API_REVOCATION_TEST_DSN")
	if dsn == "" {
		t.Skip("explicit rehearsal database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	open := func() (*settingRepository, *sql.DB) {
		db, err := sql.Open("postgres", dsn)
		require.NoError(t, err)
		t.Cleanup(func() { _ = db.Close() })
		var name string
		require.NoError(t, db.QueryRowContext(ctx, "SELECT current_database()").Scan(&name))
		require.True(t, strings.HasSuffix(name, "_rehearsal"), "a disposable rehearsal database is required")
		client := dbent.NewClient(dbent.Driver(entsql.OpenDB(dialect.Postgres, db)))
		return &settingRepository{client: client}, db
	}
	first, db := open()
	key := fmt.Sprintf("prompt_guard:synthetic-persistence-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		cleanup, err := sql.Open("postgres", dsn)
		if err == nil {
			defer func() { _ = cleanup.Close() }()
			_, _ = cleanup.Exec("DELETE FROM security_audit_revocations WHERE key = $1", key)
		}
	})
	require.NoError(t, first.SaveSecurityAuditRevocations(ctx, []string{key, key}))
	require.NoError(t, first.SaveSecurityAuditRevocations(ctx, []string{key}))
	var count int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM security_audit_revocations WHERE key = $1", key).Scan(&count))
	require.Equal(t, 1, count)
	require.NoError(t, db.Close())
	_, err := first.LoadSecurityAuditRevocations(ctx, []string{key})
	require.Error(t, err, "an unavailable database must not look like an unrevoked session")
	second, _ := open()
	found, err := second.LoadSecurityAuditRevocations(ctx, []string{key, key + "-unrelated"})
	require.NoError(t, err)
	require.Equal(t, map[string]bool{key: true}, found)
	_, err = second.LoadSecurityAuditRevocations(ctx, nil)
	require.NoError(t, err)
}
