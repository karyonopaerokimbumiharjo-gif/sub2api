package repository

import (
	"context"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/lib/pq"
)

var _ service.SecurityAuditRevocationStore = (*settingRepository)(nil)

func (r *settingRepository) SaveSecurityAuditRevocations(ctx context.Context, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	_, err := r.client.ExecContext(ctx, `INSERT INTO security_audit_revocations(key) SELECT DISTINCT unnest($1::text[]) ON CONFLICT(key) DO NOTHING`, pq.Array(keys))
	return err
}
func (r *settingRepository) LoadSecurityAuditRevocations(ctx context.Context, keys []string) (map[string]bool, error) {
	found := make(map[string]bool)
	if len(keys) == 0 {
		return found, nil
	}
	rows, err := r.client.QueryContext(ctx, `SELECT key FROM security_audit_revocations WHERE key = ANY($1::text[])`, pq.Array(keys))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		found[key] = true
	}
	return found, rows.Err()
}
