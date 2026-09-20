package securityaudit

import (
	"context"
	"errors"
	"time"
)

type PromptAuditInvocation struct {
	RequestID            string
	ConfigVersion        int64
	GuardEndpointID      string
	GuardEndpointName    string
	Protocol             string
	Model                string
	AccountID            int64
	AccountNameSnapshot  string
	AccountEmailSnapshot string
	InputTokens          int
	OutputTokens         int
	CacheCreationTokens  int
	CacheReadTokens      int
	EstimatedCostUSD     float64
	PricingKnown         bool
	Status               string
	ErrorCode            string
	LatencyMS            int64
}

func (r *PostgreSQLRepository) RecordInvocation(ctx context.Context, value PromptAuditInvocation) error {
	if r == nil || r.db == nil {
		return errors.New("prompt audit database unavailable")
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO prompt_audit_invocations (
			request_id, config_version, guard_endpoint_id, guard_endpoint_name,
			protocol, model, account_id, account_name_snapshot, account_email_snapshot,
			input_tokens, output_tokens, cache_creation_tokens, cache_read_tokens,
			estimated_cost_usd, pricing_known, status, error_code, latency_ms
		) VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,0),$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
		value.RequestID, value.ConfigVersion, value.GuardEndpointID, value.GuardEndpointName,
		value.Protocol, value.Model, value.AccountID, value.AccountNameSnapshot, value.AccountEmailSnapshot,
		value.InputTokens, value.OutputTokens, value.CacheCreationTokens, value.CacheReadTokens,
		value.EstimatedCostUSD, value.PricingKnown, value.Status, value.ErrorCode, value.LatencyMS,
	)
	return err
}

func (r *PostgreSQLRepository) UsageOverview(ctx context.Context, now time.Time) (PromptAuditUsageOverview, error) {
	if r == nil || r.db == nil {
		return PromptAuditUsageOverview{}, errors.New("prompt audit database unavailable")
	}
	location := time.Local
	localNow := now.In(location)
	todayStart := time.Date(localNow.Year(), localNow.Month(), localNow.Day(), 0, 0, 0, 0, location)
	last7Start := localNow.AddDate(0, 0, -7)
	result := PromptAuditUsageOverview{}
	var err error
	if result.Today, err = r.usagePeriod(ctx, &todayStart); err != nil {
		return PromptAuditUsageOverview{}, err
	}
	if result.Last7Days, err = r.usagePeriod(ctx, &last7Start); err != nil {
		return PromptAuditUsageOverview{}, err
	}
	if result.AllTime, err = r.usagePeriod(ctx, nil); err != nil {
		return PromptAuditUsageOverview{}, err
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT account_id,
			(array_agg(account_name_snapshot ORDER BY created_at DESC))[1],
			(array_agg(account_email_snapshot ORDER BY created_at DESC))[1],
			COUNT(*), COUNT(*) FILTER (WHERE status='success'),
			COUNT(*) FILTER (WHERE status='failed'), COUNT(*) FILTER (WHERE status='invalid'),
			COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0),
			COALESCE(SUM(cache_creation_tokens),0), COALESCE(SUM(cache_read_tokens),0),
			COALESCE(SUM(estimated_cost_usd),0)::float8,
			COUNT(*) FILTER (WHERE pricing_known)
		FROM prompt_audit_invocations
		WHERE account_id IS NOT NULL
		GROUP BY account_id
		ORDER BY COALESCE(SUM(estimated_cost_usd),0) DESC, COUNT(*) DESC`)
	if err != nil {
		return PromptAuditUsageOverview{}, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var item PromptAuditAccountUsage
		if err := rows.Scan(&item.AccountID, &item.AccountName, &item.AccountEmail,
			&item.Invocations, &item.Successes, &item.Failures, &item.Invalid,
			&item.InputTokens, &item.OutputTokens, &item.CacheCreationTokens, &item.CacheReadTokens,
			&item.EstimatedCostUSD, &item.PricedInvocations); err != nil {
			return PromptAuditUsageOverview{}, err
		}
		result.ByAccount = append(result.ByAccount, item)
	}
	return result, rows.Err()
}

func (r *PostgreSQLRepository) usagePeriod(ctx context.Context, start *time.Time) (PromptAuditUsagePeriod, error) {
	query := `SELECT COUNT(*), COUNT(*) FILTER (WHERE status='success'),
		COUNT(*) FILTER (WHERE status='failed'), COUNT(*) FILTER (WHERE status='invalid'),
		COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0),
		COALESCE(SUM(cache_creation_tokens),0), COALESCE(SUM(cache_read_tokens),0),
		COALESCE(SUM(estimated_cost_usd),0)::float8,
		COUNT(*) FILTER (WHERE pricing_known) FROM prompt_audit_invocations`
	args := []any{}
	if start != nil {
		query += ` WHERE created_at >= $1`
		args = append(args, *start)
	}
	var value PromptAuditUsagePeriod
	err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&value.Invocations, &value.Successes, &value.Failures, &value.Invalid,
		&value.InputTokens, &value.OutputTokens, &value.CacheCreationTokens, &value.CacheReadTokens,
		&value.EstimatedCostUSD, &value.PricedInvocations,
	)
	return value, err
}
