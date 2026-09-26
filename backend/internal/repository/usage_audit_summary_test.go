package repository

import (
	"database/sql"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
	"testing"
)

type usageAuditMetadataScanner struct{ raw string }

func (s usageAuditMetadataScanner) Scan(dest ...any) error {
	// SQL NULL is the zero value of sql.NullString. The final two columns are
	// metadata and created_at; no test fixture depends on unrelated usage fields.
	*dest[len(dest)-2].(*sql.NullString) = sql.NullString{String: s.raw, Valid: s.raw != ""}
	return nil
}
func TestUsageAuditMetadataRestoresNativeResultWithoutPromptText(t *testing.T) {
	log, err := scanUsageLog(usageAuditMetadataScanner{raw: `{"source":"native","status":"audited","result":"allow","engine":"typesafe","model":"jev-test","latency_ms":102}`})
	require.NoError(t, err)
	require.NotNil(t, log.Audit)
	require.Equal(t, "native", log.Audit.Source)
	require.Equal(t, "allow", log.Audit.Result)
	require.Equal(t, "jev-test", log.Audit.Model)
	require.Equal(t, 102, *log.Audit.LatencyMS)
	historical, err := scanUsageLog(usageAuditMetadataScanner{})
	require.NoError(t, err)
	require.Nil(t, historical.Audit)
	require.Nil(t, historical.PromptAuditLatencyMs)
	require.IsType(t, (*service.UsageAudit)(nil), log.Audit)
}
func TestUsageAuditQueryCorrelatesBothSourcesByRequestAndKey(t *testing.T) {
	require.Contains(t, usageLogAuditSelectExpression, "pae.api_key_id = usage_logs.api_key_id")
	require.Contains(t, usageLogAuditSelectExpression, "cml.api_key_id = usage_logs.api_key_id")
	require.Contains(t, usageLogAuditSelectExpression, "cml.request_id = usage_logs.request_id")
	require.Contains(t, usageLogAuditSelectExpression, "usage_logs.request_id <> ''")
	require.NotContains(t, usageLogAuditSelectExpression, "input_excerpt")
	require.NotContains(t, usageLogAuditSelectExpression, "full_prompt")
}
