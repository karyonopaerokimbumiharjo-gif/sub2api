ALTER TABLE usage_logs ADD COLUMN IF NOT EXISTS vps_latency_ms INTEGER;
COMMENT ON COLUMN usage_logs.vps_latency_ms IS 'Measured handler entry to first upstream dispatch, including auth/audit/queue; NULL means not recorded';
