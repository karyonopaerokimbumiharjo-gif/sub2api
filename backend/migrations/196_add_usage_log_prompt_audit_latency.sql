-- Persist the synchronous prompt-audit delay separately from the established
-- upstream duration/TTFT fields so both latency scopes remain observable.
ALTER TABLE usage_logs
    ADD COLUMN IF NOT EXISTS prompt_audit_latency_ms INTEGER;

ALTER TABLE usage_logs
    DROP CONSTRAINT IF EXISTS usage_logs_prompt_audit_latency_ms_nonnegative;

ALTER TABLE usage_logs
    ADD CONSTRAINT usage_logs_prompt_audit_latency_ms_nonnegative
    CHECK (prompt_audit_latency_ms IS NULL OR prompt_audit_latency_ms >= 0) NOT VALID;

ALTER TABLE usage_logs
    VALIDATE CONSTRAINT usage_logs_prompt_audit_latency_ms_nonnegative;
