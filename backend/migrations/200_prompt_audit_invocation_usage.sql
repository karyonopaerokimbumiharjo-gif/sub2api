-- Keep classifier usage separate from user-facing audit events: one prompt can
-- produce multiple chunks, retries, and failover calls, all of which consume
-- upstream capacity even when no safe event is persisted.
CREATE TABLE IF NOT EXISTS prompt_audit_invocations (
    id BIGSERIAL PRIMARY KEY,
    request_id VARCHAR(128) NOT NULL DEFAULT '',
    config_version BIGINT NOT NULL DEFAULT 0,
    guard_endpoint_id VARCHAR(128) NOT NULL DEFAULT '',
    guard_endpoint_name VARCHAR(255) NOT NULL DEFAULT '',
    protocol VARCHAR(64) NOT NULL DEFAULT '',
    model VARCHAR(255) NOT NULL DEFAULT '',
    account_id BIGINT,
    account_name_snapshot VARCHAR(255) NOT NULL DEFAULT '',
    account_email_snapshot VARCHAR(320) NOT NULL DEFAULT '',
    input_tokens BIGINT NOT NULL DEFAULT 0,
    output_tokens BIGINT NOT NULL DEFAULT 0,
    cache_creation_tokens BIGINT NOT NULL DEFAULT 0,
    cache_read_tokens BIGINT NOT NULL DEFAULT 0,
    estimated_cost_usd NUMERIC(20,12) NOT NULL DEFAULT 0,
    pricing_known BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(32) NOT NULL,
    error_code VARCHAR(128) NOT NULL DEFAULT '',
    latency_ms BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_prompt_audit_invocation_status
        CHECK (status IN ('success', 'failed', 'invalid'))
);

CREATE INDEX IF NOT EXISTS idx_prompt_audit_invocations_created_at
    ON prompt_audit_invocations (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_invocations_account_created_at
    ON prompt_audit_invocations (account_id, created_at DESC)
    WHERE account_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_prompt_audit_invocations_endpoint_created_at
    ON prompt_audit_invocations (guard_endpoint_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_invocations_request_id
    ON prompt_audit_invocations (request_id)
    WHERE request_id <> '';
