-- Distinguish a complete prompt captured while auditing was disabled from a
-- classifier Allow. Gap events are historical markers and are not backfilled.
ALTER TABLE prompt_audit_events
    ADD COLUMN IF NOT EXISTS audit_status VARCHAR(32) NOT NULL DEFAULT 'audited';

ALTER TABLE prompt_audit_events
    DROP CONSTRAINT IF EXISTS chk_prompt_audit_events_audit_status;
ALTER TABLE prompt_audit_events
    ADD CONSTRAINT chk_prompt_audit_events_audit_status
        CHECK (audit_status IN ('audited', 'gap'));

CREATE INDEX IF NOT EXISTS idx_prompt_audit_events_audit_status_created
    ON prompt_audit_events (audit_status, created_at DESC, id DESC);

COMMENT ON COLUMN prompt_audit_events.audit_status IS
    'audited=classifier verdict; gap=captured while prompt auditing was disabled';
