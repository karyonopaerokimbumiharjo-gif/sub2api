-- Preserve a distinct, non-verdict record for a fail-closed Jev review outcome.
-- The request was rejected, but the prompt was not proven unsafe.
ALTER TABLE prompt_audit_events
    DROP CONSTRAINT IF EXISTS chk_prompt_audit_events_audit_status;
ALTER TABLE prompt_audit_events
    ADD CONSTRAINT chk_prompt_audit_events_audit_status
        CHECK (audit_status IN ('audited', 'gap', 'bypass', 'review_required'));

ALTER TABLE prompt_audit_events
    DROP CONSTRAINT IF EXISTS chk_prompt_audit_events_decision;
ALTER TABLE prompt_audit_events
    ADD CONSTRAINT chk_prompt_audit_events_decision
        CHECK (decision IN ('pass', 'flag', 'critical', 'review_required'));

ALTER TABLE prompt_audit_events
    DROP CONSTRAINT IF EXISTS chk_prompt_audit_events_risk_level;
ALTER TABLE prompt_audit_events
    ADD CONSTRAINT chk_prompt_audit_events_risk_level
        CHECK (risk_level IN ('low', 'medium', 'high', 'critical', 'unknown'));

COMMENT ON COLUMN prompt_audit_events.audit_status IS
    'audited, gap, bypass, or review_required; review_required is a rejected request with no safety verdict';
