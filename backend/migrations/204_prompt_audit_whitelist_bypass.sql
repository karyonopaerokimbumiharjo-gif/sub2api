-- Record administrator-managed email whitelist bypasses as explicit
-- not-audited events without confusing them with audit gaps or classifier
-- Allow verdicts.
ALTER TABLE prompt_audit_events
    DROP CONSTRAINT IF EXISTS chk_prompt_audit_events_audit_status;

ALTER TABLE prompt_audit_events
    ADD CONSTRAINT chk_prompt_audit_events_audit_status
        CHECK (audit_status IN ('audited', 'gap', 'bypass'));

COMMENT ON COLUMN prompt_audit_events.audit_status IS
    'audited=classifier verdict; gap=captured while prompt auditing was disabled; bypass=administrator email whitelist bypass';
