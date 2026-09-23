-- NULL distinguishes historical events whose coverage was not measured.
ALTER TABLE prompt_audit_events ADD COLUMN IF NOT EXISTS output_capture jsonb;
ALTER TABLE prompt_audit_events DROP CONSTRAINT IF EXISTS chk_prompt_audit_events_audit_status;
ALTER TABLE prompt_audit_events ADD CONSTRAINT chk_prompt_audit_events_audit_status
  CHECK (audit_status IN ('audited', 'gap', 'bypass', 'review_required', 'partial'));
