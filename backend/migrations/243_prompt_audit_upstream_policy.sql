-- Provider refusals must not be reported as locally confirmed violations.
ALTER TABLE prompt_audit_events DROP CONSTRAINT IF EXISTS chk_prompt_audit_events_decision;
ALTER TABLE prompt_audit_events ADD CONSTRAINT chk_prompt_audit_events_decision
  CHECK (decision IN ('pass', 'flag', 'critical', 'review_required', 'upstream_policy_block'));
UPDATE prompt_audit_events SET decision='upstream_policy_block', risk_level='unknown',
  scanner_scores='{}'::jsonb, matched_scanners='[]'::jsonb
  WHERE stage IN ('upstream_feedback','local_policy_cache') AND policy_id='provider-policy-feedback';

ALTER TABLE prompt_audit_events ADD COLUMN IF NOT EXISTS policy_review jsonb;
