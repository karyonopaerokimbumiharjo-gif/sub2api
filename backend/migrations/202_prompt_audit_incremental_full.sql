-- Keep the complete extracted request separate from the exact text sent to the
-- blocking classifier. Existing events used full_prompt for both meanings.
ALTER TABLE prompt_audit_events
    ADD COLUMN IF NOT EXISTS audited_prompt TEXT NOT NULL DEFAULT '';

UPDATE prompt_audit_events
SET audited_prompt = full_prompt
WHERE audited_prompt = '' AND full_prompt <> '';

COMMENT ON COLUMN prompt_audit_events.full_prompt IS
    'Complete client-controlled request text retained for administrator review';
COMMENT ON COLUMN prompt_audit_events.audited_prompt IS
    'Exact cleaned incremental text sent to the prompt-audit classifier';
