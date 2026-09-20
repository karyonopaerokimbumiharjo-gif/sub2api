-- Exact cache-write provenance and independent review evidence. Empty context
-- on historical samples deliberately cannot authorize automatic cache release.
ALTER TABLE prompt_audit_adaptive_samples
    ADD COLUMN IF NOT EXISTS correction_context JSONB NOT NULL DEFAULT '{}'::jsonb;
