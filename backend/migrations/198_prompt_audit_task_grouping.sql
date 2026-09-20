-- Persist a stable task fingerprint and audit subject so the admin UI can
-- aggregate runtime-noise duplicates without deleting the original events.
ALTER TABLE prompt_audit_jobs
    ADD COLUMN IF NOT EXISTS task_fingerprint VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS audit_subject VARCHAR(32) NOT NULL DEFAULT 'intent';

ALTER TABLE prompt_audit_events
    ADD COLUMN IF NOT EXISTS task_fingerprint VARCHAR(64) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS audit_subject VARCHAR(32) NOT NULL DEFAULT 'intent';

-- Existing rows use a deterministic PostgreSQL-only backfill. New rows use
-- the stronger Go canonicalizer and SHA-256 fingerprint.
UPDATE prompt_audit_events
SET task_fingerprint = md5(
        lower(
            regexp_replace(
                regexp_replace(
                    regexp_replace(full_prompt, '(?is)<system-reminder[^>]*>.*?</system-reminder>', ' ', 'g'),
                    '(?is)#\s*AGENTS\.md instructions\s*<INSTRUCTIONS>.*?</INSTRUCTIONS>', ' ', 'g'
                ),
                '\s+', ' ', 'g'
            )
        )
    )
WHERE task_fingerprint = '' AND full_prompt <> '';

UPDATE prompt_audit_events
SET audit_subject = CASE
    WHEN stage = 'upstream_feedback' THEN 'upstream_feedback'
    WHEN stage = 'local_policy_cache' THEN 'local_cache'
    ELSE 'intent'
END
WHERE audit_subject = '' OR audit_subject = 'intent';

CREATE INDEX IF NOT EXISTS idx_prompt_audit_events_task_group
    ON prompt_audit_events (task_fingerprint, user_id, created_at DESC, id DESC)
    WHERE task_fingerprint <> '';
