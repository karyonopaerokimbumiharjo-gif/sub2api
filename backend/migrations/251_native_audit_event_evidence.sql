-- Keep native moderation evidence under its existing retention policy.
-- Empty historical fields mean unavailable; never reconstruct audited text
-- from the old 240-character preview.
ALTER TABLE content_moderation_logs
    ADD COLUMN IF NOT EXISTS full_prompt text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS audited_prompt text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS prompt_hash text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS content_truncated boolean NOT NULL DEFAULT false;
