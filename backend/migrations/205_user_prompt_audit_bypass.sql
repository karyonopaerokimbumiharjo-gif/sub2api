-- Move prompt-audit release authority from a mutable global email list to an
-- explicit per-user flag managed from the admin user editor.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS prompt_audit_bypass BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN users.prompt_audit_bypass IS
    'Administrator-controlled user-level bypass for prompt/content/output safety auditing';

-- Keep the durable API-key authentication cache invalidation backstop aware of
-- the new field. Application updates also invalidate immediately, while this
-- covers direct SQL and crash windows.
CREATE OR REPLACE FUNCTION enqueue_user_auth_cache_invalidation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    target_user_id BIGINT;
BEGIN
    target_user_id := OLD.id;
    IF TG_OP = 'UPDATE'
       AND OLD.status IS NOT DISTINCT FROM NEW.status
       AND OLD.role IS NOT DISTINCT FROM NEW.role
       AND OLD.prompt_audit_bypass IS NOT DISTINCT FROM NEW.prompt_audit_bypass
       AND OLD.deleted_at IS NOT DISTINCT FROM NEW.deleted_at THEN
        RETURN NEW;
    END IF;

    INSERT INTO auth_cache_invalidation_outbox (cache_key)
    SELECT encode(sha256(convert_to(k.key, 'UTF8')), 'hex')
    FROM api_keys AS k
    WHERE k.user_id = target_user_id
      AND k.deleted_at IS NULL
      AND k.key <> '';
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

-- Preserve any legacy email-list configuration before removing it from the
-- prompt audit policy document. Matching remains case-insensitive for this
-- one-time compatibility conversion only.
WITH legacy_emails AS (
    SELECT DISTINCT LOWER(BTRIM(entry.email)) AS email
    FROM settings s
    CROSS JOIN LATERAL jsonb_array_elements_text(
        CASE
            WHEN jsonb_typeof(COALESCE(NULLIF(s.value, '')::jsonb, '{}'::jsonb)->'whitelist_emails') = 'array'
                THEN COALESCE(NULLIF(s.value, '')::jsonb, '{}'::jsonb)->'whitelist_emails'
            ELSE '[]'::jsonb
        END
    ) AS entry(email)
    WHERE s.key = 'prompt_audit_config'
)
UPDATE users u
SET prompt_audit_bypass = TRUE,
    updated_at = NOW()
WHERE u.deleted_at IS NULL
  AND EXISTS (
      SELECT 1
      FROM legacy_emails legacy
      WHERE legacy.email = LOWER(BTRIM(u.email))
  );

UPDATE settings
SET value = (COALESCE(NULLIF(value, '')::jsonb, '{}'::jsonb) - 'whitelist_emails')::text,
    updated_at = NOW()
WHERE key = 'prompt_audit_config'
  AND COALESCE(NULLIF(value, '')::jsonb, '{}'::jsonb) ? 'whitelist_emails';

COMMENT ON COLUMN prompt_audit_events.audit_status IS
    'audited=classifier verdict; gap=captured while prompt auditing was disabled; bypass=administrator user-level release';
