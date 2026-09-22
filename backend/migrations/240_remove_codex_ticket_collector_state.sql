-- Retire only the removed collector's persisted material. Keep accounts,
-- credentials, usage logs, audit history, and unrelated settings intact.
UPDATE accounts AS a
SET extra = a.extra - ARRAY(
    SELECT key
    FROM jsonb_object_keys(
        CASE WHEN jsonb_typeof(a.extra) = 'object' THEN a.extra ELSE '{}'::jsonb END
    ) AS key
    WHERE key LIKE 'codex_turn_ticket:%' OR key = 'codex_harvest_proxy_url'
)
WHERE jsonb_typeof(a.extra) = 'object'
  AND EXISTS (
      SELECT 1
      FROM jsonb_object_keys(a.extra) AS key
      WHERE key LIKE 'codex_turn_ticket:%' OR key = 'codex_harvest_proxy_url'
  );

DELETE FROM settings
WHERE key IN (
    'openai_codex_ticket_enabled',
    'openai_codex_ticket_models',
    'openai_codex_ticket_harvest_proxy_url'
);
