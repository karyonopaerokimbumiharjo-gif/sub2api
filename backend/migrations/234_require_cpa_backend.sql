-- The CPA bridge is the sole runtime account. Keep usage/audit history and IDs,
-- but remove direct credentials and group bindings (including deleted records).
DELETE FROM account_groups ag USING accounts a
WHERE ag.account_id = a.id AND NOT (
  a.platform = 'openai' AND a.type = 'apikey' AND a.parent_account_id IS NULL
  AND a.proxy_id IS NULL
  AND a.credentials->>'base_url' IN ('http://cpa:8317', 'http://cpa:8317/', 'http://cpa:8317/v1', 'http://cpa:8317/v1/')
) IS TRUE;

UPDATE accounts SET credentials = '{}'::jsonb, extra = '{}'::jsonb,
  status = 'disabled', schedulable = false, deleted_at = COALESCE(deleted_at, NOW()), updated_at = NOW()
WHERE NOT (
  platform = 'openai' AND type = 'apikey' AND parent_account_id IS NULL
  AND proxy_id IS NULL
  AND credentials->>'base_url' IN ('http://cpa:8317', 'http://cpa:8317/', 'http://cpa:8317/v1', 'http://cpa:8317/v1/')
) IS TRUE;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'accounts_cpa_backend_required') THEN
    ALTER TABLE accounts ADD CONSTRAINT accounts_cpa_backend_required CHECK (
      deleted_at IS NOT NULL OR (
        platform = 'openai' AND type = 'apikey' AND parent_account_id IS NULL
        AND proxy_id IS NULL
        AND credentials->>'base_url' IN ('http://cpa:8317', 'http://cpa:8317/', 'http://cpa:8317/v1', 'http://cpa:8317/v1/')
      ) IS TRUE
    );
  END IF;
END $$;

-- The legacy moderation API is currently disabled. Remove its independent
-- official-API destination and keys without changing the audit enable switch.
UPDATE settings SET value = (value::jsonb || jsonb_build_object(
  'base_url', 'http://cpa:8317', 'proxy_id', NULL, 'api_keys', '[]'::jsonb
))::text, updated_at = NOW()
WHERE key = 'content_moderation_config'
  AND (value::jsonb->>'base_url' IS DISTINCT FROM 'http://cpa:8317' OR value::jsonb->'proxy_id' IS DISTINCT FROM 'null'::jsonb);

-- Remove external/internal-OAuth audit fallbacks, even disabled ones. Preserve
-- the classifier, encrypted CPA keys, gate settings, and remaining node order.
DO $$ DECLARE cfg jsonb; nodes jsonb; next_version bigint;
BEGIN
  SELECT value::jsonb INTO cfg FROM settings WHERE key = 'prompt_audit_config' FOR UPDATE;
  IF cfg IS NOT NULL THEN
    SELECT COALESCE(jsonb_agg(e ORDER BY ord), '[]'::jsonb) INTO nodes
    FROM jsonb_array_elements(cfg->'endpoints') WITH ORDINALITY AS t(e, ord)
    WHERE e->>'protocol' = 'openai_compatible'
      AND COALESCE((e->>'account_id')::bigint, 0) = 0
      AND e->>'base_url' IN ('http://cpa:8317', 'http://cpa:8317/', 'http://cpa:8317/v1', 'http://cpa:8317/v1/');
    IF cfg->>'enabled' = 'true' AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(nodes) e WHERE e->>'enabled' = 'true') THEN
      RAISE EXCEPTION 'CPA-only migration requires an enabled CPA audit node';
    END IF;
    IF nodes IS DISTINCT FROM cfg->'endpoints' THEN
      next_version := COALESCE((cfg->>'config_version')::bigint, 0) + 1;
      cfg := cfg || jsonb_build_object('endpoints', nodes, 'config_version', next_version,
        'updated_at', NOW(), 'updated_by', 0, 'change_summary', 'Require CPA for every audit endpoint');
      UPDATE settings SET value = cfg::text, updated_at = NOW() WHERE key = 'prompt_audit_config';
      INSERT INTO prompt_audit_policy_versions(config_version, config_snapshot, endpoint_order, created_at)
      VALUES (next_version, cfg, (SELECT COALESCE(jsonb_agg(e->>'id'), '[]'::jsonb) FROM jsonb_array_elements(nodes) e), NOW());
    END IF;
  END IF;
END $$;
