-- A business account may reuse an existing native Pi authorization when the
-- same upstream ChatGPT identity is already owned by another row. The alias
-- has its own groups/billing identity but resolves token refresh and runtime
-- sessions through pi_runtime_account_id, so the native Pi identity remains
-- unique and refresh-safe.
ALTER TABLE accounts DROP CONSTRAINT IF EXISTS accounts_execution_backend_required;
ALTER TABLE accounts ADD CONSTRAINT accounts_execution_backend_required CHECK (
  deleted_at IS NOT NULL OR (
    platform = 'openai' AND parent_account_id IS NULL AND proxy_id IS NULL AND (
      (type = 'apikey' AND credentials->>'base_url' IN (
        'http://cpa:8317', 'http://cpa:8317/', 'http://cpa:8317/v1', 'http://cpa:8317/v1/'
      )) OR (
        type = 'oauth' AND credentials->>'harness_kind' = 'pi'
        AND CASE WHEN credentials->>'pi_owner_user_id' ~ '^[0-9]{1,19}$'
          THEN (credentials->>'pi_owner_user_id')::numeric BETWEEN 1 AND 9223372036854775807
          ELSE false END
        AND length(btrim(credentials->>'access_token')) > 0
        AND length(btrim(credentials->>'refresh_token')) > 0
        AND length(btrim(credentials->>'chatgpt_account_id')) > 0
        AND COALESCE(btrim(credentials->>'base_url'), '') = ''
        AND COALESCE(credentials->>'pi_transport', '') IN ('', 'sse', 'auto', 'websocket', 'websocket-cached')
      ) OR (
        type = 'oauth' AND credentials->>'harness_kind' = 'pi_shared'
        AND CASE WHEN credentials->>'pi_owner_user_id' ~ '^[0-9]{1,19}$'
          THEN (credentials->>'pi_owner_user_id')::numeric BETWEEN 1 AND 9223372036854775807
          ELSE false END
        AND CASE WHEN credentials->>'pi_runtime_account_id' ~ '^[0-9]{1,19}$'
          THEN (credentials->>'pi_runtime_account_id')::numeric > 0
          ELSE false END
        AND length(btrim(credentials->>'chatgpt_account_id')) > 0
        AND COALESCE(btrim(credentials->>'base_url'), '') = ''
      )
    )
  ) IS TRUE
);
