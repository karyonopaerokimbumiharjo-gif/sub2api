-- Application routing supports two explicitly configured backends. Replace the
-- CPA-only constraint without touching credentials, accounts, groups or history.
-- Keep deleted historical records compatible and reject unbound/direct OAuth.
ALTER TABLE accounts DROP CONSTRAINT IF EXISTS accounts_cpa_backend_required;
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
      )
    )
  ) IS TRUE
);

-- One live row owns refresh for a Pi OAuth identity, including disabled rows.
CREATE UNIQUE INDEX IF NOT EXISTS accounts_native_pi_identity_unique
  ON accounts ((credentials->>'chatgpt_account_id'))
  WHERE deleted_at IS NULL AND platform='openai' AND type='oauth'
    AND credentials->>'harness_kind'='pi';
