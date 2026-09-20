ALTER TABLE user_balance_grants
    ADD COLUMN IF NOT EXISTS granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

UPDATE user_balance_grants g
SET granted_at = rc.used_at
FROM redeem_codes rc
WHERE g.redeem_code_id = rc.id
  AND rc.used_at IS NOT NULL
  AND g.granted_at IS DISTINCT FROM rc.used_at;

UPDATE user_balance_grants
SET granted_at = created_at
WHERE redeem_code_id IS NULL
  AND granted_at IS DISTINCT FROM created_at;
