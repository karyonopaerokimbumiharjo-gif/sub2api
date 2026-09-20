CREATE TABLE IF NOT EXISTS user_balance_grants (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redeem_code_id BIGINT NULL REFERENCES redeem_codes(id) ON DELETE SET NULL,
    source_type VARCHAR(64) NOT NULL DEFAULT 'redeem_code',
    original_amount DECIMAL(20,8) NOT NULL,
    remaining_amount DECIMAL(20,8) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed_at TIMESTAMPTZ NULL,
    expired_at TIMESTAMPTZ NULL,
    CONSTRAINT user_balance_grants_amounts_nonnegative CHECK (original_amount >= 0 AND remaining_amount >= 0),
    CONSTRAINT user_balance_grants_status_valid CHECK (status IN ('active', 'consumed', 'expired'))
);

CREATE UNIQUE INDEX IF NOT EXISTS user_balance_grants_redeem_code_id_uq
    ON user_balance_grants (redeem_code_id)
    WHERE redeem_code_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS user_balance_grants_user_active_expiry_idx
    ON user_balance_grants (user_id, expires_at, id)
    WHERE status = 'active' AND remaining_amount > 0;

CREATE OR REPLACE FUNCTION public.expire_user_balance_grants(p_user_id BIGINT)
RETURNS NUMERIC
LANGUAGE plpgsql
AS $$
DECLARE
    v_expired DECIMAL(20,8);
BEGIN
    WITH expired AS (
        SELECT id, remaining_amount
        FROM user_balance_grants
        WHERE user_id = p_user_id
          AND status = 'active'
          AND remaining_amount > 0
          AND expires_at <= NOW()
        ORDER BY expires_at ASC, id ASC
        FOR UPDATE
    ),
    updated AS (
        UPDATE user_balance_grants g
        SET remaining_amount = 0,
            status = 'expired',
            expired_at = COALESCE(g.expired_at, NOW()),
            updated_at = NOW()
        FROM expired e
        WHERE g.id = e.id
        RETURNING e.remaining_amount
    )
    SELECT COALESCE(SUM(remaining_amount), 0)::DECIMAL(20,8)
    INTO v_expired
    FROM updated;

    IF v_expired > 0 THEN
        UPDATE users
        SET balance = CASE
                WHEN balance > 0 THEN GREATEST(balance - v_expired, 0)
                ELSE balance
            END,
            updated_at = NOW()
        WHERE id = p_user_id
          AND deleted_at IS NULL;
    END IF;

    RETURN COALESCE(v_expired, 0);
END;
$$;

CREATE OR REPLACE FUNCTION public.consume_user_balance_grants(p_user_id BIGINT, p_amount NUMERIC)
RETURNS NUMERIC
LANGUAGE plpgsql
AS $$
DECLARE
    v_left DECIMAL(20,8);
    v_consumed DECIMAL(20,8) := 0;
    v_take DECIMAL(20,8);
    grant_row RECORD;
BEGIN
    v_left := GREATEST(COALESCE(p_amount, 0), 0);
    IF v_left <= 0 THEN
        RETURN 0;
    END IF;

    PERFORM public.expire_user_balance_grants(p_user_id);

    FOR grant_row IN
        SELECT id, remaining_amount
        FROM user_balance_grants
        WHERE user_id = p_user_id
          AND status = 'active'
          AND remaining_amount > 0
          AND expires_at > NOW()
        ORDER BY expires_at ASC, id ASC
        FOR UPDATE
    LOOP
        EXIT WHEN v_left <= 0;

        v_take := LEAST(grant_row.remaining_amount, v_left);

        UPDATE user_balance_grants
        SET remaining_amount = remaining_amount - v_take,
            status = CASE
                WHEN grant_row.remaining_amount - v_take <= 0 THEN 'consumed'
                ELSE status
            END,
            consumed_at = CASE
                WHEN grant_row.remaining_amount - v_take <= 0 THEN COALESCE(consumed_at, NOW())
                ELSE consumed_at
            END,
            updated_at = NOW()
        WHERE id = grant_row.id;

        v_left := v_left - v_take;
        v_consumed := v_consumed + v_take;
    END LOOP;

    RETURN v_consumed;
END;
$$;

CREATE OR REPLACE FUNCTION public.expire_due_balance_grants(p_limit INTEGER DEFAULT 1000)
RETURNS TABLE(expired_user_id BIGINT, expired_amount NUMERIC)
LANGUAGE plpgsql
AS $$
DECLARE
    user_row RECORD;
    v_expired DECIMAL(20,8);
BEGIN
    FOR user_row IN
        SELECT DISTINCT user_id
        FROM user_balance_grants
        WHERE status = 'active'
          AND remaining_amount > 0
          AND expires_at <= NOW()
        ORDER BY user_id
        LIMIT GREATEST(COALESCE(p_limit, 1000), 1)
    LOOP
        v_expired := public.expire_user_balance_grants(user_row.user_id);
        IF v_expired > 0 THEN
            expired_user_id := user_row.user_id;
            expired_amount := v_expired;
            RETURN NEXT;
        END IF;
    END LOOP;
END;
$$;
