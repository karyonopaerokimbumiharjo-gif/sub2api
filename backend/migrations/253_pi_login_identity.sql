-- A team workspace can contain several independent authorized login users.
-- Keep one rotating-credential owner per login AND workspace, not per team.
CREATE OR REPLACE FUNCTION sub2api_openai_oauth_principal(c jsonb)
RETURNS text LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE AS $$
DECLARE
  token_value text;
  payload text;
  claims jsonb;
  principal text;
  subject_value text;
  email_value text;
BEGIN
  FOREACH token_value IN ARRAY ARRAY[c->>'access_token', c->>'id_token'] LOOP
    IF token_value IS NULL OR array_length(string_to_array(token_value, '.'), 1) <> 3 THEN CONTINUE; END IF;
    payload := split_part(token_value, '.', 2);
    IF length(payload) > 1048576 THEN CONTINUE; END IF;
    BEGIN
      claims := convert_from(decode(translate(payload, '-_', '+/') || repeat('=', (4 - length(payload) % 4) % 4), 'base64'), 'UTF8')::jsonb;
    EXCEPTION WHEN OTHERS THEN
      CONTINUE;
    END;
    principal := COALESCE(NULLIF(btrim(claims->'https://api.openai.com/auth'->>'chatgpt_user_id'), ''), NULLIF(btrim(claims->'https://api.openai.com/auth'->>'user_id'), ''));
    IF principal IS NOT NULL THEN RETURN 'user:' || principal; END IF;
    subject_value := COALESCE(subject_value, NULLIF(btrim(claims->>'sub'), ''));
    email_value := COALESCE(email_value, NULLIF(btrim(claims->'https://api.openai.com/profile'->>'email'), ''), NULLIF(btrim(claims->>'email'), ''));
  END LOOP;
  IF subject_value IS NOT NULL THEN RETURN 'user:' || subject_value; END IF;
  principal := NULLIF(btrim(c->>'chatgpt_user_id'), '');
  IF principal IS NOT NULL THEN RETURN 'user:' || principal; END IF;
  principal := NULLIF(btrim(c->>'openai_oauth_principal'), '');
  IF principal IS NOT NULL THEN RETURN principal; END IF;
  email_value := COALESCE(email_value, NULLIF(btrim(c->>'email'), ''));
  IF email_value IS NOT NULL THEN RETURN 'email:' || lower(email_value); END IF;
  RETURN 'legacy:unknown';
END;
$$;

CREATE UNIQUE INDEX IF NOT EXISTS accounts_native_pi_login_identity_unique
  ON accounts ((credentials->>'chatgpt_account_id'), sub2api_openai_oauth_principal(credentials))
  WHERE deleted_at IS NULL AND platform='openai' AND type='oauth'
    AND credentials->>'harness_kind'='pi';
DROP INDEX IF EXISTS accounts_native_pi_identity_unique;
