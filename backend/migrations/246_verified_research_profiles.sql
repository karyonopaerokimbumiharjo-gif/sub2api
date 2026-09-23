-- Immutable administrator approvals; revocation is the only permitted update.
CREATE TABLE IF NOT EXISTS safety_research_profiles (
 id BIGSERIAL PRIMARY KEY,
 user_id BIGINT NOT NULL REFERENCES users(id),
 api_key_id BIGINT NOT NULL REFERENCES api_keys(id),
 organization TEXT NOT NULL, purpose TEXT NOT NULL, verification_reference TEXT NOT NULL,
 projects JSONB NOT NULL, resources JSONB NOT NULL, tools JSONB NOT NULL,
 approved_by BIGINT NOT NULL REFERENCES users(id), approved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 expires_at TIMESTAMPTZ NOT NULL, revoked_at TIMESTAMPTZ, revoked_by BIGINT REFERENCES users(id), revoke_reason TEXT,
 CHECK (expires_at > approved_at), CHECK (expires_at <= approved_at + INTERVAL '90 days'),
 CHECK (jsonb_typeof(projects)='array' AND jsonb_typeof(resources)='array' AND jsonb_typeof(tools)='array')
);
CREATE INDEX IF NOT EXISTS safety_research_profiles_key ON safety_research_profiles(user_id,api_key_id,expires_at) WHERE revoked_at IS NULL;
