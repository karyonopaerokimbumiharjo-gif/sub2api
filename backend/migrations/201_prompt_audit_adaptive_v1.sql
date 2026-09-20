-- Prompt Audit Adaptive v1 keeps the synchronous verdict backward compatible
-- while exposing intent and semantic-content findings separately.
ALTER TABLE prompt_audit_events
    ADD COLUMN IF NOT EXISTS intent_categories JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS content_categories JSONB NOT NULL DEFAULT '[]'::jsonb;

UPDATE prompt_audit_events
SET intent_categories = categories
WHERE intent_categories = '[]'::jsonb
  AND categories <> '[]'::jsonb;

-- Adaptive samples are deliberately separate from enforcement events. A model
-- disagreement is evidence for review, never an automatically trusted label.
CREATE TABLE IF NOT EXISTS prompt_audit_adaptive_samples (
    id BIGSERIAL PRIMARY KEY,
    request_id VARCHAR(128) NOT NULL DEFAULT '',
    user_id BIGINT,
    prompt_hash VARCHAR(64) NOT NULL,
    task_fingerprint VARCHAR(64) NOT NULL DEFAULT '',
    stage VARCHAR(64) NOT NULL DEFAULT 'http',
    audit_subject VARCHAR(32) NOT NULL DEFAULT 'intent',
    redacted_preview TEXT NOT NULL DEFAULT '',
    full_prompt TEXT NOT NULL DEFAULT '',
    config_version BIGINT NOT NULL DEFAULT 0,
    policy_version INTEGER NOT NULL DEFAULT 0,
    primary_endpoint_id VARCHAR(128) NOT NULL DEFAULT '',
    shadow_endpoint_id VARCHAR(128) NOT NULL DEFAULT '',
    primary_decision VARCHAR(32) NOT NULL DEFAULT '',
    shadow_decision VARCHAR(32) NOT NULL DEFAULT '',
    primary_categories JSONB NOT NULL DEFAULT '[]'::jsonb,
    shadow_categories JSONB NOT NULL DEFAULT '[]'::jsonb,
    primary_intent_categories JSONB NOT NULL DEFAULT '[]'::jsonb,
    primary_content_categories JSONB NOT NULL DEFAULT '[]'::jsonb,
    shadow_intent_categories JSONB NOT NULL DEFAULT '[]'::jsonb,
    shadow_content_categories JSONB NOT NULL DEFAULT '[]'::jsonb,
    status VARCHAR(32) NOT NULL,
    review_status VARCHAR(16) NOT NULL DEFAULT 'pending',
    review_note TEXT NOT NULL DEFAULT '',
    reviewed_by BIGINT,
    reviewed_at TIMESTAMPTZ,
    occurrence_count BIGINT NOT NULL DEFAULT 1,
    last_error_code VARCHAR(128) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_prompt_audit_adaptive_status CHECK (
        status IN ('pending','shadow_match','disagreement','shadow_failed')
    ),
    CONSTRAINT chk_prompt_audit_adaptive_review_status CHECK (
        review_status IN ('pending','allow','block')
    ),
    CONSTRAINT uq_prompt_audit_adaptive_sample UNIQUE (
        prompt_hash, stage, audit_subject, config_version, primary_endpoint_id, policy_version
    )
);

CREATE INDEX IF NOT EXISTS idx_prompt_audit_adaptive_status_updated
    ON prompt_audit_adaptive_samples (review_status, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_prompt_audit_adaptive_user_updated
    ON prompt_audit_adaptive_samples (user_id, updated_at DESC)
    WHERE user_id IS NOT NULL;

-- Every administrator save is a full policy switch. Snapshots make that switch
-- auditable and give the UI/API a stable rollback source without mutating old
-- migration files or relying on model-name-specific code.
CREATE TABLE IF NOT EXISTS prompt_audit_policy_versions (
    id BIGSERIAL PRIMARY KEY,
    config_version BIGINT NOT NULL UNIQUE,
    config_snapshot JSONB NOT NULL,
    endpoint_order JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_by BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO prompt_audit_policy_versions (
    config_version, config_snapshot, endpoint_order, created_by
)
SELECT
    COALESCE(NULLIF(value::jsonb->>'config_version','')::bigint, 1),
    value::jsonb,
    COALESCE((
        SELECT jsonb_agg(endpoint->>'id' ORDER BY ordinality)
        FROM jsonb_array_elements(COALESCE(value::jsonb->'endpoints', '[]'::jsonb))
            WITH ORDINALITY AS ordered_endpoint(endpoint, ordinality)
    ), '[]'::jsonb),
    NULLIF(value::jsonb->>'updated_by','')::bigint
FROM settings
WHERE key = 'prompt_audit_config'
ON CONFLICT (config_version) DO NOTHING;
