-- J is an opt-in execution mode, independent from Safety and backend choice.
CREATE TABLE IF NOT EXISTS j_key_settings (
    api_key_id BIGINT PRIMARY KEY REFERENCES api_keys(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS j_tasks (
    api_key_id BIGINT NOT NULL REFERENCES api_keys(id),
    task_id TEXT NOT NULL CHECK (length(task_id) BETWEEN 1 AND 128),
    user_id BIGINT NOT NULL REFERENCES users(id),
    account_id BIGINT NOT NULL REFERENCES accounts(id),
    session_hash TEXT NOT NULL,
    base_model TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('running','completed','failed','cancelled')),
    next_actor TEXT NOT NULL DEFAULT 'jev' CHECK (next_actor IN ('jev','base')),
    result BYTEA,
    response_id TEXT,
    policy_version TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '24 hours',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (api_key_id, task_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS j_tasks_response ON j_tasks(api_key_id,response_id) WHERE response_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS j_tasks_retention ON j_tasks(created_at);
CREATE INDEX IF NOT EXISTS j_tasks_expiry ON j_tasks(expires_at);
CREATE INDEX IF NOT EXISTS j_tasks_user_recent ON j_tasks(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS j_events (
    id BIGSERIAL PRIMARY KEY,
    api_key_id BIGINT NOT NULL,
    task_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    call_id TEXT NOT NULL DEFAULT '',
    tool TEXT NOT NULL DEFAULT '',
    outcome TEXT NOT NULL DEFAULT '',
    input_tokens BIGINT NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
    output_tokens BIGINT NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (api_key_id,task_id) REFERENCES j_tasks(api_key_id,task_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS j_events_task ON j_events(api_key_id,task_id,id);

-- Client-side functions retain the base/decision phase on the next HTTP turn.
-- No function arguments, tokens, prompts or output text are kept in this table.
CREATE TABLE IF NOT EXISTS j_client_calls (
    api_key_id BIGINT NOT NULL,
    call_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    actor TEXT NOT NULL CHECK (actor IN ('jev','base')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (api_key_id,call_id),
    FOREIGN KEY (api_key_id,task_id) REFERENCES j_tasks(api_key_id,task_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS j_tool_grants (
    id TEXT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    api_key_id BIGINT NOT NULL REFERENCES api_keys(id),
    session_hash TEXT NOT NULL,
    tools BYTEA NOT NULL,
    secret_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS j_tool_calls (
    api_key_id BIGINT NOT NULL,
    task_id TEXT NOT NULL,
    call_id TEXT NOT NULL,
    grant_id TEXT NOT NULL REFERENCES j_tool_grants(id),
    payload BYTEA NOT NULL,
    result BYTEA,
    status TEXT NOT NULL CHECK (status IN ('queued','dispatched','completed','cancelled','unknown')),
    lease_hash TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY(api_key_id,task_id,call_id),
    FOREIGN KEY(api_key_id,task_id) REFERENCES j_tasks(api_key_id,task_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS j_tool_calls_poll ON j_tool_calls(grant_id,status,expires_at);

CREATE INDEX IF NOT EXISTS j_tool_calls_expiry ON j_tool_calls(expires_at);
