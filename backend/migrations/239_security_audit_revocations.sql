-- Permanent local conversation revocations. Keys are namespaced hashes, never
-- prompts, credentials or upstream state blobs. Redis remains an acceleration
-- layer; restoring or evicting its cache cannot reopen a revoked conversation.
CREATE TABLE IF NOT EXISTS security_audit_revocations (
    key TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
