CREATE INDEX IF NOT EXISTS idx_content_moderation_logs_usage_audit
ON content_moderation_logs(request_id, api_key_id, created_at DESC, id DESC)
WHERE request_id <> '';
