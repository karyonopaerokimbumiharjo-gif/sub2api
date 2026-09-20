-- Historical OpenAI response.failed records may contain a full instructions
-- echo in error_body/upstream_error_detail. Keep the policy diagnosis and both
-- status layers, but remove internal prompt material from persisted payloads.
WITH sanitized AS (
    SELECT
        id,
        jsonb_build_object(
            'error', jsonb_build_object(
                'code', 'bio_policy',
                'message', COALESCE(
                    NULLIF(upstream_error_message, ''),
                    NULLIF(error_message, ''),
                    'Request blocked by biological-safety policy'
                )
            ),
            'source', COALESCE(NULLIF(error_source, ''), 'upstream_http'),
            'semantic_status', CASE WHEN COALESCE(status_code, 0) >= 400 THEN status_code ELSE 403 END,
            'upstream_transport_status', upstream_status_code
        )::text AS safe_body
    FROM ops_error_logs
    WHERE error_type = 'bio_policy'
      AND (
          POSITION('instructions' IN COALESCE(error_body, '')) > 0
          OR POSITION('instructions' IN COALESCE(upstream_error_detail, '')) > 0
      )
)
UPDATE ops_error_logs AS e
SET error_body = sanitized.safe_body,
    upstream_error_detail = sanitized.safe_body
FROM sanitized
WHERE e.id = sanitized.id;

