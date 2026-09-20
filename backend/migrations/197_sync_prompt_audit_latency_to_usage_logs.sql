-- Prompt auditing can finish before or after the corresponding usage log.
-- Keep the measured scanner latency on usage_logs in either ordering, while
-- preserving a directly measured blocking-gate latency when one is present.

CREATE INDEX IF NOT EXISTS idx_prompt_audit_events_request_api_key_created
    ON prompt_audit_events (request_id, api_key_id, created_at DESC, id DESC);

CREATE OR REPLACE FUNCTION fill_usage_log_prompt_audit_latency()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.prompt_audit_latency_ms IS NULL
       AND NEW.request_id IS NOT NULL
       AND BTRIM(NEW.request_id) <> ''
       AND NEW.api_key_id IS NOT NULL THEN
        SELECT event.latency_ms
          INTO NEW.prompt_audit_latency_ms
          FROM prompt_audit_events AS event
         WHERE event.request_id = NEW.request_id
           AND event.api_key_id = NEW.api_key_id
         ORDER BY event.created_at DESC, event.id DESC
         LIMIT 1;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_usage_logs_fill_prompt_audit_latency ON usage_logs;
CREATE TRIGGER trg_usage_logs_fill_prompt_audit_latency
BEFORE INSERT OR UPDATE OF request_id, api_key_id, prompt_audit_latency_ms
ON usage_logs
FOR EACH ROW
EXECUTE FUNCTION fill_usage_log_prompt_audit_latency();

CREATE OR REPLACE FUNCTION sync_prompt_audit_latency_to_usage_log()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.request_id IS NOT NULL
       AND BTRIM(NEW.request_id) <> ''
       AND NEW.api_key_id IS NOT NULL THEN
        UPDATE usage_logs
           SET prompt_audit_latency_ms = NEW.latency_ms
         WHERE request_id = NEW.request_id
           AND api_key_id = NEW.api_key_id
           AND prompt_audit_latency_ms IS NULL;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_prompt_audit_events_sync_usage_latency ON prompt_audit_events;
CREATE TRIGGER trg_prompt_audit_events_sync_usage_latency
AFTER INSERT OR UPDATE OF latency_ms
ON prompt_audit_events
FOR EACH ROW
EXECUTE FUNCTION sync_prompt_audit_latency_to_usage_log();

WITH latest_event AS (
    SELECT DISTINCT ON (request_id, api_key_id)
           request_id, api_key_id, latency_ms
      FROM prompt_audit_events
     WHERE request_id IS NOT NULL
       AND BTRIM(request_id) <> ''
       AND api_key_id IS NOT NULL
     ORDER BY request_id, api_key_id, created_at DESC, id DESC
)
UPDATE usage_logs AS usage
   SET prompt_audit_latency_ms = latest_event.latency_ms
  FROM latest_event
 WHERE usage.request_id = latest_event.request_id
   AND usage.api_key_id = latest_event.api_key_id
   AND usage.prompt_audit_latency_ms IS NULL;
