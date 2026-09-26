-- Retire J-only runtime; retain business accounts and ordinary usage.
DROP TABLE IF EXISTS j_tool_calls;
DROP TABLE IF EXISTS j_tool_grants;
DROP TABLE IF EXISTS j_client_calls;
DROP TABLE IF EXISTS j_events;
DROP TABLE IF EXISTS j_tasks;
DROP TABLE IF EXISTS j_key_settings;
