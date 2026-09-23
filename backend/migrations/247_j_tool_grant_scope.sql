-- Old session-wide grants cannot authorize a new task or device.
ALTER TABLE j_tool_grants ADD COLUMN IF NOT EXISTS task_id TEXT NOT NULL DEFAULT '';
ALTER TABLE j_tool_grants ADD COLUMN IF NOT EXISTS device_id TEXT NOT NULL DEFAULT '';
UPDATE j_tool_grants SET revoked_at=COALESCE(revoked_at,NOW()) WHERE task_id='' OR device_id='';
DO $$ BEGIN
IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='j_tool_grant_scope' AND conrelid='j_tool_grants'::regclass) THEN
ALTER TABLE j_tool_grants ADD CONSTRAINT j_tool_grant_scope CHECK (
 (length(task_id) BETWEEN 1 AND 128 AND length(device_id) BETWEEN 1 AND 128) OR revoked_at IS NOT NULL
);
END IF;
END $$;
