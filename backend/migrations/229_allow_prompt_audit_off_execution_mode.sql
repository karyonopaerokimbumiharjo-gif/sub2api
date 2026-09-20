-- Explicit administrator bypass markers are intentionally not audited. Allow
-- their completed bookkeeping jobs to describe that state without reusing an
-- audited execution mode.
ALTER TABLE prompt_audit_jobs
    DROP CONSTRAINT IF EXISTS chk_prompt_audit_jobs_execution_mode;

ALTER TABLE prompt_audit_jobs
    ADD CONSTRAINT chk_prompt_audit_jobs_execution_mode
        CHECK (execution_mode IN ('off', 'async_audit', 'blocking'));

COMMENT ON COLUMN prompt_audit_jobs.execution_mode IS
    'off=not audited user bypass marker; async_audit=background audit; blocking=synchronous audit';
