-- Earlier native hard-rule checks reused the prompt event table without a
-- source marker. Only recover provenance when the exact saved policy version
-- and both deterministic backend/policy identifiers prove native execution.
-- The shared risk-control switch was not part of these policy snapshots.
-- Native-enabled policy versions disable the legacy evaluation mode, so a
-- completed HTTP hard-rule event under that version came from the native path.
-- Unknown versions and non-HTTP stages retain their original metadata.
UPDATE prompt_audit_events e
SET stage = 'native_hard_rules'
FROM prompt_audit_policy_versions v
WHERE e.config_version = v.config_version
  AND v.config_snapshot->>'native_audit_enabled' = 'true'
  AND e.stage = 'http'
  AND e.audit_status = 'audited'
  AND (
      (e.scanner_backend = 'local-explicit-bypass-policy' AND e.policy_id = 'explicit_active_bypass')
      OR
      (e.scanner_backend = 'local-repository-policy' AND e.policy_id = 'known_jailbreak_repository')
  );
