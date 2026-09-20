export type PromptAuditMode = 'off' | 'async_audit' | 'blocking'
export type PromptBlockingAuditMode = 'fast_latest' | 'incremental_full' | 'full'
export type PromptBackgroundAuditMode = 'off' | PromptBlockingAuditMode
export type PromptDecision = 'pass' | 'flag' | 'critical'
export type PromptRiskLevel = 'low' | 'medium' | 'high' | 'critical'
export type PromptAuditProtocol = 'openai_compatible' | 'typesafe_systemone' | 'antigravity_internal' | 'openai_internal'
export type PromptAuditAdapter = 'qwen3guard' | 'generic_llm'

export interface PromptAuditEndpoint {
  id: string
  name: string
  protocol: PromptAuditProtocol
  adapter: PromptAuditAdapter
  base_url: string
  model: string
  account_id: number
  timeout_ms: number
  input_limit: number
  enabled: boolean
  has_token: boolean
  token_status: 'configured' | 'missing' | 'invalid' | string
}

export interface PromptAuditEndpointDraft extends PromptAuditEndpoint {
  token: string
  clear_token: boolean
}

export interface PromptAuditConfig {
  enabled: boolean
  blocking_enabled: boolean
  blocking_audit_mode: PromptBlockingAuditMode
  background_audit_mode?: PromptBackgroundAuditMode
  blocking_latest_turn_only: boolean
  store_pass_events: boolean
  adaptive_enabled: boolean
  adaptive_collect_when_disabled: boolean
  adaptive_allow_sample_rate: number
  adaptive_risk_sample_rate: number
  output_audit_enabled: boolean
  output_allow_sample_rate: number
  output_risk_sample_rate: number
  effective_mode: PromptAuditMode
  strategy: 'priority'
  worker_count: number
  prompt_chunk_concurrency: number
  queue_capacity: number
  scanners: string[]
  all_groups: boolean
  group_ids: number[]
  whitelist_emails?: string[]
  endpoints: PromptAuditEndpoint[]
  config_version: number
  updated_at: string
  updated_by: number
  change_summary: string
}

export interface PromptPolicyVersion {
  id: number
  config_version: number
  endpoint_order: string[]
  created_by: number
  created_at: string
  change_summary: string
}

export interface PromptAuditDraft extends Omit<PromptAuditConfig, 'endpoints' | 'background_audit_mode' | 'whitelist_emails'> {
  background_audit_mode: PromptBackgroundAuditMode
  whitelist_emails: string[]
  endpoints: PromptAuditEndpointDraft[]
}

export interface PromptAuditUpdateRequest {
  expected_config_version: number
  enabled: boolean
  blocking_enabled: boolean
  blocking_audit_mode: PromptBlockingAuditMode
  background_audit_mode: PromptBackgroundAuditMode
  blocking_latest_turn_only: boolean
  store_pass_events: boolean
  adaptive_enabled: boolean
  adaptive_collect_when_disabled: boolean
  adaptive_allow_sample_rate: number
  adaptive_risk_sample_rate: number
  output_audit_enabled: boolean
  output_allow_sample_rate: number
  output_risk_sample_rate: number
  strategy: 'priority'
  worker_count: number
  prompt_chunk_concurrency: number
  queue_capacity: number
  scanners: string[]
  all_groups: boolean
  group_ids: number[]
  whitelist_emails: string[]
  endpoints: Array<{
    id: string
    name: string
    protocol: PromptAuditProtocol
    adapter: PromptAuditAdapter
    base_url: string
    model: string
    account_id: number
    token?: string
    clear_token: boolean
    timeout_ms: number
    input_limit: number
    enabled: boolean
  }>
}

export interface PromptProbeResult {
  ok: boolean
  status: string
  error_code?: string
  message: string
  latency_ms: number
  http_status: number
  retryable: boolean
  checked_at: string
  token_applied: boolean
}

export interface PromptQueueStats {
  staging: number
  queued: number
  processing: number
  retry: number
  done: number
  failed: number
  active: number
}

export interface PromptGuardMetrics {
  total: number
  allowed: number
  flagged: number
  blocked: number
  unavailable: number
  invalid: number
  timeouts: number
  failovers: number
  bulkhead_full: number
  record_failed: number
  latency_avg_ms?: number
  latency_p50_ms?: number
  latency_p95_ms?: number
  latency_p99_ms?: number
  latency_max_ms?: number
}

export interface PromptAuditUsagePeriod {
  invocations: number
  successes: number
  failures: number
  invalid: number
  input_tokens: number
  output_tokens: number
  cache_creation_tokens: number
  cache_read_tokens: number
  estimated_cost_usd: number
  priced_invocations: number
}

export interface PromptAuditAccountUsage extends PromptAuditUsagePeriod {
  account_id: number
  account_name: string
  account_email: string
}

export interface PromptAuditUsageOverview {
  today: PromptAuditUsagePeriod
  last_7_days: PromptAuditUsagePeriod
  all_time: PromptAuditUsagePeriod
  by_account: PromptAuditAccountUsage[]
}

export interface PromptAuditOAuthAccount {
  id: number
  name: string
  email: string
  status: string
  schedulable: boolean
}

export interface PromptAuditRuntime {
  process_status: 'disabled' | 'running' | 'degraded' | 'error' | string
  effective_mode: PromptAuditMode
  expected_config_version: number
  active_config_version: number
  config_loaded_at?: string
  config_load_error?: string
  worker_total: number
  worker_active: number
  worker_heartbeat_at?: string
  queue_capacity: number
  queue: PromptQueueStats
  processed_total: number
  failed_total: number
  enqueued_total: number
  dropped_total: number
  last_processed_at?: string
  last_error_code?: string
  last_error_message?: string
  database_status: string
  redis_status: string
  endpoints: Record<string, PromptProbeResult>
  guard_metrics: PromptGuardMetrics
  audit_usage: PromptAuditUsageOverview
  adaptive: {
    pending: number
    shadow_match: number
    disagreement: number
    shadow_failed: number
    reviewed_allow: number
    reviewed_block: number
    total: number
    last_updated_at?: string
  }
}

export interface PromptAdaptiveSample {
  id: number
  request_id: string
  user_id: number
  prompt_hash: string
  task_fingerprint: string
  stage: string
  audit_subject: string
  redacted_preview: string
  full_prompt: string
  config_version: number
  policy_version: number
  primary_endpoint_id: string
  shadow_endpoint_id: string
  primary_decision: PromptDecision
  shadow_decision: PromptDecision | ''
  primary_categories: string[]
  shadow_categories: string[]
  primary_intent_categories: string[]
  primary_content_categories: string[]
  shadow_intent_categories: string[]
  shadow_content_categories: string[]
  status: 'pending' | 'shadow_match' | 'disagreement' | 'shadow_failed' | string
  review_status: 'pending' | 'allow' | 'block' | string
  review_note: string
  reviewed_by: number
  reviewed_at?: string
  occurrence_count: number
  last_error_code: string
  created_at: string
  updated_at: string
}

export interface PromptAdaptiveSamplePage {
  items: PromptAdaptiveSample[]
  total: number
  page: number
  page_size: number
  pages: number
}

export interface PromptSnapshot {
  request_id: string
  user_id: number
  username: string
  user_email: string
  api_key_id: number
  api_key_name: string
  group_id?: number
  group_name: string
  provider: string
  endpoint: string
  protocol: string
  model: string
  prompt_hash: string
  task_fingerprint?: string
  audit_subject?: string
  redacted_preview: string
  full_prompt: string
  audited_prompt?: string
  prompt_length: number
  message_count: number
  stage: string
}

export interface PromptIssueSummary {
  category: string
  scanner_id: string
  title: string
  description: string
  severity: string
  severity_label: string
  action: string
  action_label: string
  code: string
  score: number
  evidence: string
  evidence_hash: string
  start_rune?: number
  end_rune?: number
}

export interface PromptAuditEvent {
  id: number
  job_id: number
  snapshot: PromptSnapshot
  audit_status?: 'audited' | 'gap' | string
  decision: PromptDecision
  risk_level: PromptRiskLevel
  action: 'Allow' | 'Warn' | 'Block' | string
  categories: string[]
  intent_categories: string[]
  content_categories: string[]
  matched_scanners: string[]
  scanner_scores: Record<string, number>
  scanner_evidence: Record<string, string>
  scanner_backend: string
  scanner_version: string
  guard_endpoint_id: string
  policy_id: string
  policy_version: number
  config_version: number
  chunk_total: number
  latency_ms: number
  issue_summaries: PromptIssueSummary[]
  duplicate_count?: number
  policy_source?: string
  policy_code?: string
  review_status?: string
  created_at: string
}

export interface PromptEventFilters {
  aggregate?: boolean
  decision: string
  risk_level: string
  endpoint: string
  group_id: string
  user_id: string
  api_key_id: string
  request_id: string
  prompt_hash: string
  keyword: string
  start_at: string
  end_at: string
}

export interface PromptEventPage {
  items: PromptAuditEvent[]
  total: number
  page: number
  page_size: number
  pages: number
}

export interface PromptDeleteResult {
  deleted_events: number
  deleted_jobs: number
}

export interface PromptDeletePreview {
  matched_count: number
  filter_summary: Record<string, unknown>
  snapshot_max_id: number
  filter_hash: string
  confirmation_token: string
  expires_at: string
}

export interface PromptAuditGroup {
  id: number
  name: string
  status: 'active' | 'inactive'
  platform: string
}

export interface PromptLoadErrors {
  config: string
  runtime: string
  groups: string
  accounts: string
  events: string
  adaptive: string
  policies: string
}
