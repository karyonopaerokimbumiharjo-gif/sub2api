import type {
  PromptAuditConfig,
  PromptAuditDraft,
  PromptAuditEndpointDraft,
  PromptAuditUpdateRequest,
  PromptEventFilters,
} from './types'

import { JEV_BASE_URL, JEV_MODEL, JEV_PROTOCOL } from './securityViewModel'

export const DEFAULT_GUARD_MODEL = 'sileader/qwen3guard:0.6b'
export const DEFAULT_ANTIGRAVITY_AUDIT_MODEL = 'gemini-3.6-flash-low'
export const DEFAULT_OPENAI_INTERNAL_AUDIT_MODEL = 'gpt-5.3-codex-spark'
export const DEFAULT_PROMPT_CHUNK_CONCURRENCY = 4
export const DEFAULT_ADAPTIVE_ALLOW_SAMPLE_RATE = 5
export const DEFAULT_ADAPTIVE_RISK_SAMPLE_RATE = 100
export const DEFAULT_OUTPUT_ALLOW_SAMPLE_RATE = 5
export const DEFAULT_OUTPUT_RISK_SAMPLE_RATE = 100

export const SCANNER_CATALOG = [
  { id: 'violent', label: 'Violent' },
  { id: 'non_violent_illegal_acts', label: 'Non-violent Illegal Acts' },
  { id: 'biological_risk', label: 'Biological Risk' },
  { id: 'sexual_content_or_sexual_acts', label: 'Sexual Content or Sexual Acts' },
  { id: 'pii', label: 'PII' },
  { id: 'suicide_and_self_harm', label: 'Suicide & Self-Harm' },
  { id: 'unethical_acts', label: 'Unethical Acts' },
  { id: 'politically_sensitive_topics', label: 'Politically Sensitive Topics' },
  { id: 'copyright_violation', label: 'Copyright Violation' },
  { id: 'jailbreak', label: 'Jailbreak' },
] as const

export const CONTENT_CATEGORY_CATALOG = [
  'harassment', 'harassment_threatening', 'hate', 'hate_threatening',
  'illicit', 'illicit_violent', 'self_harm', 'self_harm_intent',
  'self_harm_instructions', 'sexual', 'sexual_minors', 'violence', 'violence_graphic',
] as const

// Vue props/refs are proxies and cannot be passed to structuredClone in every
// browser. Prompt Audit state is JSON-only, so this produces a detached draft
// without retaining reactive proxies or browser storage references.
export function cloneData<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T
}

export function configToDraft(config: PromptAuditConfig): PromptAuditDraft {
  return {
    ...cloneData(config),
	blocking_audit_mode: config.blocking_audit_mode ?? (config.blocking_latest_turn_only ? 'incremental_full' : 'full'),
	background_audit_mode: config.background_audit_mode ?? (config.blocking_enabled ? 'off' : (config.blocking_audit_mode ?? 'full')),
	adaptive_enabled: config.adaptive_enabled ?? false,
	adaptive_collect_when_disabled: config.adaptive_collect_when_disabled ?? true,
	adaptive_allow_sample_rate: Number.isFinite(Number(config.adaptive_allow_sample_rate)) ? Number(config.adaptive_allow_sample_rate) : DEFAULT_ADAPTIVE_ALLOW_SAMPLE_RATE,
	adaptive_risk_sample_rate: Number.isFinite(Number(config.adaptive_risk_sample_rate)) ? Number(config.adaptive_risk_sample_rate) : DEFAULT_ADAPTIVE_RISK_SAMPLE_RATE,
	output_audit_enabled: config.output_audit_enabled ?? false,
	output_allow_sample_rate: Number.isFinite(Number(config.output_allow_sample_rate)) ? Number(config.output_allow_sample_rate) : DEFAULT_OUTPUT_ALLOW_SAMPLE_RATE,
	output_risk_sample_rate: Number.isFinite(Number(config.output_risk_sample_rate)) ? Number(config.output_risk_sample_rate) : DEFAULT_OUTPUT_RISK_SAMPLE_RATE,
    whitelist_emails: [...(config.whitelist_emails ?? [])],
    prompt_chunk_concurrency: Number(config.prompt_chunk_concurrency) || DEFAULT_PROMPT_CHUNK_CONCURRENCY,
    group_ids: [...(config.group_ids ?? [])],
    scanners: [...(config.scanners ?? [])],
    endpoints: (config.endpoints ?? []).map((endpoint) => {
      const protocol = endpoint.protocol ?? 'openai_compatible'
      return {
        ...endpoint,
        protocol,
        adapter: endpoint.adapter ?? (protocol === 'openai_compatible' ? 'qwen3guard' : 'generic_llm'),
        account_id: Number(endpoint.account_id) || 0,
        token: '',
        clear_token: false,
      }
    }),
  }
}

export function createDefaultEndpoint(index = 1): PromptAuditEndpointDraft {
  return {
    id: `guard-${Date.now()}-${index}`,
    name: `Guard ${index}`,
    protocol: JEV_PROTOCOL,
    base_url: JEV_BASE_URL,
    model: JEV_MODEL,
    timeout_ms: 3000,
    adapter: 'generic_llm',
    account_id: 0,
    input_limit: 4000,
    enabled: false,
    has_token: false,
    token_status: 'missing',
    token: '',
    clear_token: false,
  }
}

export function buildUpdateRequest(draft: PromptAuditDraft): PromptAuditUpdateRequest {
  return {
    expected_config_version: draft.config_version,
    enabled: draft.enabled,
    blocking_enabled: draft.enabled && draft.blocking_enabled,
    blocking_audit_mode: draft.blocking_audit_mode,
    background_audit_mode: draft.background_audit_mode,
    blocking_latest_turn_only: draft.blocking_audit_mode !== 'full',
    store_pass_events: draft.store_pass_events,
	adaptive_enabled: draft.adaptive_enabled,
	adaptive_collect_when_disabled: draft.adaptive_collect_when_disabled,
	adaptive_allow_sample_rate: Number(draft.adaptive_allow_sample_rate),
	adaptive_risk_sample_rate: Number(draft.adaptive_risk_sample_rate),
	output_audit_enabled: draft.output_audit_enabled,
	output_allow_sample_rate: Number(draft.output_allow_sample_rate),
	output_risk_sample_rate: Number(draft.output_risk_sample_rate),
    strategy: 'priority',
    worker_count: Number(draft.worker_count),
    prompt_chunk_concurrency: Number(draft.prompt_chunk_concurrency),
    queue_capacity: Number(draft.queue_capacity),
    scanners: [...draft.scanners],
    all_groups: draft.all_groups,
    group_ids: draft.all_groups ? [] : [...draft.group_ids].sort((a, b) => a - b),
    whitelist_emails: [...new Set(draft.whitelist_emails.map((email) => email.trim().toLowerCase()).filter(Boolean))].sort(),
    endpoints: draft.endpoints.map((endpoint) => ({
      id: endpoint.id.trim(),
      name: endpoint.name.trim(),
      protocol: endpoint.protocol,
      adapter: endpoint.adapter,
      base_url: endpoint.base_url.trim(),
      model: endpoint.model.trim() || (
        endpoint.protocol === JEV_PROTOCOL ? JEV_MODEL : endpoint.protocol === 'antigravity_internal'
          ? DEFAULT_ANTIGRAVITY_AUDIT_MODEL
          : endpoint.protocol === 'openai_internal'
            ? DEFAULT_OPENAI_INTERNAL_AUDIT_MODEL
            : DEFAULT_GUARD_MODEL
      ),
      account_id: endpoint.protocol === 'openai_internal' ? Number(endpoint.account_id) || 0 : 0,
      token: endpoint.token.trim() || undefined,
      clear_token: endpoint.clear_token,
      timeout_ms: Number(endpoint.timeout_ms),
      input_limit: Number(endpoint.input_limit),
      enabled: endpoint.enabled,
    })),
  }
}

export function draftFingerprint(draft: PromptAuditDraft | null): string {
  if (!draft) return ''
  return JSON.stringify(buildUpdateRequest(draft))
}

export function emptyEventFilters(): PromptEventFilters {
  return {
    aggregate: true,
    decision: '',
    risk_level: '',
    endpoint: '',
    group_id: '',
    user_id: '',
    api_key_id: '',
    request_id: '',
    prompt_hash: '',
    keyword: '',
    start_at: '',
    end_at: '',
  }
}

function toISO(value: string): string | undefined {
  if (!value.trim()) return undefined
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString()
}

export function eventQueryParams(filters: PromptEventFilters): Record<string, string | number | boolean> {
  const result: Record<string, string | number | boolean> = { aggregate: filters.aggregate !== false }
  for (const key of ['decision', 'risk_level', 'endpoint', 'request_id', 'prompt_hash', 'keyword'] as const) {
    const value = filters[key].trim()
    if (value) result[key] = value
  }
  for (const key of ['group_id', 'user_id', 'api_key_id'] as const) {
    const value = Number(filters[key])
    if (Number.isInteger(value) && value > 0) result[key] = value
  }
  const start = toISO(filters.start_at)
  const end = toISO(filters.end_at)
  if (start) result.start_at = start
  if (end) result.end_at = end
  return result
}

export function eventFilterPayload(filters: PromptEventFilters): Record<string, unknown> {
  const payload = eventQueryParams(filters)
  delete payload.aggregate
  return payload
}

export function hasExplicitDeleteRange(filters: PromptEventFilters): boolean {
  const start = toISO(filters.start_at)
  const end = toISO(filters.end_at)
  return Boolean(start && end && new Date(start).getTime() < new Date(end).getTime())
}

export type DeleteRangePreset = '1d' | '7d' | '30d' | '90d' | 'all' | 'custom'

export const DELETE_RANGE_PRESETS: ReadonlyArray<{ id: DeleteRangePreset; days: number | null }> = [
  { id: '1d', days: 1 },
  { id: '7d', days: 7 },
  { id: '30d', days: 30 },
  { id: '90d', days: 90 },
  { id: 'all', days: null },
  { id: 'custom', days: null },
]

const DAY_MS = 24 * 60 * 60 * 1000

// Presets delete events older than the chosen cutoff: the range always starts
// at the epoch and ends at (now - days) so the backend's explicit-range
// requirement is satisfied without asking the user for a begin date.
export function resolveDeleteRangeFilters(
  filters: PromptEventFilters,
  preset: DeleteRangePreset,
  now: number = Date.now(),
): PromptEventFilters {
  const resolved = cloneData(filters)
  if (preset === 'custom') return resolved
  const days = DELETE_RANGE_PRESETS.find((item) => item.id === preset)?.days ?? null
  resolved.start_at = new Date(0).toISOString()
  resolved.end_at = new Date(days === null ? now : now - days * DAY_MS).toISOString()
  return resolved
}
