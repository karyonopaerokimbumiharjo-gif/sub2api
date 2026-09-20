import type { PromptAuditEndpointDraft } from './types'

export const JEV_PROTOCOL = 'typesafe_systemone' as const
export const JEV_MODEL = 'jev-1.13.0'
export const JEV_BASE_URL = 'https://api.typesafe.ai'

export function createLatestRequestGate() {
  let generation = 0
  return {
    begin: () => ++generation,
    isCurrent: (ticket: number) => ticket === generation,
    invalidate: () => { generation++ },
  }
}

export function changeAuditProvider(
  endpoint: PromptAuditEndpointDraft,
  protocol: PromptAuditEndpointDraft['protocol'],
): PromptAuditEndpointDraft {
  if (protocol === endpoint.protocol) return { ...endpoint }
  return {
    ...endpoint,
    protocol,
    token: '',
    clear_token: endpoint.has_token,
    enabled: false,
    base_url: protocol === JEV_PROTOCOL ? JEV_BASE_URL : 'http://cpa:8317',
    model: protocol === JEV_PROTOCOL ? JEV_MODEL : 'sileader/qwen3guard:0.6b',
    input_limit: Math.min(4000, endpoint.input_limit),
  }
}

export function validateAuditEndpoint(
  endpoint: PromptAuditEndpointDraft,
  others: readonly PromptAuditEndpointDraft[],
  editingIndex: number,
): string {
  if (!endpoint.id.trim() || !endpoint.name.trim()) return 'identity'
  if (others.some((other, i) => i !== editingIndex && other.id.trim() === endpoint.id.trim())) return 'duplicate'
  if (!Number.isInteger(endpoint.timeout_ms) || endpoint.timeout_ms < 100 || endpoint.timeout_ms > 30000) return 'timeout'
  const max = endpoint.protocol === JEV_PROTOCOL ? 4000 : 100000
  if (!Number.isInteger(endpoint.input_limit) || endpoint.input_limit < 128 || endpoint.input_limit > max) return 'input'
  if (endpoint.protocol !== JEV_PROTOCOL && endpoint.protocol !== 'openai_compatible') return 'protocol'
  let url: URL
  try { url = new URL(endpoint.base_url.trim()) } catch { return 'url' }
  if (url.username || url.password || url.search || url.hash || !['http:', 'https:'].includes(url.protocol)) return 'url'
  if (endpoint.protocol === JEV_PROTOCOL) {
    if (!/^https:\/\/api\.typesafe\.ai(?:\/(?:v1\/?)?)?$/.test(endpoint.base_url.trim())) return 'jevOrigin'
    if (!/^jev-\d+\.\d+\.\d+$/.test(endpoint.model.trim())) return 'model'
    if (endpoint.enabled && !(endpoint.token.trim() || (endpoint.has_token && !endpoint.clear_token && endpoint.token_status !== 'invalid'))) return 'credential'
  }
  return ''
}

export function auditEndpointError(code: string, locale: string): string {
  const zh: Record<string, string> = {
    identity: '节点 ID 和名称不能为空。',
    duplicate: '节点 ID 已存在。',
    timeout: '超时必须为 100–30000 毫秒的整数。',
    input: '输入上限无效；Jev 节点支持 128–4000 个字符。',
    protocol: '不支持该审查协议。',
    url: '节点地址无效，不能包含凭据、查询参数或片段。',
    jevOrigin: 'Jev 仅允许 https://api.typesafe.ai 或其 /v1 基地址。',
    model: '请填写固定版本，例如 jev-1.13.0，不使用漂移别名。',
    credential: '启用 Jev 前必须配置有效凭据。切换服务商后需重新输入凭据。',
  }
  const en: Record<string, string> = {
    identity: 'Node ID and name are required.',
    duplicate: 'Node ID already exists.',
    timeout: 'Timeout must be an integer between 100 and 30000 ms.',
    input: 'Invalid input limit. Jev supports 128–4000 characters per chunk.',
    protocol: 'Unsupported audit protocol.',
    url: 'Invalid endpoint; credentials, query strings and fragments are not allowed.',
    jevOrigin: 'Jev requires https://api.typesafe.ai or its /v1 base URL.',
    model: 'Use a pinned version such as jev-1.13.0, not a floating alias.',
    credential: 'A valid credential is required before enabling Jev. Re-enter it after changing providers.',
  }
  return (locale.startsWith('zh') ? zh : en)[code] ?? code
}

export function auditDescription(locale: string): string {
  return locale.startsWith('zh')
    ? '文本输入审查：规则脱敏后的文本将发送至 TypeSafe；规则脱敏不等于完整 DLP。既有内容审核不变，新事件不保存未脱敏全文。节点可用不等于策略有效，启用阻断前需完成中文与英文回归评测。'
    : 'Text-input screening: rule-redacted text is sent to TypeSafe; this is not comprehensive DLP. Existing content moderation is unchanged. New events do not store raw prompts. Endpoint availability is not policy accuracy; evaluate before enabling blocking.'
}
