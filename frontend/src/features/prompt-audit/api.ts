import { apiClient } from '@/api/client'
import { list as listAccounts } from '@/api/admin/accounts'
import type {
  PromptAuditConfig,
  PromptAuditEvent,
  PromptAuditGroup,
  PromptAuditRuntime,
  PromptAuditUpdateRequest,
  PromptDeletePreview,
  PromptDeleteResult,
  PromptEventFilters,
  PromptEventPage,
  PromptProbeResult,
  PromptAuditEndpointDraft,
  PromptAuditOAuthAccount,
  PromptAdaptiveSample,
  PromptAdaptiveSamplePage,
  PromptPolicyVersion,
} from './types'
import { eventFilterPayload, eventQueryParams } from './viewModel'

const basePath = '/admin/prompt-audit'

export async function getConfig(): Promise<PromptAuditConfig> {
  const { data } = await apiClient.get<PromptAuditConfig>(`${basePath}/config`)
  return data
}

export async function updateConfig(payload: PromptAuditUpdateRequest): Promise<PromptAuditConfig> {
  const { data } = await apiClient.put<PromptAuditConfig>(`${basePath}/config`, payload)
  return data
}

export async function listPolicyVersions(limit = 20): Promise<PromptPolicyVersion[]> {
  const { data } = await apiClient.get<PromptPolicyVersion[]>(`${basePath}/policy-versions`, {
    params: { limit },
  })
  return data
}

export async function rollbackPolicy(configVersion: number, expectedConfigVersion: number): Promise<PromptAuditConfig> {
  const { data } = await apiClient.post<PromptAuditConfig>(`${basePath}/policy-versions/${configVersion}/rollback`, {
    expected_config_version: expectedConfigVersion,
  })
  return data
}

export async function probeEndpoint(endpoint: PromptAuditEndpointDraft): Promise<PromptProbeResult> {
  const { data } = await apiClient.post<PromptProbeResult>(`${basePath}/endpoints/probe`, {
    endpoint: {
      id: endpoint.id,
      name: endpoint.name,
	  protocol: endpoint.protocol,
	  adapter: endpoint.adapter,
      base_url: endpoint.base_url,
      model: endpoint.model,
      account_id: endpoint.account_id,
      token: endpoint.token || undefined,
      clear_token: endpoint.clear_token,
      timeout_ms: endpoint.timeout_ms,
      input_limit: endpoint.input_limit,
      enabled: endpoint.enabled,
    },
  })
  return data
}

export async function getRuntime(): Promise<PromptAuditRuntime> {
  const { data } = await apiClient.get<PromptAuditRuntime>(`${basePath}/runtime`)
  return data
}

export async function listEvents(
  filters: PromptEventFilters,
  page: number,
  pageSize: number,
): Promise<PromptEventPage> {
  const { data } = await apiClient.get<PromptEventPage>(`${basePath}/events`, {
    params: { page, page_size: pageSize, ...eventQueryParams(filters) },
  })
  return data
}

export async function getEvent(id: number): Promise<PromptAuditEvent> {
  const { data } = await apiClient.get<PromptAuditEvent>(`${basePath}/events/${id}`)
  return data
}

export async function deleteEvent(id: number): Promise<PromptDeleteResult> {
  const { data } = await apiClient.delete<PromptDeleteResult>(`${basePath}/events/${id}`)
  return data
}

export async function batchDeleteEvents(ids: number[]): Promise<PromptDeleteResult> {
  const { data } = await apiClient.post<PromptDeleteResult>(`${basePath}/events/batch-delete`, { ids })
  return data
}

export async function previewDelete(filters: PromptEventFilters): Promise<PromptDeletePreview> {
  const { data } = await apiClient.post<PromptDeletePreview>(
    `${basePath}/events/delete-preview`,
    eventFilterPayload(filters),
  )
  return data
}

export async function deleteEventsByFilter(
  filters: PromptEventFilters,
  preview: PromptDeletePreview,
): Promise<PromptDeleteResult> {
  const { data } = await apiClient.post<PromptDeleteResult>(`${basePath}/events/delete-by-filter`, {
    filter: eventFilterPayload(filters),
    snapshot_max_id: preview.snapshot_max_id,
    filter_hash: preview.filter_hash,
    confirmation_token: preview.confirmation_token,
    confirm: true,
  })
  return data
}

export async function listGroups(): Promise<PromptAuditGroup[]> {
  const { data } = await apiClient.get<PromptAuditGroup[]>('/admin/groups/all', {
    params: { include_inactive: true },
  })
  return data
}

export async function listOpenAIOAuthAccounts(): Promise<PromptAuditOAuthAccount[]> {
  const result = await listAccounts(1, 100, {
    platform: 'openai', type: 'oauth', sort_by: 'name', sort_order: 'asc',
  })
  return result.items.map((account) => ({
    id: account.id,
    name: account.name,
    email: typeof account.credentials?.email === 'string' ? account.credentials.email : '',
    status: account.status,
    schedulable: account.schedulable,
  }))
}

export async function listAdaptiveSamples(
  status: string,
  page: number,
  pageSize: number,
): Promise<PromptAdaptiveSamplePage> {
  const { data } = await apiClient.get<PromptAdaptiveSamplePage>(`${basePath}/adaptive-samples`, {
    params: { status, page, page_size: pageSize },
  })
  return data
}

export async function reviewAdaptiveSample(
  id: number,
  decision: 'allow' | 'block',
  note = '',
): Promise<PromptAdaptiveSample> {
  const { data } = await apiClient.post<PromptAdaptiveSample>(`${basePath}/adaptive-samples/${id}/review`, {
    decision,
    note,
  })
  return data
}

export const promptAuditAPI = {
  getConfig,
  updateConfig,
  listPolicyVersions,
  rollbackPolicy,
  probeEndpoint,
  getRuntime,
  listEvents,
  getEvent,
  deleteEvent,
  batchDeleteEvents,
  previewDelete,
  deleteEventsByFilter,
  listGroups,
  listOpenAIOAuthAccounts,
  listAdaptiveSamples,
  reviewAdaptiveSample,
}

export default promptAuditAPI
