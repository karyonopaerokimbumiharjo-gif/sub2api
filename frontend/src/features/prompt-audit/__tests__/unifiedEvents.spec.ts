import { describe, expect, it, vi } from 'vitest'
import { defineComponent, ref } from 'vue'
import { mount } from '@vue/test-utils'
import EventWorkspace from '../components/EventWorkspace.vue'
import EventDetailDialog from '../components/EventDetailDialog.vue'
import type { PromptAuditEvent } from '../types'
import { emptyEventFilters, eventFilterPayload, eventQueryParams } from '../viewModel'

vi.mock('vue-i18n', async () => {
  const actual = await vi.importActual<typeof import('vue-i18n')>('vue-i18n')
  return { ...actual, useI18n: () => ({ locale: ref('en'), t: (key: string) => key }) }
})

const DialogStub = defineComponent({ props: ['show'], template: '<div v-if="show"><slot /></div>' })
const nativeEvent = (): PromptAuditEvent => ({
  id: -7, native_log_id: 7, event_origin: 'content_moderation', event_key: 'content_moderation:7', audit_source: 'native',
  content_availability: 'full', native_action: 'allow', native_engine_meta: { model: 'audit-model', rules_version: 'rules-v1' },
  job_id: 0, audit_status: 'audited', decision: 'pass', risk_level: 'low', action: 'Allow',
  categories: [], intent_categories: [], content_categories: [], matched_scanners: [], scanner_scores: {}, scanner_evidence: {},
  scanner_backend: 'openai_moderation', scanner_version: 'audit-model', guard_endpoint_id: '', policy_id: '',
  policy_version: 0, config_version: 0, chunk_total: 1, latency_ms: 25, issue_summaries: [], created_at: '2026-09-26T00:00:00Z',
  snapshot: {
    request_id: 'native-request-7', user_id: 2, username: 'alice', user_email: '', api_key_id: 3, api_key_name: 'review-key',
    group_name: 'pro', provider: 'openai', endpoint: '/v1/responses', protocol: 'openai_responses', model: 'request-model',
    prompt_hash: 'a'.repeat(64), redacted_preview: 'preview only', full_prompt: 'complete request context',
    audited_prompt: 'actual audited input', prompt_length: 24, message_count: 1, stage: 'native_content_moderation',
  },
})

describe('Unified audit events', () => {
  it('shows each source and limits batch selection to records that can be deleted', async () => {
    const native = nativeEvent()
    const legacy = { ...native, id: 7, native_log_id: undefined, event_origin: 'prompt_audit' as const, event_key: 'prompt_audit:7', audit_source: 'legacy' as const }
    const hardRule = { ...legacy, id: 8, event_key: 'prompt_audit:8', audit_source: 'native' as const }
    const wrapper = mount(EventWorkspace, {
      props: { events: [native, legacy, hardRule], total: 3, page: 1, pageSize: 20, filters: emptyEventFilters(), selectedIds: [], loading: false, error: '' },
      global: { stubs: { Pagination: true } },
    })
    expect(wrapper.get('[data-test="event--7"] [data-test="event-audit-source"]').text()).toBe('admin.promptAudit.events.auditSources.native')
    expect(wrapper.get('[data-test="event-7"] [data-test="event-audit-source"]').text()).toBe('admin.promptAudit.events.auditSources.legacy')
    expect(wrapper.get('[data-test="event--7"] input').attributes()).toHaveProperty('disabled')
    expect(wrapper.get('[data-test="event--7"]').findAll('button').some(button => button.text() === 'common.delete')).toBe(false)
    await wrapper.get('[aria-label="admin.promptAudit.events.selectAll"]').setValue(true)
    expect(wrapper.emitted('selection')?.at(-1)?.[0]).toEqual([7, 8])
    await wrapper.get('[data-test="event--7"]').findAll('button').find(button => button.text() === 'common.view')!.trigger('click')
    expect(wrapper.emitted('view')?.at(-1)).toEqual([-7])
    await wrapper.get('[data-test="audit-source-filter"]').setValue('native')
    await wrapper.get('form').trigger('submit')
    expect(wrapper.emitted('search')?.at(-1)?.[0]).toMatchObject({ audit_source: 'native', aggregate: true })
  })

  it('preserves the selected audit source in list and deletion filters', () => {
    const filters = { ...emptyEventFilters(), audit_source: 'native' as const }
    expect(eventQueryParams(filters)).toEqual({ aggregate: true, audit_source: 'native' })
    expect(eventFilterPayload(filters)).toEqual({ audit_source: 'native' })
  })

  it('displays actual native audited content and retained engine metadata', async () => {
    const wrapper = mount(EventDetailDialog, {
      props: { show: true, loading: false, event: nativeEvent() },
      global: { stubs: { BaseDialog: DialogStub } },
    })
    expect(wrapper.get('[data-test="detail-audit-source"]').text()).toContain('admin.promptAudit.events.auditSources.native')
    expect(wrapper.get('[data-test="summary-prompt-full"]').text()).toBe('complete request context')
    expect(wrapper.get('[data-test="summary-audited-prompt"]').text()).toBe('actual audited input')
    expect(wrapper.get('[data-test="risk-guard-return"]').text()).toContain('rules-v1')
    expect(wrapper.find('[data-test="content-availability"]').exists()).toBe(false)
    await wrapper.setProps({ event: { ...nativeEvent(), content_availability: 'truncated' } })
    expect(wrapper.get('[data-test="content-availability"]').text()).toBe('admin.promptAudit.events.contentAvailability.truncated')
  })

  it('does not reconstruct missing native audit content from an old preview', () => {
    const event = nativeEvent()
    event.content_availability = 'excerpt_only'
    event.snapshot.full_prompt = ''
    event.snapshot.audited_prompt = ''
    const wrapper = mount(EventDetailDialog, {
      props: { show: true, loading: false, event },
      global: { stubs: { BaseDialog: DialogStub } },
    })
    expect(wrapper.get('[data-test="content-availability"]').text()).toBe('admin.promptAudit.events.contentAvailability.excerpt_only')
    expect(wrapper.get('[data-test="summary-prompt-full"]').text()).toBe('preview only')
    expect(wrapper.get('[data-test="summary-audited-prompt"]').text()).toBe('admin.promptAudit.events.auditedContentNotStored')
    expect(wrapper.get('[data-test="risk-prompt-full"]').text()).not.toContain('preview only')
  })

  it('keeps failed native audits distinct from confirmed violations and rejected reviews', () => {
    const event = { ...nativeEvent(), audit_status: 'error', decision: 'review_required' as const, action: 'Warn', native_action: 'error', native_error: 'audit_unavailable' }
    const wrapper = mount(EventDetailDialog, {
      props: { show: true, loading: false, event },
      global: { stubs: { BaseDialog: DialogStub } },
    })
    expect(wrapper.get('[data-test="audit-failed"]').text()).toBe('admin.promptAudit.events.auditFailedHint')
    expect(wrapper.get('[data-test="risk-guard-return"]').text()).toContain('admin.promptAudit.events.auditFailed')
    expect(wrapper.text()).not.toContain('admin.promptAudit.events.reviewRequiredHint')
    expect(wrapper.find('[data-test="policy-review"]').exists()).toBe(false)
  })
})
