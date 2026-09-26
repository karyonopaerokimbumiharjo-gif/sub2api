import { defineComponent } from 'vue'
import { mount, flushPromises } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import LocalAuditControls from '../components/LocalAuditControls.vue'
const mocks = vi.hoisted(() => ({ getConfig: vi.fn(), updateConfig: vi.fn() }))
vi.mock('@/api/admin', () => ({ adminAPI: { riskControl: mocks } }))
const Dialog = defineComponent({ props: ['show'], template: '<div v-if="show"><slot /><slot name="footer" /></div>' })
describe('local audit shared controls', () => {
  it('saves only response and keyword controls without changing the selected engine or credentials', async () => {
    mocks.getConfig.mockResolvedValue({ engine: 'typesafe', enabled: true, api_key_masked: 'masked-only', block_status: 403,
      block_message: 'refused', email_on_hit: true, auto_ban_enabled: false, ban_threshold: 10, violation_window_hours: 720,
      cyber_policy_exclude_from_ban_count: false, keyword_blocking_mode: 'keyword_and_api', blocked_keywords: [] })
    mocks.updateConfig.mockResolvedValue({})
    const wrapper = mount(LocalAuditControls, { global: { stubs: { BaseDialog: Dialog } } })
    await wrapper.get('[data-test="open-local-audit-controls"]').trigger('click')
    await flushPromises()
    await wrapper.get('textarea').setValue('test marker\ntest marker')
    const save = wrapper.findAll('button').find(b => b.text() === '保存内容审计配置')!
    await save.trigger('click'); await flushPromises()
    expect(mocks.updateConfig).toHaveBeenCalledWith(expect.objectContaining({ blocked_keywords: ['test marker'], email_on_hit: true }))
    const payload = mocks.updateConfig.mock.calls[0]![0]
    for (const key of ['engine', 'enabled', 'api_keys', 'clear_api_key', 'model', 'thresholds']) expect(payload).not.toHaveProperty(key)
    wrapper.unmount()
  })
})
