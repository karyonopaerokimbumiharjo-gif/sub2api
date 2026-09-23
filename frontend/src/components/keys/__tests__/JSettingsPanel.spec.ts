import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { ref } from 'vue'
const api = vi.hoisted(() => ({ get: vi.fn(), put: vi.fn() }))
vi.mock('@/api/client', () => ({ default: api }))
vi.mock('vue-i18n', () => ({ useI18n: () => ({ locale: ref('zh') }) }))
import JSettingsPanel from '../JSettingsPanel.vue'
beforeEach(() => { vi.clearAllMocks() })
describe('persisted J settings', () => {
  it('reads saved key state, saves changes and offers only supplied base models', async () => {
    api.get.mockResolvedValue({ data: { enabled: false } })
    api.put.mockResolvedValue({ data: { enabled: true } })
    const w = mount(JSettingsPanel, { props: { apiKeyId: 7, enabled: false, baseModel: '', models: ['gpt-5.6-sol'] } })
    await flushPromises()
    expect(api.get).toHaveBeenCalledWith('/keys/7/j')
    await w.get('input').setValue(true); await flushPromises()
    expect(api.put).toHaveBeenCalledWith('/keys/7/j', { enabled: true })
    expect(w.emitted('update:enabled')?.at(-1)).toEqual([true])
    await w.setProps({ enabled: true })
    expect(w.findAll('option').map(o => o.text())).toEqual(['gpt-5.6-sol'])
  })
  it('does not report enabled when saving fails', async () => {
    api.get.mockResolvedValue({ data: { enabled: false } }); api.put.mockRejectedValue(Error('offline'))
    const w = mount(JSettingsPanel, { props: { apiKeyId: 7, enabled: false, baseModel: '', models: [] } })
    await flushPromises(); await w.get('input').setValue(true); await flushPromises()
    expect(w.emitted('update:enabled')?.flat()).not.toContain(true)
    expect(w.get('[role="alert"]').text()).toContain('保存失败')
  })
})
