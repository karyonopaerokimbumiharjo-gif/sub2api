import { mount, flushPromises } from '@vue/test-utils'
import { describe, expect, it, vi, beforeEach } from 'vitest'
import ResearchProfiles from '../components/ResearchProfiles.vue'
const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), delete: vi.fn() }))
vi.mock('@/api/client', () => ({ default: api }))
vi.mock('vue-i18n', () => ({ useI18n: () => ({ locale: { value: 'zh' } }) }))
beforeEach(() => { vi.clearAllMocks(); api.get.mockImplementation((url: string) => Promise.resolve({ data: url.endsWith('bio-catalog') ? { tiers: [{ tier: 'B2', description: 'Review required', action: 'review_required' }] } : [] })) })
describe('Verified research approval', () => {
 it('loads only when expanded and keeps the no-bypass policy visible', async () => {
  const w = mount(ResearchProfiles)
  expect(api.get).not.toHaveBeenCalled()
  const details = w.get('details'); (details.element as HTMLDetailsElement).open = true; await details.trigger('toggle'); await flushPromises()
  expect(w.text()).toContain('B2'); expect(w.text()).toContain('不解除 B3/B4')
  expect(api.get).toHaveBeenCalledTimes(2)
 })
 it('keeps a load failure visible instead of showing successful approval', async () => {
  api.get.mockRejectedValue(new Error('offline'))
  const w = mount(ResearchProfiles); const details = w.get('details'); (details.element as HTMLDetailsElement).open = true; await details.trigger('toggle'); await flushPromises()
  expect(w.get('[role="alert"]').text()).toContain('操作失败')
  expect(api.post).not.toHaveBeenCalled()
 })
})
