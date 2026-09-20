import { defineComponent } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({ list: vi.fn(), save: vi.fn(), proxies: vi.fn() }))
vi.mock('@/api/admin/accounts', () => ({ listCPACredentials: mocks.list, updateCPACredential: mocks.save }))
vi.mock('@/api/admin/proxies', () => ({ getAll: mocks.proxies }))
vi.mock('vue-i18n', () => ({ useI18n: () => ({ locale: { value: 'zh' } }) }))
import CPACredentialsModal from '../CPACredentialsModal.vue'

const credential = { name: 'test.json', email: 'test@example.invalid', provider: 'codex', status: 'active', disabled: false, proxy_id: null, proxy_configured: false, priority: 2, weight: 1, request_retry: 0 }
const Dialog = defineComponent({ template: '<div><slot/></div>' })
const render = () => mount(CPACredentialsModal, { props: { show: true }, global: { stubs: { BaseDialog: Dialog } } })

describe('CPA runtime save feedback', () => {
  beforeEach(() => { vi.clearAllMocks(); mocks.list.mockResolvedValue([{...credential}]); mocks.proxies.mockResolvedValue([]); mocks.save.mockResolvedValue({...credential}) })
  it('shows verified success only until the next edit', async () => {
    const wrapper = render(); await flushPromises()
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(mocks.save).toHaveBeenCalledWith(expect.objectContaining({name:'test.json', priority:2}))
    expect(wrapper.get('[role="status"]').text()).toContain('回读核对')
    await wrapper.findAll('input[type="number"]')[0].setValue('7')
    expect(wrapper.find('[role="status"]').exists()).toBe(false)
  })
  it('surfaces a failed CPA write without showing success', async () => {
    mocks.save.mockRejectedValue({response:{data:{message:'CPA unavailable'}}})
    const wrapper = render(); await flushPromises()
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toBe('CPA unavailable')
    expect(wrapper.find('[role="status"]').exists()).toBe(false)
  })
})
