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
const render = (authName = 'test.json') => mount(CPACredentialsModal, { props: { show: true, authName }, global: { stubs: { BaseDialog: Dialog } } })

describe('CPA runtime save feedback', () => {
  it('does not silently select a different credential when the requested binding is missing', async () => {
    const wrapper = render('missing.json'); await flushPromises()
    expect(wrapper.get('[role=alert]').text()).toContain('未选择其他账号')
    expect(wrapper.find('[data-testid=cpa-runtime-fields]').exists()).toBe(false)
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(mocks.save).not.toHaveBeenCalled()
  })
  it('requires an explicit choice when no credential is bound', async () => {
    const wrapper = render(''); await flushPromises()
    expect(wrapper.find('[data-testid=cpa-runtime-fields]').exists()).toBe(false)
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(mocks.save).not.toHaveBeenCalled()
    await wrapper.get('[data-testid=cpa-credential-choice]').setValue('test.json')
    expect(wrapper.find('[data-testid=cpa-runtime-fields]').exists()).toBe(true)
  })
  it('identifies saved CPA settings separately from the Pi business backend', async () => {
    mocks.list.mockResolvedValue([{...credential, business_backend:'pi', cpa_routing_enabled:false, proxy_id:9, proxy_configured:true}])
    const wrapper = render(); await flushPromises()
    expect(wrapper.get('[data-testid=cpa-routing-status]').text()).toContain('业务账号当前使用 Pi')
    expect(wrapper.get('[data-testid=cpa-routing-status]').text()).toContain('不代表 Pi 的实际出口')
    expect(wrapper.text()).toContain('不可用或未加载')
    expect(wrapper.find('[data-testid=cpa-credential-choice]').exists()).toBe(false)
  })
  it('discards an earlier credential lookup when the account target changes', async () => {
    let finish!: (items: object[]) => void
    mocks.list.mockImplementationOnce(() => new Promise(resolve => { finish = resolve }))
    const wrapper = render('old.json')
    await wrapper.setProps({authName:'test.json'}); await flushPromises()
    finish([{...credential, name:'old.json'}]); await flushPromises()
    await wrapper.get('form').trigger('submit'); await flushPromises()
    expect(mocks.save).toHaveBeenCalledWith(expect.objectContaining({name:'test.json'}))
  })

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
