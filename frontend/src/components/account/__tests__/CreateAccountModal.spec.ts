import { defineComponent, ref } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({ files: vi.fn(), oauth: vi.fn(), refresh: vi.fn(), exchange: vi.fn(), create: vi.fn() }))
vi.mock('@/api/admin', () => ({ adminAPI: { accounts: { importCPAAuthFiles: mocks.files, importOpenAIOAuthToCPA: mocks.oauth, create: mocks.create } } }))
vi.mock('vue-i18n', () => ({ useI18n: () => ({ locale: { value: 'zh' }, t: (key: string) => key }) }))
vi.mock('@/composables/useOpenAIOAuth', () => ({ useOpenAIOAuth: () => ({
  authUrl: ref(''), sessionId: ref('session'), oauthState: ref('expected-state'), loading: ref(false), error: ref(''),
  generateAuthUrl: vi.fn(), resetState: vi.fn(), validateRefreshToken: mocks.refresh, exchangeAuthCode: mocks.exchange,
  buildCredentials: (value: Record<string, unknown>) => ({ ...value })
}) }))
vi.mock('../CPABridgeSetup.vue', () => ({default: {template: '<div />'}}))
import CreateAccountModal from '../CreateAccountModal.vue'
const Dialog = defineComponent({ props: ['show'], template: '<div v-if="show"><slot/><slot name="footer"/></div>' })
const render = () => mount(CreateAccountModal, { props: { show: true }, global: { stubs: { BaseDialog: Dialog, CPABridgeSetup: true } } })

describe('CPA-only account import', () => {
  beforeEach(() => { vi.clearAllMocks(); mocks.files.mockResolvedValue({ created: 1, updated: 0, failed: 0, errors: [] }); mocks.oauth.mockResolvedValue({ bridge_account_id: 30 }) })
  it('exposes no direct backend, provider routing URL, or separate Sub2 account creation', () => {
    const wrapper = render()
    expect(wrapper.get('[data-testid="cpa-only-notice"]').text()).toContain('CPA')
    expect(wrapper.find('[data-testid="openai-runtime-backend-direct"]').exists()).toBe(false)
    expect(wrapper.find('[name="base_url"]').exists()).toBe(false)
    expect(wrapper.text()).not.toContain('Sub2 直连')
  })
  it('imports JSON only through CPA and clears credentials after success', async () => {
    const wrapper = render()
    await wrapper.get('[data-testid="cpa-json"]').setValue('{"access_token":"synthetic"}')
    await wrapper.get('[data-testid="cpa-import-submit"]').trigger('click'); await flushPromises()
    expect(mocks.files).toHaveBeenCalledWith(['{"access_token":"synthetic"}'], expect.objectContaining({priority: 0,weight: 1,request_retry: 0,proxy_id:null}))
    expect(mocks.create).not.toHaveBeenCalled()
    expect(wrapper.emitted('created')).toHaveLength(1)
    expect((wrapper.get('[data-testid="cpa-json"]').element as HTMLTextAreaElement).value).toBe('')
  })
  it('shows partial import errors without falling back to Sub2', async () => {
    mocks.files.mockResolvedValue({ created: 1, updated: 0, failed: 1, errors: [{ index: 2, message: 'expired' }] })
    const wrapper = render()
    await wrapper.get('[data-testid="cpa-json"]').setValue('[{},{}]')
    await wrapper.get('[data-testid="cpa-import-submit"]').trigger('click'); await flushPromises()
    expect(wrapper.get('[role="alert"]').text()).toContain('#2: expired')
    expect(mocks.create).not.toHaveBeenCalled()
  })
  it.each(['file', 'json'])('imports %s without a business bridge and shows a routing warning', async (mode) => {
    mocks.files.mockResolvedValue({ created: 1, updated: 0, failed: 0, errors: [], items: [{ index: 1, action: 'imported_cpa' }] })
    const wrapper = render()
    const synthetic = '{"tokens":{"access_token":"synthetic"}}'
    if (mode === 'file') {
      const input = wrapper.get('[data-testid="cpa-files"]')
      Object.defineProperty(input.element, 'files', { value: [{ size: synthetic.length, text: () => Promise.resolve(synthetic) }] })
      await input.trigger('change'); await flushPromises()
    } else {
      await wrapper.get('[data-testid="cpa-json"]').setValue(synthetic)
    }
    await wrapper.get('[data-testid="cpa-import-submit"]').trigger('click'); await flushPromises()
    expect(mocks.files).toHaveBeenCalledWith([synthetic], expect.any(Object))
    expect(wrapper.get('[data-testid="cpa-routing-warning"]').text()).toContain('尚未配置业务桥接')
    expect(wrapper.get('[role="status"]').text()).toContain('1')
    expect(mocks.create).not.toHaveBeenCalled()
  })
  it('does not show a green success message when all imports failed', async () => {
    mocks.files.mockResolvedValue({ created: 0, updated: 0, failed: 1, errors: [{ index: 1, message: '授权未通过验证' }] })
    const wrapper = render()
    await wrapper.get('[data-testid="cpa-json"]').setValue('{}')
    await wrapper.get('[data-testid="cpa-import-submit"]').trigger('click'); await flushPromises()
    expect(wrapper.find('[role="status"]').exists()).toBe(false)
    expect(wrapper.get('[role="alert"]').text()).toContain('授权未通过验证')
  })
  it('preserves an unrotated refresh token while importing into CPA', async () => {
    mocks.refresh.mockResolvedValue({ access_token: 'fresh', id_token: 'id' })
    const wrapper = render()
    await wrapper.get('[data-testid="cpa-tab-refresh"]').trigger('click')
    await wrapper.get('[data-testid="cpa-refresh-tokens"]').setValue('original-refresh')
    await wrapper.get('[data-testid="cpa-import-submit"]').trigger('click'); await flushPromises()
    expect(mocks.oauth).toHaveBeenCalledWith(expect.objectContaining({ refresh_token: 'original-refresh', access_token: 'fresh' }), expect.objectContaining({disabled:false,weight:1}))
    expect(mocks.create).not.toHaveBeenCalled()
  })
  it('rejects a mismatched OAuth callback before exchanging credentials', async () => {
    const wrapper = render()
    await wrapper.get('[data-testid="cpa-tab-oauth"]').trigger('click')
    await wrapper.get('[data-testid="cpa-callback"]').setValue('http://localhost/callback?code=test&state=wrong')
    await wrapper.get('[data-testid="cpa-import-submit"]').trigger('click'); await flushPromises()
    expect(mocks.exchange).not.toHaveBeenCalled()
    expect(wrapper.get('[role="alert"]').text()).toContain('不匹配')
  })
  it('keeps credentials visible for correction on an import failure and never falls back', async () => {
    mocks.files.mockRejectedValue(new Error('CPA unavailable'))
    const wrapper = render()
    await wrapper.get('[data-testid="cpa-json"]').setValue('{}')
    await wrapper.get('[data-testid="cpa-import-submit"]').trigger('click'); await flushPromises()
    expect(wrapper.emitted('created')).toBeUndefined()
    expect(mocks.create).not.toHaveBeenCalled()
    expect(wrapper.get('[role="alert"]').text()).toContain('CPA unavailable')
  })
})
