import { defineComponent, ref } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({ importFiles: vi.fn(), create: vi.fn(), grokAuthorize: vi.fn() }))
vi.mock('@/api/admin', () => ({ adminAPI: { accounts: {
  importCPAAuthFiles: mocks.importFiles,
  create: mocks.create,
  grokAuthorize: mocks.grokAuthorize
} } }))
vi.mock('vue-i18n', async () => ({ ...await vi.importActual('vue-i18n'), useI18n: () => ({ locale: ref('en'), t: (key: string) => key }) }))
vi.mock('@/composables/useOpenAIOAuth', () => ({ useOpenAIOAuth: () => ({
  authUrl: ref(''), sessionId: ref('session'), oauthState: ref('state'), loading: ref(false), error: ref(''),
  generateAuthUrl: vi.fn(), resetState: vi.fn(), validateRefreshToken: vi.fn(), exchangeAuthCode: vi.fn(),
  buildCredentials: (value: Record<string, unknown>) => ({ ...value })
}) }))

import CreateAccountModal from '../CreateAccountModal.vue'

const Dialog = defineComponent({ props: ['show'], template: '<div v-if="show"><slot/><slot name="footer"/></div>' })
const render = () => mount(CreateAccountModal, { props: { show: true }, global: { stubs: { BaseDialog: Dialog, CPABridgeSetupCard: true } } })
const unsupportedAuth = JSON.stringify({ type: 'grok', api_key: 'synthetic-key', base_url: 'https://relay.example.com/v1' })

describe('CPA-only import boundary for legacy Grok setup', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mocks.importFiles.mockResolvedValue({ created: 0, updated: 0, failed: 1, errors: [{ index: 1, message: 'Unsupported provider: grok' }] })
  })

  it('does not expose direct Grok setup, custom upstream URLs, or password authorization in any import mode', async () => {
    const wrapper = render()
    for (const mode of ['json', 'oauth', 'refresh']) {
      await wrapper.get(`[data-testid="cpa-tab-${mode}"]`).trigger('click')
      expect(wrapper.get('[data-testid="cpa-only-notice"]').text()).toContain('CPA')
      expect(wrapper.find('[data-testid="grok-account-type-api-key"]').exists()).toBe(false)
      expect(wrapper.find('[data-testid="grok-custom-base-url-toggle"]').exists()).toBe(false)
      expect(wrapper.find('[data-testid="grok-custom-base-url-input"]').exists()).toBe(false)
      expect(wrapper.find('input[type="password"]').exists()).toBe(false)
      expect(wrapper.text()).not.toContain('https://api.x.ai')
    }
    wrapper.unmount()
  })

  it('sends source JSON only to CPA without copying a provider URL into runtime settings', async () => {
    const wrapper = render()
    await wrapper.get('[data-testid="cpa-json"]').setValue(unsupportedAuth)
    await wrapper.get('[data-testid="cpa-import-submit"]').trigger('click')
    await flushPromises()

    expect(mocks.importFiles).toHaveBeenCalledTimes(1)
    expect(mocks.importFiles.mock.calls[0][0]).toEqual([unsupportedAuth])
    expect(mocks.importFiles.mock.calls[0][1]).not.toHaveProperty('base_url')
    expect(mocks.importFiles.mock.calls[0][1]).not.toHaveProperty('api_key')
    expect(mocks.create).not.toHaveBeenCalled()
    expect(mocks.grokAuthorize).not.toHaveBeenCalled()
    wrapper.unmount()
  })

  it('shows an unsupported-provider result and preserves the source without creating a direct account', async () => {
    const wrapper = render()
    await wrapper.get('[data-testid="cpa-json"]').setValue(unsupportedAuth)
    await wrapper.get('[data-testid="cpa-import-submit"]').trigger('click')
    await flushPromises()

    expect(wrapper.get('[role="alert"]').text()).toContain('Unsupported provider: grok')
    expect((wrapper.get('[data-testid="cpa-json"]').element as HTMLTextAreaElement).value).toBe(unsupportedAuth)
    expect(wrapper.emitted('created')).toBeUndefined()
    expect(mocks.create).not.toHaveBeenCalled()
    expect(mocks.grokAuthorize).not.toHaveBeenCalled()
    wrapper.unmount()
  })

  it('keeps CPA transport failures visible and never retries against a direct Grok backend', async () => {
    mocks.importFiles.mockRejectedValue(new Error('CPA unavailable'))
    const wrapper = render()
    await wrapper.get('[data-testid="cpa-json"]').setValue(unsupportedAuth)
    await wrapper.get('[data-testid="cpa-import-submit"]').trigger('click')
    await flushPromises()

    expect(wrapper.get('[role="alert"]').text()).toContain('CPA unavailable')
    expect(mocks.importFiles).toHaveBeenCalledTimes(1)
    expect(wrapper.emitted('created')).toBeUndefined()
    expect(mocks.create).not.toHaveBeenCalled()
    expect(mocks.grokAuthorize).not.toHaveBeenCalled()
    wrapper.unmount()
  })
})
