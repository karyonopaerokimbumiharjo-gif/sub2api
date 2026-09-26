import { defineComponent, ref } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { AdminGroup } from '@/types'

const mocks = vi.hoisted(() => ({ files: vi.fn(), oauth: vi.fn(), refresh: vi.fn(), exchange: vi.fn(), create: vi.fn(), post: vi.fn(), sync: vi.fn(), generateAuthUrl: vi.fn(), getById: vi.fn(), update: vi.fn(), setSchedulable: vi.fn() }))
vi.mock('@/api/admin', () => ({ adminAPI: { accounts: { importCPAAuthFiles: mocks.files, importOpenAIOAuthToCPA: mocks.oauth, create: mocks.create, getById: mocks.getById, update: mocks.update, setSchedulable: mocks.setSchedulable } } }))
vi.mock('@/api/client', () => ({ apiClient: { post: mocks.post } }))
vi.mock('@/api/admin/accounts', () => ({ syncCPAAccounts: mocks.sync }))
vi.mock('vue-i18n', async () => ({ ...await vi.importActual('vue-i18n'), useI18n: () => ({ locale: ref('zh'), t: (key: string) => key }) }))
vi.mock('@/composables/useOpenAIOAuth', () => ({ useOpenAIOAuth: () => ({
  authUrl: ref(''), sessionId: ref('session'), oauthState: ref('expected-state'), loading: ref(false), error: ref(''), harnessKind: ref(''),
  generateAuthUrl: mocks.generateAuthUrl, resetState: vi.fn(), validateRefreshToken: mocks.refresh, exchangeAuthCode: mocks.exchange,
  buildCredentials: (value: Record<string, unknown>) => ({ ...value })
}) }))
vi.mock('../CPABridgeSetup.vue', () => ({ default: { template: '<div />' } }))
import CreateAccountModal from '../CreateAccountModal.vue'
const Dialog = defineComponent({ props: ['show'], template: '<div v-if="show"><slot/><slot name="footer"/></div>' })
const group = { id: 42, name: 'Clients', platform: 'openai', status: 'active' } as AdminGroup
const render = (groups: AdminGroup[] = [group]) => mount(CreateAccountModal, { props: { show: true, groups }, global: { stubs: { BaseDialog: Dialog, CPABridgeSetup: true, CPABridgeSetupCard: true } } })
type Wrapper = ReturnType<typeof render>
const submit = async (w: Wrapper) => { await w.get('[data-testid="cpa-import-submit"]').trigger('click'); await flushPromises() }
const fillJSON = async (w: Wrapper) => w.get('[data-testid="cpa-json"]').setValue('{"type":"codex"}')
const fillOAuth = async (w: Wrapper, code = 'once', state = 'expected-state') => {
  await w.get('[data-testid="cpa-tab-oauth"]').trigger('click')
  await w.get('[data-testid="cpa-callback"]').setValue(`http://localhost/callback?code=${code}&state=${state}`)
}
beforeEach(() => {
  vi.resetAllMocks()
  mocks.files.mockResolvedValue({ created: 1, updated: 0, items: [{ index: 1, action: 'imported_cpa', account_id: 101 }], errors: [] })
  mocks.oauth.mockResolvedValue({ auth_name: 'one.json', account_ids: [101] })
  mocks.exchange.mockResolvedValue({ access_token: 'synthetic' })
  mocks.refresh.mockResolvedValue({ access_token: 'synthetic' })
})

describe('one-step account import', () => {
  it('imports with the selected group in one request and displays only completed accounts', async () => {
    const w = render(); await fillJSON(w); await submit(w)
    expect(mocks.files).toHaveBeenCalledWith(expect.any(Array), expect.objectContaining({ proxy_id: 0 }), [42])
    for (const followup of [mocks.sync, mocks.getById, mocks.update, mocks.setSchedulable, mocks.create]) expect(followup).not.toHaveBeenCalled()
    expect(w.get('[role="status"]').text()).toContain('已导入 1 个账号，可以使用')
    expect(w.text()).not.toContain('业务接入')
    expect(w.find('[data-testid="cpa-routing-warning"]').exists()).toBe(false)
    expect((w.get('[data-testid="cpa-json"]').element as HTMLTextAreaElement).value).toBe('')
    expect(w.emitted('created')).toHaveLength(1)
  })
  it('defaults an unselected proxy to the configured CPA exit', async () => {
    const w = render()
    expect(w.get('[data-testid=cpa-runtime-fields] option[value="0"]').text()).toContain('使用 CPA 默认出口')
    expect(w.find('[data-testid=cpa-runtime-fields] option[value=""]').exists()).toBe(false)
  })
  it.each(['json', 'oauth', 'refresh'])('does not require a backend choice in %s mode', async mode => {
    const w = render(); await w.get(`[data-testid="cpa-tab-${mode}"]`).trigger('click')
    for (const id of ['pi-auth-backend', 'basispoints-import-enabled', 'pi-auth-owner-user-id']) expect(w.find(`[data-testid="${id}"]`).exists()).toBe(false)
  })
  it('offers only active OpenAI groups and selects the only eligible group', () => {
    const w = render([group, { ...group, id: 43, status: 'inactive' }, { ...group, id: 44, platform: 'anthropic' }])
    expect(w.findAll('[data-testid="cpa-import-group"] option').map(o => o.attributes('value'))).toEqual(['', '42'])
    expect((w.get('[data-testid="cpa-import-group"]').element as HTMLSelectElement).value).toBe('42')
  })
  it('requires a valid group before importing', async () => {
    const w = render([group, { ...group, id: 43 }]); await fillJSON(w); await submit(w)
    expect(mocks.files).not.toHaveBeenCalled()
    await w.get('[data-testid="cpa-import-group"]').setValue('43'); await submit(w)
    expect(mocks.files).toHaveBeenCalledWith(expect.any(Array), expect.anything(), [43])
  })
  it('refuses import when no active OpenAI group exists', async () => {
    const w = render([]); await fillJSON(w); await submit(w)
    expect(mocks.files).not.toHaveBeenCalled()
  })
  it('deduplicates returned account IDs instead of counting credential files', async () => {
    mocks.files.mockResolvedValue({ created: 2, items: [{ action: 'imported_cpa', account_id: 101 }, { action: 'imported_cpa', account_id: 101 }] })
    const w = render(); await fillJSON(w); await submit(w)
    expect(w.get('[role="status"]').text()).toContain('已导入 1 个账号')
  })
  it.each([undefined, [], [0], [-1], [1.5], ['101']])('does not accept an incomplete OAuth result %j', async ids => {
    mocks.oauth.mockResolvedValue({ account_ids: ids })
    const w = render(); await fillOAuth(w); await submit(w)
    expect(w.find('[role="status"]').exists()).toBe(false)
    expect(w.get('[role="alert"]').text()).toContain('未完成')
    expect(w.emitted('created')).toBeUndefined()
    expect((w.get('[data-testid="cpa-callback"]').element as HTMLInputElement).value).not.toBe('')
  })
  it('honors the disabled option in the same import request', async () => {
    const w = render(); await fillJSON(w); await w.get('[data-testid="cpa-runtime-fields"] input[type="checkbox"]').setValue(false); await submit(w)
    expect(mocks.files).toHaveBeenCalledWith(expect.any(Array), expect.objectContaining({ disabled: true }), [42])
    expect(w.get('[role="status"]').text()).toContain('保持停用')
  })
  it('retries finalization without redeeming the single-use OAuth code twice', async () => {
    mocks.oauth.mockRejectedValueOnce(new Error('account update unavailable'))
    const w = render(); await fillOAuth(w); await submit(w)
    expect(w.find('[role="status"]').exists()).toBe(false)
    expect(w.get('[role="alert"]').text()).toContain('account update unavailable')
    await submit(w)
    expect(mocks.exchange).toHaveBeenCalledTimes(1)
    expect(mocks.oauth).toHaveBeenCalledTimes(2)
    expect(mocks.oauth).toHaveBeenLastCalledWith({ access_token: 'synthetic' }, expect.anything(), [42])
    expect(w.emitted('created')).toHaveLength(1)
  })
  it('discards cached credentials when the callback changes', async () => {
    mocks.oauth.mockRejectedValueOnce(new Error('temporary failure'))
    const w = render(); await fillOAuth(w); await submit(w); await fillOAuth(w, 'new-code'); await submit(w)
    expect(mocks.exchange).toHaveBeenCalledTimes(2)
  })
  it('rejects a callback with mismatched OAuth state', async () => {
    const w = render(); await fillOAuth(w, 'once', 'wrong-state'); await submit(w)
    expect(mocks.exchange).not.toHaveBeenCalled(); expect(mocks.oauth).not.toHaveBeenCalled()
  })
  it('preserves the submitted refresh token if exchange omits its replacement', async () => {
    const w = render(); await w.get('[data-testid="cpa-tab-refresh"]').trigger('click'); await w.get('[data-testid="cpa-refresh-tokens"]').setValue('synthetic-refresh'); await submit(w)
    expect(mocks.oauth).toHaveBeenCalledWith(expect.objectContaining({ refresh_token: 'synthetic-refresh' }), expect.anything(), [42])
  })
  it('shows only completed accounts for a partial batch and retains input', async () => {
    mocks.files.mockResolvedValue({ created: 1, failed: 1, items: [{ action: 'imported_cpa', account_id: 101 }, { action: 'failed' }], errors: [{ index: 2, message: 'invalid credential' }] })
    const w = render(); await fillJSON(w); await submit(w)
    expect(w.get('[role="status"]').text()).toContain('已导入 1 个账号')
    expect(w.get('[role="alert"]').text()).toContain('invalid credential')
    expect((w.get('[data-testid="cpa-json"]').element as HTMLTextAreaElement).value).not.toBe('')
  })
  it('does not report success when every file fails', async () => {
    mocks.files.mockResolvedValue({ created: 0, failed: 1, items: [{ action: 'failed' }], errors: [{ index: 1, message: 'invalid credential' }] })
    const w = render(); await fillJSON(w); await submit(w)
    expect(w.emitted('created')).toBeUndefined(); expect(w.find('[role="status"]').exists()).toBe(false)
  })
})
