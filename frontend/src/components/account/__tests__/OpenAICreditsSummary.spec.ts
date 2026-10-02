import { mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import OpenAICreditsSummary from '../OpenAICreditsSummary.vue'
import type { OpenAICreditsSnapshot } from '@/types/openaiCredits'

vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string, params?: Record<string, unknown>) => params?.percent !== undefined ? `${key}:${params.percent}` : key }) }))
const render = (snapshot: OpenAICreditsSnapshot | null) => mount(OpenAICreditsSummary, { props: { snapshot, loading: false } })

describe('OpenAICreditsSummary', () => {
  it.each([
    { remaining: '0', expected: '0' },
    { remaining: '0', unlimited: true, expected: 'admin.accounts.openaiCredits.unlimited' },
    { remaining: '8.5', expected: '8.5' },
    { remaining: '9007199254740993.01', expected: '9007199254740993.01' },
    { remaining: null, expected: '25' },
    { remaining: undefined, expected: '25' },
  ])('honors remaining $remaining, unlimited authorization, and decimal precision', ({ remaining, unlimited = false, expected }) => {
    const wrapper = render({
      credits: { has_credits: true, unlimited, balance: '25', remaining },
      fetched_at: 1700000000,
    })
    expect(wrapper.get('[data-testid="openai-credits-balance"]').text()).toBe(expected)
  })

  it('shows unknown values before a query and emits a refresh without spending reset credits', async () => {
    const wrapper = render(null)
    for (const field of ['limit', 'used', 'remaining']) {
      expect(wrapper.get(`[data-testid="openai-spend-${field}"]`).text()).toBe('admin.accounts.openaiCredits.unknown')
    }
    expect(wrapper.get('[data-testid="openai-credits-balance"]').text()).toContain('unknown')
    await wrapper.get('[data-testid="openai-credits-refresh"]').trigger('click')
    expect(wrapper.emitted('refresh')).toHaveLength(1)
    await wrapper.setProps({ loading: true })
    expect(wrapper.get('[data-testid="openai-credits-refresh"]').attributes('disabled')).toBeDefined()
  })

  it('keeps credit balance separate from upstream allowance and preserves decimal precision', () => {
    const wrapper = render({
      credits: { has_credits: true, unlimited: false, balance: '25.0000000000000001' },
      spend_control: { reached: false, individual_limit: { limit: '100', used: '40', remaining: '60', remaining_percent: 60, reset_after_seconds: 3600 } },
      fetched_at: 1700000000
    })
    expect(wrapper.get('[data-testid="openai-credits-balance"]').text()).toBe('25.0000000000000001')
    expect(wrapper.get('[data-testid="openai-spend-limit"]').text()).toBe('100')
    expect(wrapper.get('[data-testid="openai-spend-used"]').text()).toBe('40')
    expect(wrapper.get('[data-testid="openai-spend-remaining"]').text()).toBe('60')
    expect(wrapper.get('[data-testid="openai-spend-percent"]').text()).toContain(':60')
    expect(wrapper.get('[data-testid="openai-spend-reset"] time').attributes('datetime')).toBe(new Date(1700003600000).toISOString())
    expect(wrapper.get('[data-testid="openai-credits-fetched"] time').attributes('datetime')).toBe(new Date(1700000000000).toISOString())
    expect(wrapper.text()).not.toContain('$')
    expect(wrapper.text()).not.toContain('USD')
  })

  it('distinguishes an explicit zero from an absent value and supports unlimited credits', () => {
    const wrapper = render({
      credits: { has_credits: true, unlimited: true, balance: null },
      spend_control: { reached: true, individual_limit: { used: '0', remaining: null, remaining_percent: null, reset_at: 1700001000, reset_after_seconds: 99999 } },
      fetched_at: 1700000000
    })
    expect(wrapper.get('[data-testid="openai-credits-balance"]').text()).toContain('unlimited')
    expect(wrapper.get('[data-testid="openai-spend-used"]').text()).toBe('0')
    expect(wrapper.get('[data-testid="openai-spend-limit"]').text()).toContain('unknown')
    expect(wrapper.get('[data-testid="openai-spend-remaining"]').text()).toContain('unknown')
    expect(wrapper.get('[data-testid="openai-spend-reached"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="openai-spend-percent"]').exists()).toBe(false)
    expect(wrapper.get('[data-testid="openai-spend-reset"] time').attributes('datetime')).toBe(new Date(1700001000000).toISOString())
  })
})
