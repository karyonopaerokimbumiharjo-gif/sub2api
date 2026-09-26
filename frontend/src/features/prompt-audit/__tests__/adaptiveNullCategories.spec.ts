import { describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import AdaptiveWorkspace from '../components/AdaptiveWorkspace.vue'
import type { PromptAdaptiveSample } from '../types'

vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key }) }))

describe('historical adaptive sample rendering', () => {
  it('renders null and missing categories and continues updating after the API data changes', async () => {
    const sample = {
      id: 7, status: 'shadow_failed', review_status: 'pending', occurrence_count: 1,
      primary_intent_categories: null, primary_content_categories: null,
      shadow_intent_categories: undefined, shadow_content_categories: [],
    } as unknown as PromptAdaptiveSample
    const wrapper = mount(AdaptiveWorkspace, {
      props: { samples: [sample], total: 1, page: 1, pageSize: 20, status: 'all', loading: false, error: '', reviewingId: 0 },
      global: { stubs: { Pagination: true } },
    })
    expect(wrapper.get('[data-test="adaptive-sample-7"]').text()).toContain('None')
    await wrapper.setProps({ samples: [{ ...sample, primary_intent_categories: ['violent'] }] })
    expect(wrapper.text()).toContain('violent')
    const refresh = wrapper.findAll('button').find(button => button.text() === 'common.refresh')!
    await refresh.trigger('click')
    expect(wrapper.emitted('refresh')).toHaveLength(1)
  })
})
