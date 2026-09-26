import { mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import CPARuntimeFields from '../CPARuntimeFields.vue'
import type { Proxy } from '@/types'

vi.mock('vue-i18n', () => ({ useI18n: () => ({ locale: { value: 'zh' } }) }))

describe('CPA credential settings', () => {
  it('keeps a missing saved proxy visible without silently selecting another one', () => {
    const modelValue = {name:'test.json', disabled:false, proxy_id:9, priority:0, weight:1, request_retry:0}
    const wrapper = mount(CPARuntimeFields, {props:{modelValue, proxies:[]}})
    expect(wrapper.get('option[value="9"]').attributes('disabled')).toBeDefined()
    expect(wrapper.get('option[value="9"]').text()).toContain('不可用或未加载')
    expect((wrapper.get('select').element as HTMLSelectElement).value).toBe('9')
    expect(wrapper.emitted('update:modelValue')).toBeUndefined()
    expect(wrapper.get('option[value="0"]').text()).toContain('使用 CPA 默认出口')
  })

  it('only offers supported proxies and emits a full runtime update', async () => {
    const modelValue = { name: 'test.json', disabled: false, proxy_id: null, priority: 2, weight: 1, request_retry: 0 }
    const proxies = [
      { id: 1, name: 'supported', status: 'active', fallback_mode: 'none' },
      { id: 2, name: 'expired', status: 'active', expires_at: 1 },
      { id: 3, name: 'fallback', status: 'active', fallback_mode: 'direct' },
      { id: 4, name: 'disabled', status: 'inactive' }
    ] as Proxy[]
    const wrapper = mount(CPARuntimeFields, { props: { modelValue, proxies } })
    expect(wrapper.findAll('option').map(o => o.attributes('value'))).toEqual(['', '0', '1'])
    await wrapper.get('select').setValue('1')
    expect(wrapper.emitted('update:modelValue')?.[0]).toEqual([{ ...modelValue, proxy_id: 1 }])
    await wrapper.get('input[type="checkbox"]').setValue(false)
    expect(wrapper.emitted('update:modelValue')?.[1]).toEqual([{ ...modelValue, disabled: true }])
    await wrapper.findAll('input[type="number"]')[2].setValue('3')
    expect(wrapper.emitted('update:modelValue')?.[2]).toEqual([{ ...modelValue, request_retry: 3 }])
    await wrapper.get('select').setValue('0')
    expect(wrapper.emitted('update:modelValue')?.[3]).toEqual([{ ...modelValue, proxy_id: 0 }])
  })
})
