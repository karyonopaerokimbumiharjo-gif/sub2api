import { defineComponent, ref } from 'vue'
import { mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import NativeRiskChecklist from '../components/NativeRiskChecklist.vue'
import type { NativeRiskCategory, PromptAuditDraft } from '../types'
vi.mock('vue-i18n', () => ({ useI18n: () => ({ locale: ref('zh-CN') }) }))
const originalIDs = ['harassment', 'harassment/threatening', 'hate', 'hate/threatening', 'illicit', 'illicit/violent', 'self-harm', 'self-harm/intent', 'self-harm/instructions', 'sexual', 'sexual/minors', 'violence', 'violence/graphic']
const extras = ['biological_risk', 'pii', 'unethical_acts', 'politically_sensitive_topics', 'copyright_violation', 'jailbreak']
const catalog: NativeRiskCategory[] = [...originalIDs.map(id => ({ id, kind: 'content' as const })), ...extras.map(id => ({ id, kind: 'intent' as const })), ...['operator_ctf', 'operator_repository'].map(id => ({ id, kind: 'operator' as const }))].map(c => ({ ...c, label: c.id, label_en: c.id, description: c.id }))
const Host = defineComponent({ components: { NativeRiskChecklist }, setup() { return { draft: ref({ native_risk_catalog: catalog, native_risk_categories: ['pii'], operator_policy_enabled: false } as PromptAuditDraft) } }, template: '<NativeRiskChecklist v-model:draft="draft" />' })
describe('native audit origin checklist', () => {
  it('switches to the original profile without deleting enhanced selections', async () => {
    const wrapper = mount(Host)
    await wrapper.get('[data-test="native-profile-upstream"]').trigger('click')
    expect(wrapper.vm.draft.native_audit_profile).toBe('upstream')
    expect(wrapper.findAll('input:checked')).toHaveLength(13)
    expect(wrapper.findAll('input:enabled')).toHaveLength(3)
    expect(wrapper.get('[data-test="native-category-custom"]').text()).toContain('可选扩展（3 项，非原版）')
    expect(wrapper.find('[data-test="native-select-all"]').exists()).toBe(true)
    expect(wrapper.vm.draft.native_risk_categories).toEqual(['pii'])
    await wrapper.get('[data-test="native-select-all"]').trigger('click')
    expect(wrapper.findAll('input:checked')).toHaveLength(16)
    expect(wrapper.vm.draft.native_upstream_extensions).toEqual(['biological_risk', 'operator_ctf', 'operator_repository'])
    await wrapper.get('[data-test="native-category-operator_ctf"]').setValue(false)
    expect(wrapper.vm.draft.native_upstream_extensions).toEqual(['biological_risk', 'operator_repository'])
    expect(wrapper.vm.draft.native_risk_categories).toEqual(['pii'])
    await wrapper.get('[data-test="native-profile-enhanced"]').trigger('click')
    expect(wrapper.vm.draft.native_audit_profile).toBe('enhanced')
    expect(wrapper.findAll('input:checked')).toHaveLength(1)
    expect(wrapper.get<HTMLInputElement>('[data-test="native-category-pii"]').element.checked).toBe(true)
    await wrapper.get('[data-test="native-profile-upstream"]').trigger('click')
    expect(wrapper.findAll('input:checked')).toHaveLength(15)
    expect(wrapper.get<HTMLInputElement>('[data-test="native-category-operator_repository"]').element.checked).toBe(true)
    wrapper.unmount()
  })
  it('groups 13 original and 8 custom choices, and persists select-all without hidden duplicates', async () => {
    const wrapper = mount(Host)
    expect(wrapper.get('[data-test="native-category-original"]').text()).toContain('Sub2API 0.2.8 原版（13 类）')
    expect(wrapper.get('[data-test="native-category-custom"]').text()).toContain('我们新增（8 项，非原版）')
    expect(wrapper.get('[data-test="native-category-original"]').findAll('input')).toHaveLength(13)
    expect(wrapper.get('[data-test="native-category-custom"]').findAll('input')).toHaveLength(8)
    await wrapper.get('[data-test="native-select-all"]').trigger('click')
    expect(wrapper.findAll('input:checked')).toHaveLength(21)
    expect(wrapper.get('[data-test="native-category-count"]').text()).toContain('已勾选 21 项')
    await wrapper.get('[data-test="native-category-operator_ctf"]').setValue(false)
    expect(wrapper.findAll('input:checked')).toHaveLength(20)
    expect(wrapper.get<HTMLInputElement>('[data-test="native-category-operator_repository"]').element.checked).toBe(true)
    await wrapper.get('[data-test="native-category-sexual"]').setValue(false)
    expect(wrapper.findAll('input:checked')).toHaveLength(19)
    expect(wrapper.vm.draft.native_risk_categories).not.toContain('sexual')
    expect(wrapper.vm.draft.operator_policy_enabled).toBe(true)
    wrapper.unmount()
  })
})
