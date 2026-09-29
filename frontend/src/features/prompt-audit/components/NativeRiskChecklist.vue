<template>
  <section class="mt-5 space-y-5" aria-labelledby="native-risk-checklist-title">
    <div class="space-y-3">
      <h3 class="font-semibold">{{ zh ? '原生审核版本' : 'Native audit version' }}</h3>
      <div class="flex flex-wrap gap-2" role="group" :aria-label="zh ? '原生审核版本' : 'Native audit version'">
        <button type="button" class="btn" :class="!upstream ? 'btn-primary' : 'btn-secondary'" :aria-pressed="!upstream" data-test="native-profile-enhanced" @click="setProfile('enhanced')">{{ zh ? '增强版（当前定制版本）' : 'Enhanced (site customizations)' }}</button>
        <button type="button" class="btn" :class="upstream ? 'btn-primary' : 'btn-secondary'" :aria-pressed="upstream" data-test="native-profile-upstream" @click="setProfile('upstream')">{{ zh ? 'Sub2API 0.2.8 原版' : 'Original Sub2API 0.2.8' }}</button>
      </div>
      <p class="text-sm leading-6 text-gray-600 dark:text-dark-200" data-test="native-profile-description">{{ upstream ? (zh ? '保留 Sub2API 0.2.8 原有的 13 类审核判断，可在下方单独勾选生物与化学风险、CTF、破甲库扩展。不勾选扩展时执行原版审核。原生关键字设置继续生效；增强版选择独立保留。保存后生效。' : 'Keep the original 13 judgments, with optional biological/chemical, CTF and repository policies below. No extensions selected means original auditing. Native keyword settings still apply. Enhanced selections remain separate. Save to apply.') : (zh ? '使用当前增强版，可选择原版 13 类和本站新增 8 项规则。保存后生效。' : 'Use the current enhanced version with 13 original categories and 8 site additions. Save to apply.') }}</p>
    </div>
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div>
        <h3 id="native-risk-checklist-title" class="font-semibold">{{ zh ? 'Jev 审核分类' : 'Jev audit categories' }}</h3>
        <p class="mt-1 text-sm text-gray-600 dark:text-dark-200" data-test="native-category-count">{{ zh ? `共 ${catalog.length} 项，已勾选 ${selected.length} 项` : `${selected.length} of ${catalog.length} selected` }}</p>
      </div>
      <button type="button" class="btn btn-secondary" data-test="native-select-all" :disabled="!catalog.length" @click="select(catalog.map(item => item.id))">{{ zh ? `全部勾选（${catalog.length}项）` : `Select all (${catalog.length})` }}</button>
    </div>
    <fieldset v-for="group in groups" :key="group.id" class="rounded-xl border border-gray-200 bg-white p-4 dark:border-dark-600 dark:bg-dark-900" :data-test="`native-category-${group.id}`">
      <legend class="px-2 font-semibold">{{ group.title }}</legend>
      <p class="mb-3 text-sm text-gray-500 dark:text-dark-300">{{ group.description }}</p>
      <div class="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        <label v-for="item in group.items" :key="item.id" class="flex cursor-pointer items-start gap-2 rounded-lg p-2 hover:bg-gray-50 dark:hover:bg-dark-800" :title="item.description">
          <input type="checkbox" class="mt-1 h-4 w-4 shrink-0 rounded" :disabled="upstream && item.kind === 'content'" :checked="selected.includes(item.id)" :data-test="`native-category-${item.id}`" @change="toggle(item.id, ($event.target as HTMLInputElement).checked)" />
          <span><span class="text-sm font-medium">{{ zh ? item.label : item.label_en }}</span><span v-if="item.kind === 'operator'" class="ml-2 rounded bg-amber-100 px-1.5 py-0.5 text-xs text-amber-800">{{ zh ? '全局规则' : 'Global rule' }}</span><span v-if="zh" class="mt-1 block text-xs leading-5 text-gray-500 dark:text-dark-300">{{ item.description }}</span></span>
        </label>
      </div>
    </fieldset>
    <p v-if="upstream" class="text-xs leading-5 text-gray-500 dark:text-dark-300">{{ zh ? '扩展规则属于本站定制，并非 Sub2API 0.2.8 原版自带。生物分级需要 TypeSafe／Jev；CTF、破甲库勾选后仍按全局规则拦截。全部勾选时共 16 项，审核事件会记录已启用的扩展。' : 'Extensions are site additions. Biological tiers require TypeSafe/Jev. Selected CTF/repository policies apply globally. Selecting all enables 16 categories; audit events identify the extensions.' }}</p>
    <p v-if="!upstream" class="text-xs leading-5 text-gray-500 dark:text-dark-300">{{ zh ? '暴力、违法、性内容、自伤的重复意图判断已合并到原版细分类。新增项属于本站定制；CTF 和破甲库规则适用于全部分组，本地与原生审核共用。新增的模型风险分类需使用 TypeSafe／Jev；OpenAI 审核接口不支持这些扩展分类。手动设置的关键字拦截独立生效。全部勾选后，在同一次 Jev 输入审核中最多提交 21 个分类判断。' : 'Duplicate broad intent checks are merged into the original detailed categories. Added policies are site customizations. The two global rules apply across groups and both audit modes. All selections use at most 21 judgments in one Jev input evaluation.' }}</p>
  </section>
</template>
<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { PromptAuditDraft } from '../types'
import { cloneData } from '../viewModel'
const props = defineProps<{ draft: PromptAuditDraft }>()
const emit = defineEmits<{ (event: 'update:draft', value: PromptAuditDraft): void }>()
const { locale } = useI18n()
const zh = computed(() => locale.value.startsWith('zh'))
const upstream = computed(() => props.draft.native_audit_profile === 'upstream')
const extensionIDs = ['biological_risk', 'operator_ctf', 'operator_repository']
const catalog = computed(() => (props.draft.native_risk_catalog ?? []).filter(item => !upstream.value || item.kind === 'content' || extensionIDs.includes(item.id)))
const selected = computed(() => catalog.value.filter(item => upstream.value ? item.kind === 'content' || props.draft.native_upstream_extensions?.includes(item.id) : props.draft.native_risk_categories?.includes(item.id) && (item.kind !== 'operator' || props.draft.operator_policy_enabled)).map(item => item.id))
const groups = computed(() => [
  { id: 'original', title: zh.value ? 'Sub2API 0.2.8 原版（13 类）' : 'Original Sub2API 0.2.8 (13)', description: zh.value ? '以下 13 类来自原版内容审计。' : 'These 13 content categories ship with the original release.', items: catalog.value.filter(item => item.kind === 'content') },
  { id: 'custom', title: upstream.value ? (zh.value ? '可选扩展（3 项，非原版）' : 'Optional extensions (3, custom)') : (zh.value ? '我们新增（8 项，非原版）' : 'Our additions (8, custom)'), description: upstream.value ? (zh.value ? '独立勾选，保存后与原版 13 类共同执行；不会启用增强版的其他分类。' : 'Enable independently alongside the original 13; other enhanced categories remain inactive.') : (zh.value ? '6 类补充风险 + CTF、破甲库 2 项全局规则。' : 'Six complementary risks and two global operator rules.'), items: catalog.value.filter(item => item.kind !== 'content') },
].filter(group => group.items.length > 0))
function setProfile(profile: 'enhanced' | 'upstream') {
  emit('update:draft', { ...cloneData(props.draft), native_audit_profile: profile })
}
function select(ids: string[]) {
  const draft = cloneData(props.draft)
  if (upstream.value) {
    draft.native_upstream_extensions = extensionIDs.filter(id => ids.includes(id))
    emit('update:draft', draft)
    return
  }
  draft.native_risk_categories = catalog.value.filter(item => ids.includes(item.id)).map(item => item.id)
  draft.operator_policy_enabled = catalog.value.some(item => item.kind === 'operator' && ids.includes(item.id))
  emit('update:draft', draft)
}
function toggle(id: string, checked: boolean) {
  select(checked ? [...selected.value, id] : selected.value.filter(value => value !== id))
}
</script>
