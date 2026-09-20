<template>
  <section aria-labelledby="adaptive-samples-title" class="py-6">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 id="adaptive-samples-title" class="text-base font-semibold text-gray-950 dark:text-white">{{ t('admin.promptAudit.samples.title') }}</h2>
        <p class="mt-1 max-w-3xl text-sm text-gray-500 dark:text-dark-300">{{ t('admin.promptAudit.samples.description') }}</p>
      </div>
      <button type="button" class="btn btn-secondary btn-sm" @click="$emit('refresh')">{{ t('common.refresh') }}</button>
    </div>

    <div class="mt-5 flex flex-wrap items-end gap-3">
      <label class="text-xs text-gray-600 dark:text-dark-200">
        <span>{{ t('admin.promptAudit.samples.filter') }}</span>
        <select :value="status" class="input mt-1 min-w-48" :aria-label="t('admin.promptAudit.samples.filter')" @change="$emit('status', ($event.target as HTMLSelectElement).value)">
          <option value="review_pending">{{ t('admin.promptAudit.samples.filters.reviewPending') }}</option>
          <option value="disagreement">{{ t('admin.promptAudit.samples.filters.disagreement') }}</option>
          <option value="shadow_failed">{{ t('admin.promptAudit.samples.filters.shadowFailed') }}</option>
          <option value="shadow_match">{{ t('admin.promptAudit.samples.filters.shadowMatch') }}</option>
          <option value="allow">{{ t('admin.promptAudit.samples.filters.reviewedAllow') }}</option>
          <option value="block">{{ t('admin.promptAudit.samples.filters.reviewedBlock') }}</option>
          <option value="all">{{ t('common.all') }}</option>
        </select>
      </label>
      <span class="text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.samples.total', { count: total }) }}</span>
    </div>

    <div v-if="error" role="alert" class="mt-4 rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700 dark:bg-red-950/30 dark:text-red-300">{{ error }}</div>
    <div class="mt-5 space-y-3">
      <div v-if="loading" class="rounded-xl border border-gray-200 px-4 py-12 text-center text-sm text-gray-500 dark:border-dark-700" aria-busy="true">{{ t('common.loading') }}</div>
      <div v-else-if="samples.length === 0" class="rounded-xl border border-gray-200 px-4 py-12 text-center text-sm text-gray-500 dark:border-dark-700">{{ t('admin.promptAudit.samples.empty') }}</div>
      <article v-for="sample in samples" v-else :key="sample.id" class="rounded-xl border border-gray-200 bg-white p-4 dark:border-dark-700/60 dark:bg-dark-900/20" :data-test="`adaptive-sample-${sample.id}`">
        <div class="flex flex-wrap items-start justify-between gap-3">
          <div class="min-w-0">
            <div class="flex flex-wrap items-center gap-2 text-xs">
              <span class="rounded-full bg-gray-100 px-2 py-1 font-medium text-gray-700 dark:bg-dark-700 dark:text-dark-200">{{ sample.status }}</span>
              <span class="rounded-full px-2 py-1 font-medium" :class="reviewClass(sample.review_status)">{{ reviewLabel(sample.review_status) }}</span>
              <span class="text-gray-500 dark:text-dark-400">#{{ sample.id }} · {{ formatDate(sample.updated_at) }} · ×{{ sample.occurrence_count }}</span>
            </div>
            <p class="mt-2 text-xs text-gray-500 dark:text-dark-400">{{ sample.stage }} / {{ sample.audit_subject }} · policy {{ sample.policy_version }} · config {{ sample.config_version }}</p>
          </div>
          <div class="flex gap-2">
            <button type="button" class="btn btn-secondary btn-sm" :disabled="reviewingId === sample.id" @click="$emit('review', sample.id, 'allow')">{{ t('admin.promptAudit.samples.markAllow') }}</button>
            <button type="button" class="btn btn-danger btn-sm" :disabled="reviewingId === sample.id" @click="$emit('review', sample.id, 'block')">{{ t('admin.promptAudit.samples.markBlock') }}</button>
          </div>
        </div>

        <div class="mt-4 grid gap-3 lg:grid-cols-2">
          <div class="rounded-lg bg-gray-50 p-3 dark:bg-dark-800/70">
            <p class="text-xs font-semibold text-gray-800 dark:text-dark-100">{{ t('admin.promptAudit.samples.primary') }} · {{ sample.primary_endpoint_id || '—' }} · {{ sample.primary_decision || '—' }}</p>
            <CategoryLines :intent="sample.primary_intent_categories" :content="sample.primary_content_categories" />
          </div>
          <div class="rounded-lg bg-gray-50 p-3 dark:bg-dark-800/70">
            <p class="text-xs font-semibold text-gray-800 dark:text-dark-100">{{ t('admin.promptAudit.samples.shadow') }} · {{ sample.shadow_endpoint_id || '—' }} · {{ sample.shadow_decision || '—' }}</p>
            <CategoryLines :intent="sample.shadow_intent_categories" :content="sample.shadow_content_categories" />
          </div>
        </div>

        <details class="mt-3 rounded-lg border border-gray-100 px-3 py-2 dark:border-dark-700">
          <summary class="cursor-pointer text-xs font-medium text-gray-700 dark:text-dark-200">{{ t('admin.promptAudit.samples.prompt') }}</summary>
          <pre class="mt-3 max-h-80 overflow-auto whitespace-pre-wrap break-words text-xs text-gray-700 dark:text-dark-200">{{ sample.full_prompt || sample.redacted_preview }}</pre>
        </details>
      </article>
    </div>

    <Pagination :total="total" :page="page" :page-size="pageSize" @update:page="$emit('page', $event)" @update:page-size="$emit('page-size', $event)" />
  </section>
</template>

<script setup lang="ts">
import { defineComponent, h, type PropType } from 'vue'
import { useI18n } from 'vue-i18n'
import Pagination from '@/components/common/Pagination.vue'
import type { PromptAdaptiveSample } from '../types'

defineProps<{
  samples: PromptAdaptiveSample[]
  total: number
  page: number
  pageSize: number
  status: string
  loading: boolean
  error: string
  reviewingId: number
}>()
defineEmits<{
  (event: 'status', value: string): void
  (event: 'page', value: number): void
  (event: 'page-size', value: number): void
  (event: 'refresh'): void
  (event: 'review', id: number, decision: 'allow' | 'block'): void
}>()
const { t } = useI18n()

const CategoryLines = defineComponent({
  props: {
    intent: { type: Array as PropType<string[]>, required: true },
    content: { type: Array as PropType<string[]>, required: true },
  },
  setup(props) {
    const labels = (values: string[]) => values.length > 0 ? values.join(', ') : 'None'
    return () => h('div', { class: 'mt-2 space-y-1 text-xs text-gray-600 dark:text-dark-300' }, [
      h('p', `${t('admin.promptAudit.samples.intent')}: ${labels(props.intent)}`),
      h('p', `${t('admin.promptAudit.samples.content')}: ${labels(props.content)}`),
    ])
  },
})

function formatDate(value: string): string {
  return value ? new Date(value).toLocaleString() : '—'
}

function reviewLabel(value: string): string {
  if (value === 'allow') return t('admin.promptAudit.samples.filters.reviewedAllow')
  if (value === 'block') return t('admin.promptAudit.samples.filters.reviewedBlock')
  return t('admin.promptAudit.samples.filters.reviewPending')
}

function reviewClass(value: string): string {
  if (value === 'allow') return 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-200'
  if (value === 'block') return 'bg-red-100 text-red-800 dark:bg-red-950/50 dark:text-red-200'
  return 'bg-amber-100 text-amber-800 dark:bg-amber-950/50 dark:text-amber-200'
}
</script>
