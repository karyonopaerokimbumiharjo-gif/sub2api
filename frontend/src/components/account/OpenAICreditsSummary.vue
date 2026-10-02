<template>
  <section class="mt-2 min-w-[210px] max-w-[320px] space-y-1.5 rounded-md border border-gray-200 bg-gray-50/60 p-2 text-[10px] dark:border-dark-600 dark:bg-dark-800/50" data-testid="openai-credits-summary">
    <div class="flex items-center justify-between gap-3">
      <span class="font-medium text-gray-700 dark:text-gray-200">{{ t('admin.accounts.openaiCredits.title') }}</span>
      <button type="button" :disabled="loading" class="shrink-0 text-blue-600 hover:underline disabled:cursor-wait disabled:opacity-50 dark:text-blue-400" data-testid="openai-credits-refresh" @click="emit('refresh')">
        {{ t(loading ? 'admin.accounts.openaiCredits.refreshing' : 'admin.accounts.openaiCredits.refresh') }}
      </button>
    </div>
    <div class="flex items-baseline justify-between gap-2 border-b border-gray-200 pb-1.5 dark:border-dark-600">
      <span class="text-gray-500 dark:text-gray-400">{{ t('admin.accounts.openaiCredits.balance') }}</span>
      <span class="break-all text-right font-medium tabular-nums text-gray-800 dark:text-gray-100" data-testid="openai-credits-balance">{{ balance }}</span>
    </div>
    <div class="flex flex-wrap items-center justify-between gap-1 text-gray-500 dark:text-gray-400">
      <span>{{ t('admin.accounts.openaiCredits.usageAllowance') }}</span>
      <span v-if="snapshot?.spend_control?.reached === true" class="font-medium text-amber-700 dark:text-amber-400" data-testid="openai-spend-reached">{{ t('admin.accounts.openaiCredits.reached') }}</span>
    </div>
    <dl class="grid grid-cols-3 gap-x-2 gap-y-1">
      <div v-for="field in allowanceFields" :key="field.key" class="min-w-0">
        <dt class="text-gray-500 dark:text-gray-400">{{ t(`admin.accounts.openaiCredits.${field.key}`) }}</dt>
        <dd class="break-all font-medium tabular-nums text-gray-800 dark:text-gray-100" :data-testid="`openai-spend-${field.key}`">{{ field.value }}</dd>
      </div>
    </dl>
    <p v-if="remainingPercent !== null" class="text-gray-600 dark:text-gray-300" data-testid="openai-spend-percent">{{ t('admin.accounts.openaiCredits.remainingPercent', { percent: remainingPercent }) }}</p>
    <p class="text-gray-500 dark:text-gray-400">{{ t('admin.accounts.openaiCredits.usageScope') }}</p>
    <div class="border-t border-gray-200 pt-1 text-gray-500 dark:border-dark-600 dark:text-gray-400">
      <p v-if="resetAt" data-testid="openai-spend-reset">{{ t('admin.accounts.openaiCredits.resetsAt') }} <time :datetime="resetAt.toISOString()">{{ resetAt.toLocaleString() }}</time></p>
      <p data-testid="openai-credits-fetched">{{ t('admin.accounts.openaiCredits.updatedAt') }} <time v-if="fetchedAt" :datetime="fetchedAt.toISOString()">{{ fetchedAt.toLocaleString() }}</time><span v-else>{{ t('admin.accounts.openaiCredits.unknown') }}</span></p>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { OpenAICreditsSnapshot } from '@/types/openaiCredits'

const props = defineProps<{ snapshot: OpenAICreditsSnapshot | null; loading: boolean }>()
const emit = defineEmits<{ refresh: [] }>()
const { t } = useI18n()
const unknown = () => t('admin.accounts.openaiCredits.unknown')
// Preserve decimal precision and never turn an omitted amount into zero.
const amount = (value: string | null | undefined) =>
  typeof value === 'string' && /^-?\d+(?:\.\d+)?$/.test(value.trim()) ? value.trim() : unknown()
const balance = computed(() => props.snapshot?.credits?.unlimited === true
  ? t('admin.accounts.openaiCredits.unlimited')
  : amount(props.snapshot?.credits?.remaining ?? props.snapshot?.credits?.balance))
const individualLimit = computed(() => props.snapshot?.spend_control?.individual_limit)
const allowanceFields = computed(() => [
  { key: 'limit', value: amount(individualLimit.value?.limit) },
  { key: 'used', value: amount(individualLimit.value?.used) },
  { key: 'remaining', value: amount(individualLimit.value?.remaining) }
])
const remainingPercent = computed(() => {
  const value = individualLimit.value?.remaining_percent
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 100 ? value : null
})
const timestamp = (seconds: number | null | undefined): Date | null => {
  if (typeof seconds !== 'number' || !Number.isFinite(seconds) || seconds <= 0) return null
  const date = new Date(seconds * 1000)
  return Number.isNaN(date.getTime()) ? null : date
}
const fetchedAt = computed(() => timestamp(props.snapshot?.fetched_at))
const resetAt = computed(() => {
  const absolute = timestamp(individualLimit.value?.reset_at)
  if (absolute) return absolute
  const after = individualLimit.value?.reset_after_seconds
  if (!fetchedAt.value || typeof after !== 'number' || !Number.isFinite(after) || after < 0) return null
  return timestamp(props.snapshot!.fetched_at + after)
})
</script>
