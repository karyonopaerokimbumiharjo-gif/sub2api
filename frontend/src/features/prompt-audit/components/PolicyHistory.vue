<template>
  <section class="mt-6 rounded-xl border border-gray-200 p-4 dark:border-dark-700/60 dark:bg-dark-900/20 sm:p-5" data-test="policy-history">
    <div class="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h3 class="text-sm font-semibold text-gray-900 dark:text-white">{{ t('admin.promptAudit.history.title') }}</h3>
        <p class="mt-1 text-xs text-gray-500 dark:text-dark-400">{{ t('admin.promptAudit.history.description') }}</p>
      </div>
      <button type="button" class="btn btn-secondary btn-sm" :disabled="loading" @click="$emit('refresh')">
        {{ t('admin.promptAudit.actions.refresh') }}
      </button>
    </div>

    <p v-if="disabled" class="mt-3 rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-800 dark:bg-amber-950/30 dark:text-amber-200">
      {{ t('admin.promptAudit.history.unsavedHint') }}
    </p>
    <p v-if="error" role="alert" class="mt-3 text-sm text-red-600 dark:text-red-300">{{ error }}</p>
    <div v-else-if="loading" class="mt-4 text-sm text-gray-500">{{ t('common.loading') }}</div>
    <div v-else-if="versions.length === 0" class="mt-4 text-sm text-gray-500">{{ t('admin.promptAudit.history.empty') }}</div>

    <div v-else class="mt-4 overflow-x-auto">
      <table class="min-w-full divide-y divide-gray-200 text-left text-sm dark:divide-dark-700">
        <thead class="text-xs text-gray-500 dark:text-dark-400">
          <tr>
            <th class="pb-2 pr-4 font-medium">{{ t('admin.promptAudit.history.version') }}</th>
            <th class="pb-2 pr-4 font-medium">{{ t('admin.promptAudit.history.order') }}</th>
            <th class="pb-2 pr-4 font-medium">{{ t('admin.promptAudit.history.savedAt') }}</th>
            <th class="pb-2 text-right font-medium">{{ t('admin.promptAudit.common.actions') }}</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-100 dark:divide-dark-800">
          <tr v-for="version in versions" :key="version.id" :data-test="`policy-version-${version.config_version}`">
            <td class="py-3 pr-4 font-medium text-gray-900 dark:text-white">
              v{{ version.config_version }}
              <span v-if="version.config_version === currentVersion" class="ml-1 rounded bg-primary-50 px-1.5 py-0.5 text-[11px] text-primary-700 dark:bg-primary-950/40 dark:text-primary-300">
                {{ t('admin.promptAudit.history.current') }}
              </span>
            </td>
            <td class="max-w-xl py-3 pr-4 text-xs text-gray-600 dark:text-dark-300">
              {{ version.endpoint_order.length ? version.endpoint_order.join(' → ') : t('admin.promptAudit.history.noEndpoints') }}
            </td>
            <td class="whitespace-nowrap py-3 pr-4 text-xs text-gray-500 dark:text-dark-400">{{ formatDate(version.created_at) }}</td>
            <td class="py-3 text-right">
              <button
                type="button"
                class="btn btn-secondary btn-sm"
                :disabled="disabled || rollingBack > 0 || version.config_version >= currentVersion"
                :data-test="`rollback-policy-${version.config_version}`"
                @click="$emit('rollback', version.config_version)"
              >
                {{ rollingBack === version.config_version ? t('admin.promptAudit.history.rollingBack') : t('admin.promptAudit.history.rollback') }}
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>

<script setup lang="ts">
import { useI18n } from 'vue-i18n'
import type { PromptPolicyVersion } from '../types'

defineProps<{
  versions: PromptPolicyVersion[]
  currentVersion: number
  loading: boolean
  error: string
  disabled: boolean
  rollingBack: number
}>()

defineEmits<{
  refresh: []
  rollback: [configVersion: number]
}>()

const { t, locale } = useI18n()

function formatDate(value: string): string {
  if (!value) return '—'
  return new Intl.DateTimeFormat(locale.value, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
}
</script>
