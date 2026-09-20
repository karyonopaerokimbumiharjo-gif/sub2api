<template>
  <section
    data-testid="profile-balance-grants-card"
    class="card border border-gray-100 bg-white/90 p-6 dark:border-dark-700 dark:bg-dark-900/50"
  >
    <div class="mb-5 flex items-center justify-between gap-4">
      <div class="flex items-center gap-3">
        <span class="flex h-10 w-10 items-center justify-center rounded-2xl bg-primary-50 text-primary-600 dark:bg-primary-900/30 dark:text-primary-300">
          <Icon name="calendar" size="md" />
        </span>
        <div>
          <h3 class="text-lg font-semibold text-gray-900 dark:text-white">
            {{ t('profile.balanceGrants.title') }}
          </h3>
        </div>
      </div>
      <div class="rounded-full bg-primary-50 px-3 py-1 text-sm font-semibold text-primary-700 dark:bg-primary-900/30 dark:text-primary-200">
        {{ formatCurrency(totalRemaining) }}
      </div>
    </div>

    <div
      v-if="sortedGrants.length === 0"
      class="rounded-2xl border border-dashed border-gray-200 px-4 py-6 text-center text-sm text-gray-500 dark:border-dark-700 dark:text-gray-400"
    >
      {{ t('profile.balanceGrants.empty') }}
    </div>

    <div v-else class="overflow-hidden rounded-2xl border border-gray-100 dark:border-dark-700">
      <div class="hidden grid-cols-[1.2fr_1fr_1fr_1fr] gap-4 bg-gray-50 px-4 py-3 text-xs font-semibold uppercase text-gray-500 dark:bg-dark-900/60 dark:text-gray-400 md:grid">
        <span>{{ t('profile.balanceGrants.expiresAt') }}</span>
        <span>{{ t('profile.balanceGrants.remainingAmount') }}</span>
        <span>{{ t('profile.balanceGrants.originalAmount') }}</span>
        <span>{{ t('profile.balanceGrants.redeemCode') }}</span>
      </div>

      <div class="divide-y divide-gray-100 dark:divide-dark-700">
        <div
          v-for="grant in sortedGrants"
          :key="grant.id"
          class="grid gap-3 px-4 py-4 text-sm md:grid-cols-[1.2fr_1fr_1fr_1fr] md:items-center md:gap-4"
        >
          <div>
            <p class="md:hidden text-xs font-medium text-gray-400 dark:text-gray-500">
              {{ t('profile.balanceGrants.expiresAt') }}
            </p>
            <p class="font-medium text-gray-900 dark:text-white">
              {{ formatDateTime(grant.expires_at) }}
            </p>
            <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">
              {{ t('profile.balanceGrants.grantedAt') }} {{ formatDateTime(grant.granted_at) }}
            </p>
          </div>

          <div>
            <p class="md:hidden text-xs font-medium text-gray-400 dark:text-gray-500">
              {{ t('profile.balanceGrants.remainingAmount') }}
            </p>
            <p class="font-semibold text-primary-700 dark:text-primary-200">
              {{ formatCurrency(grant.remaining_amount) }}
            </p>
          </div>

          <div>
            <p class="md:hidden text-xs font-medium text-gray-400 dark:text-gray-500">
              {{ t('profile.balanceGrants.originalAmount') }}
            </p>
            <p class="text-gray-700 dark:text-gray-200">
              {{ formatCurrency(grant.original_amount) }}
            </p>
          </div>

          <div class="min-w-0">
            <p class="md:hidden text-xs font-medium text-gray-400 dark:text-gray-500">
              {{ t('profile.balanceGrants.redeemCode') }}
            </p>
            <p class="truncate font-mono text-xs text-gray-600 dark:text-gray-300">
              {{ grant.redeem_code ? truncateCode(grant.redeem_code) : '-' }}
            </p>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import Icon from '@/components/icons/Icon.vue'
import type { UserBalanceGrant } from '@/types'

const props = defineProps<{
  grants?: UserBalanceGrant[] | null
}>()

const { t } = useI18n()

const sortedGrants = computed(() => {
  return [...(props.grants ?? [])].sort((a, b) => {
    const expiresA = new Date(a.expires_at).getTime()
    const expiresB = new Date(b.expires_at).getTime()
    if (expiresA !== expiresB) {
      return expiresA - expiresB
    }
    return a.id - b.id
  })
})

const totalRemaining = computed(() => {
  return sortedGrants.value.reduce((sum, grant) => sum + (Number(grant.remaining_amount) || 0), 0)
})

function formatCurrency(value: number): string {
  return `$${(Number(value) || 0).toFixed(2)}`
}

function formatDateTime(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return '-'
  }
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  }).format(date)
}

function truncateCode(code: string): string {
  if (code.length <= 16) {
    return code
  }
  return `${code.slice(0, 8)}...${code.slice(-6)}`
}
</script>
