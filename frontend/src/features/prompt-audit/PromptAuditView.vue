<template>
  <AppLayout>
    <div class="mx-auto max-w-[1600px]" :class="activeTab === 'config' && draft ? 'pb-28' : 'pb-8'">
      <header class="mb-6 flex flex-wrap items-end justify-between gap-4">
        <div>
          <p class="text-xs font-semibold uppercase tracking-[0.16em] text-primary-600 dark:text-primary-400">{{ t('nav.securityAudit') }}</p>
          <h1 class="mt-1 text-2xl font-semibold tracking-tight text-gray-950 dark:text-white">{{ t('admin.promptAudit.title') }}</h1>
          <p class="mt-2 max-w-3xl text-sm text-gray-500 dark:text-dark-300">{{ auditDescription(locale) }}</p>
        </div>
        <div v-if="draft" class="text-right text-xs text-gray-500 dark:text-dark-400">
          <p>{{ t('admin.promptAudit.configVersion', { version: draft.config_version }) }}</p>
          <p v-if="draft.updated_at" class="mt-1">{{ formatDate(draft.updated_at) }}</p>
        </div>
      </header>

      <div v-if="loadErrors.config && !draft" role="alert" class="rounded-xl border border-red-200 bg-red-50 p-5 dark:border-red-900 dark:bg-red-950/30">
        <p class="text-sm text-red-700 dark:text-red-300">{{ loadErrors.config }}</p>
        <button type="button" class="btn btn-secondary btn-sm mt-3" @click="loadConfig">{{ t('admin.promptAudit.actions.retry') }}</button>
      </div>

      <template v-else>
        <div class="mb-4" role="tablist" :aria-label="t('admin.promptAudit.title')">
          <div class="tabs inline-flex">
            <button
              v-for="tab in pageTabs"
              :key="tab.id"
              type="button"
              role="tab"
              class="tab"
              :class="{ 'tab-active': activeTab === tab.id }"
              :aria-selected="activeTab === tab.id"
              :data-test="`tab-${tab.id}`"
              @click="activeTab = tab.id"
            >
              {{ tab.label }}
            </button>
          </div>
        </div>

        <main class="card px-4 sm:px-6 lg:px-8">
          <div v-show="activeTab === 'config'" data-test="tab-panel-config">
            <RuntimeOverview :runtime="runtime" :loading="loading.runtime" :error="loadErrors.runtime" @refresh="loadRuntime" />

            <template v-if="draft">
              <EndpointPool
                :endpoints="draft.endpoints"
                :oauth-accounts="oauthAccounts"
                :probe-results="probeResults"
                :probing-ids="probingIds"
                @update:endpoints="updateEndpoints"
                @probe="runProbe"
              />
              <div v-if="loadErrors.groups || loadErrors.accounts" role="alert" class="mt-5 rounded-lg bg-amber-50 px-4 py-3 text-sm text-amber-800 dark:bg-amber-950/30 dark:text-amber-200">{{ loadErrors.groups || loadErrors.accounts }}</div>
              <PolicyPanel :draft="draft" :groups="groups" @update:draft="replaceDraft" />
              <PolicyHistory
                :versions="policyVersions"
                :current-version="serverConfig?.config_version || 0"
                :loading="loading.policies"
                :error="loadErrors.policies"
                :disabled="dirty"
                :rolling-back="rollingBackVersion"
                @refresh="loadPolicyVersions"
                @rollback="requestPolicyRollback"
              />
            </template>
          </div>

          <div v-show="activeTab === 'events'" data-test="tab-panel-events">
            <div
              v-if="draft?.enabled && !draft.store_pass_events"
              data-test="pass-events-disabled-notice"
              role="status"
              class="mt-6 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900 dark:border-amber-900/70 dark:bg-amber-950/30 dark:text-amber-200"
            >
              <span>{{ t('admin.promptAudit.events.passEventsDisabled') }}</span>
              <button type="button" class="btn btn-secondary btn-sm" @click="activeTab = 'config'">
                {{ t('admin.promptAudit.events.openConfiguration') }}
              </button>
            </div>
            <EventWorkspace
              :events="events.items"
              :total="events.total"
              :page="events.page"
              :page-size="events.page_size"
              :filters="filters"
              :selected-ids="selectedEventIds"
              :loading="loading.events"
              :error="loadErrors.events"
              @filters-change="handleFiltersChanged"
              @search="applyEventFilters"
              @selection="selectedEventIds = $event"
              @page="changePage"
              @page-size="changePageSize"
              @view="openEvent"
              @delete="requestSingleDelete"
              @batch-delete="requestBatchDelete"
              @preview-delete="requestFilterDeletePreview"
            />
          </div>

          <div v-show="activeTab === 'adaptive'" data-test="tab-panel-adaptive">
            <AdaptiveWorkspace
              :samples="adaptiveSamples.items"
              :total="adaptiveSamples.total"
              :page="adaptiveSamples.page"
              :page-size="adaptiveSamples.page_size"
              :status="adaptiveStatus"
              :loading="loading.adaptive"
              :error="loadErrors.adaptive"
              :reviewing-id="reviewingSampleId"
              @status="changeAdaptiveStatus"
              @page="changeAdaptivePage"
              @page-size="changeAdaptivePageSize"
              @refresh="loadAdaptiveSamples"
              @review="reviewAdaptiveSample"
            />
          </div>
        </main>
      </template>
    </div>

    <div v-if="draft && activeTab === 'config'" class="fixed inset-x-0 bottom-0 z-30 border-t border-gray-200 bg-white/95 px-4 py-3 shadow-[0_-12px_35px_rgba(15,23,42,0.08)] backdrop-blur dark:border-dark-700/80 dark:bg-dark-900/95 dark:shadow-[0_-12px_35px_rgba(0,0,0,0.35)] lg:left-64">
      <div class="mx-auto flex max-w-[1600px] flex-wrap items-center justify-between gap-3">
        <div class="flex flex-wrap items-center gap-x-5 gap-y-2">
          <SaveToggle :label="t('admin.promptAudit.saveBar.enabled')" :model-value="draft.enabled" data-test="enabled-toggle" @update:model-value="setEnabled" />
          <SaveToggle :label="t('admin.promptAudit.saveBar.blocking')" :model-value="draft.blocking_enabled" :disabled="!draft.enabled" data-test="blocking-toggle" @update:model-value="setBlocking" />
          <div class="flex items-center gap-2 text-sm" :class="!draft.enabled || !draft.blocking_enabled ? 'opacity-50' : ''" data-test="blocking-audit-mode">
            <span class="whitespace-nowrap text-gray-700 dark:text-dark-200">{{ t('admin.promptAudit.auditMode.label') }}</span>
            <div class="inline-flex overflow-hidden rounded-lg border border-gray-200 bg-white dark:border-dark-600 dark:bg-dark-800" role="group" :aria-label="t('admin.promptAudit.auditMode.label')">
              <button
                v-for="mode in blockingAuditModes"
                :key="mode.id"
                type="button"
                class="px-2.5 py-1 text-xs font-medium transition-colors"
                :class="draft.blocking_audit_mode === mode.id ? 'bg-primary-600 text-white' : 'text-gray-600 hover:bg-gray-50 dark:text-dark-200 dark:hover:bg-dark-700'"
                :disabled="!draft.enabled || !draft.blocking_enabled"
                :title="mode.description"
                :aria-pressed="draft.blocking_audit_mode === mode.id"
                :data-test="`blocking-audit-mode-${mode.id}`"
                @click="setBlockingAuditMode(mode.id)"
              >
                {{ mode.label }}
              </button>
            </div>
          </div>
          <div class="flex items-center gap-2 text-sm" :class="!draft.enabled ? 'opacity-50' : ''" data-test="background-audit-mode">
            <span class="whitespace-nowrap text-gray-700 dark:text-dark-200">{{ t('admin.promptAudit.auditMode.backgroundLabel') }}</span>
            <div class="inline-flex overflow-hidden rounded-lg border border-gray-200 bg-white dark:border-dark-600 dark:bg-dark-800" role="group" :aria-label="t('admin.promptAudit.auditMode.backgroundLabel')">
              <button
                v-for="mode in backgroundAuditModes"
                :key="mode.id"
                type="button"
                class="px-2.5 py-1 text-xs font-medium transition-colors"
                :class="draft.background_audit_mode === mode.id ? 'bg-primary-600 text-white' : 'text-gray-600 hover:bg-gray-50 dark:text-dark-200 dark:hover:bg-dark-700'"
                :disabled="!draft.enabled || (!draft.blocking_enabled && mode.id === 'off')"
                :title="mode.description"
                :aria-pressed="draft.background_audit_mode === mode.id"
                :data-test="`background-audit-mode-${mode.id}`"
                @click="setBackgroundAuditMode(mode.id)"
              >
                {{ mode.label }}
              </button>
            </div>
          </div>
          <SaveToggle :label="t('admin.promptAudit.saveBar.storePass')" :model-value="draft.store_pass_events" data-test="store-pass-toggle" @update:model-value="replaceDraft({ ...draft!, store_pass_events: $event })" />
        </div>
        <div class="flex items-center gap-3">
          <span class="text-sm" :class="dirty ? 'text-amber-700 dark:text-amber-300' : 'text-gray-500 dark:text-dark-400'">
            {{ dirty ? t('admin.promptAudit.saveBar.dirty') : t('admin.promptAudit.saveBar.synced') }}
          </span>
          <button type="button" class="btn btn-secondary" :disabled="!dirty || loading.saving" @click="resetDraft">{{ t('common.reset') }}</button>
          <button type="button" class="btn btn-primary" :disabled="!dirty || loading.saving" data-test="save-config" @click="saveConfig">
            {{ loading.saving ? t('common.saving') : t('common.save') }}
          </button>
        </div>
      </div>
    </div>

    <ConfirmDialog
      :show="showBlockingConfirmation"
      :title="t('admin.promptAudit.blockingConfirm.title')"
      :message="t('admin.promptAudit.blockingConfirm.message')"
      :confirm-text="t('admin.promptAudit.blockingConfirm.confirm')"
      danger
      @confirm="confirmBlocking"
      @cancel="showBlockingConfirmation = false"
    />
    <ConfirmDialog
      :show="policyRollbackTarget > 0"
      :title="t('admin.promptAudit.history.rollbackConfirmTitle')"
      :message="t('admin.promptAudit.history.rollbackConfirmMessage', { version: policyRollbackTarget })"
      :confirm-text="t('admin.promptAudit.history.rollback')"
      danger
      @confirm="confirmPolicyRollback"
      @cancel="policyRollbackTarget = 0"
    />
    <ConfirmDialog
      :show="deleteRequest.mode !== ''"
      :title="t('admin.promptAudit.events.deleteConfirmTitle')"
      :message="t('admin.promptAudit.events.deleteConfirmMessage', { count: deleteRequest.ids.length })"
      :confirm-text="t('common.delete')"
      danger
      @confirm="confirmIDDelete"
      @cancel="clearDeleteRequest"
    />
    <FilterDeleteDialog
      :show="showFilterDelete"
      :initial-filters="filters"
      :preview="deletePreview"
      :previewing="loading.previewing"
      :deleting="loading.deleting"
      @close="closeFilterDelete"
      @preview="runFilterDeletePreview"
      @confirm="confirmFilterDelete"
      @criteria-change="clearDeletePreview"
    />
    <EventDetailDialog :show="showEventDetail" :event="activeEvent" :loading="loading.detail" @close="closeEventDetail" />
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, defineComponent, h, onMounted, onBeforeUnmount, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import AppLayout from '@/components/layout/AppLayout.vue'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import { useAppStore } from '@/stores/app'
import { extractApiErrorCode, extractApiErrorMessage } from '@/utils/apiError'
import RuntimeOverview from './components/RuntimeOverview.vue'
import EndpointPool from './components/EndpointPool.vue'
import PolicyPanel from './components/PolicyPanel.vue'
import EventWorkspace from './components/EventWorkspace.vue'
import EventDetailDialog from './components/EventDetailDialog.vue'
import FilterDeleteDialog from './components/FilterDeleteDialog.vue'
import AdaptiveWorkspace from './components/AdaptiveWorkspace.vue'
import PolicyHistory from './components/PolicyHistory.vue'
import promptAuditAPI from './api'
import type {
  PromptAuditDraft,
  PromptBackgroundAuditMode,
  PromptBlockingAuditMode,
  PromptAuditEndpointDraft,
  PromptAuditEvent,
  PromptAuditGroup,
  PromptAuditRuntime,
  PromptAuditOAuthAccount,
  PromptDeletePreview,
  PromptEventFilters,
  PromptEventPage,
  PromptLoadErrors,
  PromptProbeResult,
  PromptAdaptiveSamplePage,
  PromptPolicyVersion,
} from './types'
import { buildUpdateRequest, cloneData, configToDraft, draftFingerprint, emptyEventFilters } from './viewModel'
import { auditDescription, createLatestRequestGate } from './securityViewModel'

const { t, locale } = useI18n()
const eventsGate = createLatestRequestGate()
const detailGate = createLatestRequestGate()
const previewGate = createLatestRequestGate()
onBeforeUnmount(() => {
  eventsGate.invalidate()
  detailGate.invalidate()
  previewGate.invalidate()
})
const appStore = useAppStore()
type PromptAuditPageTab = 'config' | 'events' | 'adaptive'
const activeTab = ref<PromptAuditPageTab>('events')
const pageTabs = computed(() => [
  { id: 'events' as const, label: t('admin.promptAudit.tabs.events') },
  { id: 'adaptive' as const, label: t('admin.promptAudit.tabs.adaptive') },
  { id: 'config' as const, label: t('admin.promptAudit.tabs.config') },
])
const blockingAuditModes = computed<Array<{ id: PromptBlockingAuditMode; label: string; description: string }>>(() => [
  { id: 'fast_latest', label: t('admin.promptAudit.auditMode.fast'), description: t('admin.promptAudit.auditMode.fastHint') },
  { id: 'incremental_full', label: t('admin.promptAudit.auditMode.incremental'), description: t('admin.promptAudit.auditMode.incrementalHint') },
  { id: 'full', label: t('admin.promptAudit.auditMode.full'), description: t('admin.promptAudit.auditMode.fullHint') },
])
const backgroundAuditModes = computed<Array<{ id: PromptBackgroundAuditMode; label: string; description: string }>>(() => [
  { id: 'off', label: t('admin.promptAudit.auditMode.off'), description: t('admin.promptAudit.auditMode.offHint') },
  ...blockingAuditModes.value,
])
const serverConfig = ref<PromptAuditDraft | null>(null)
const draft = ref<PromptAuditDraft | null>(null)
const runtime = ref<PromptAuditRuntime | null>(null)
const groups = ref<PromptAuditGroup[]>([])
const oauthAccounts = ref<PromptAuditOAuthAccount[]>([])
const policyVersions = ref<PromptPolicyVersion[]>([])
const events = reactive<PromptEventPage>({ items: [], total: 0, page: 1, page_size: 20, pages: 0 })
const adaptiveSamples = reactive<PromptAdaptiveSamplePage>({ items: [], total: 0, page: 1, page_size: 20, pages: 0 })
const adaptiveStatus = ref('review_pending')
const reviewingSampleId = ref(0)
const filters = ref<PromptEventFilters>(emptyEventFilters())
const appliedFilters = ref<PromptEventFilters>(emptyEventFilters())
const selectedEventIds = ref<number[]>([])
const activeEvent = ref<PromptAuditEvent | null>(null)
const showEventDetail = ref(false)
const probeResults = reactive<Record<string, PromptProbeResult>>({})
const probingIds = ref<string[]>([])
const showFilterDelete = ref(false)
const deletePreview = ref<PromptDeletePreview | null>(null)
const deletePreviewFilters = ref<PromptEventFilters | null>(null)
const showBlockingConfirmation = ref(false)
const policyRollbackTarget = ref(0)
const rollingBackVersion = ref(0)
const deleteRequest = reactive<{ mode: '' | 'single' | 'batch'; ids: number[] }>({ mode: '', ids: [] })
const loading = reactive({ config: false, runtime: false, groups: false, accounts: false, events: false, adaptive: false, policies: false, saving: false, detail: false, deleting: false, previewing: false })
const loadErrors = reactive<PromptLoadErrors>({ config: '', runtime: '', groups: '', accounts: '', events: '', adaptive: '', policies: '' })
const dirty = computed(() => draftFingerprint(draft.value) !== draftFingerprint(serverConfig.value))

function setBlockingAuditMode(mode: PromptBlockingAuditMode) {
  if (!draft.value || !draft.value.enabled || !draft.value.blocking_enabled) return
  replaceDraft({ ...draft.value, blocking_audit_mode: mode, blocking_latest_turn_only: mode !== 'full' })
}

function setBackgroundAuditMode(mode: PromptBackgroundAuditMode) {
  if (!draft.value || !draft.value.enabled) return
  if (!draft.value.blocking_enabled && mode === 'off') return
  replaceDraft({ ...draft.value, background_audit_mode: mode })
}

const SaveToggle = defineComponent({
  inheritAttrs: false,
  props: { label: { type: String, required: true }, modelValue: { type: Boolean, required: true }, disabled: { type: Boolean, default: false } },
  emits: ['update:modelValue'],
  setup(props, { emit, attrs }) {
    return () => h('label', { class: ['flex items-center gap-2.5 text-sm', props.disabled ? 'cursor-not-allowed opacity-50' : 'cursor-pointer'] }, [
      h('button', {
        ...attrs,
        type: 'button',
        role: 'switch',
        'aria-checked': props.modelValue,
        'aria-label': props.label,
        disabled: props.disabled,
        class: [
          'relative inline-flex h-6 w-11 shrink-0 items-center rounded-full border-2 border-transparent transition-colors duration-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-primary-500 focus-visible:ring-offset-2',
          props.modelValue ? 'bg-primary-600' : 'bg-gray-300 dark:bg-dark-600',
          props.disabled ? 'cursor-not-allowed' : 'cursor-pointer',
        ],
        onClick: (event: MouseEvent) => {
          event.preventDefault()
          if (!props.disabled) emit('update:modelValue', !props.modelValue)
        },
      }, [
        h('span', {
          class: [
            'pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transition-transform duration-200 ease-in-out',
            props.modelValue ? 'translate-x-5' : 'translate-x-0',
          ],
        }),
      ]),
      h('span', { class: 'select-none text-gray-700 dark:text-dark-200' }, props.label),
    ])
  },
})

function errorMessage(error: unknown, fallbackKey: string): string {
  const code = extractApiErrorCode(error)
  if (code) {
    const key = `admin.promptAudit.errors.${code}`
    const translated = t(key)
    if (translated !== key) return translated
  }
  return extractApiErrorMessage(error, t(fallbackKey))
}

async function loadConfig() {
  loading.config = true
  loadErrors.config = ''
  try {
    const config = await promptAuditAPI.getConfig()
    serverConfig.value = configToDraft(config)
    draft.value = configToDraft(config)
  } catch (error) {
    loadErrors.config = errorMessage(error, 'admin.promptAudit.errors.loadConfig')
  } finally {
    loading.config = false
  }
}
async function loadRuntime() {
  loading.runtime = true
  loadErrors.runtime = ''
  try { runtime.value = await promptAuditAPI.getRuntime() }
  catch (error) { loadErrors.runtime = errorMessage(error, 'admin.promptAudit.errors.loadRuntime') }
  finally { loading.runtime = false }
}
async function loadGroups() {
  loading.groups = true
  loadErrors.groups = ''
  try { groups.value = await promptAuditAPI.listGroups() }
  catch (error) { loadErrors.groups = errorMessage(error, 'admin.promptAudit.errors.loadGroups') }
  finally { loading.groups = false }
}
async function loadOAuthAccounts() {
  loading.accounts = true
  loadErrors.accounts = ''
  try { oauthAccounts.value = await promptAuditAPI.listOpenAIOAuthAccounts() }
  catch (error) { loadErrors.accounts = errorMessage(error, 'admin.promptAudit.errors.loadAccounts') }
  finally { loading.accounts = false }
}
async function loadEvents() {
  const ticket = eventsGate.begin()
  const query = cloneData(appliedFilters.value)
  const page = events.page
  const pageSize = events.page_size
  loading.events = true
  loadErrors.events = ''
  try {
    const result = await promptAuditAPI.listEvents(query, page, pageSize)
    if (!eventsGate.isCurrent(ticket)) return
    Object.assign(events, result)
    selectedEventIds.value = []
  } catch (error) {
    if (eventsGate.isCurrent(ticket)) loadErrors.events = errorMessage(error, 'admin.promptAudit.errors.loadEvents')
  } finally {
    if (eventsGate.isCurrent(ticket)) loading.events = false
  }
}
async function loadAdaptiveSamples() {
  loading.adaptive = true
  loadErrors.adaptive = ''
  try {
    const result = await promptAuditAPI.listAdaptiveSamples(adaptiveStatus.value, adaptiveSamples.page, adaptiveSamples.page_size)
    Object.assign(adaptiveSamples, result)
  } catch (error) {
    loadErrors.adaptive = errorMessage(error, 'admin.promptAudit.errors.loadAdaptive')
  } finally {
    loading.adaptive = false
  }
}
async function loadPolicyVersions() {
  loading.policies = true
  loadErrors.policies = ''
  try { policyVersions.value = await promptAuditAPI.listPolicyVersions(20) }
  catch (error) { loadErrors.policies = errorMessage(error, 'admin.promptAudit.errors.loadPolicies') }
  finally { loading.policies = false }
}
async function loadInitial() {
  await Promise.allSettled([loadConfig(), loadRuntime(), loadGroups(), loadOAuthAccounts(), loadEvents(), loadAdaptiveSamples(), loadPolicyVersions()])
}

function replaceDraft(value: PromptAuditDraft) { draft.value = cloneData(value) }
function updateEndpoints(value: PromptAuditEndpointDraft[]) {
  if (!draft.value) return
  replaceDraft({ ...draft.value, endpoints: value })
}
function setEnabled(value: boolean) {
  if (!draft.value) return
  const blockingEnabled = value ? draft.value.blocking_enabled : false
  const backgroundMode = value && !blockingEnabled && draft.value.background_audit_mode === 'off'
    ? 'fast_latest'
    : draft.value.background_audit_mode
  replaceDraft({ ...draft.value, enabled: value, blocking_enabled: blockingEnabled, background_audit_mode: backgroundMode })
}
function setBlocking(value: boolean) {
  if (!draft.value || !draft.value.enabled) return
  if (value && !draft.value.blocking_enabled) { showBlockingConfirmation.value = true; return }
  replaceDraft({
    ...draft.value,
    blocking_enabled: value,
    background_audit_mode: !value && draft.value.background_audit_mode === 'off' ? 'fast_latest' : draft.value.background_audit_mode,
  })
}
function confirmBlocking() {
  showBlockingConfirmation.value = false
  if (draft.value) replaceDraft({ ...draft.value, blocking_enabled: true })
}
function resetDraft() {
  if (serverConfig.value) draft.value = cloneData(serverConfig.value)
}
async function saveConfig() {
  if (!draft.value || !dirty.value || loading.saving) return
  const submitted = draftFingerprint(draft.value)
  const request = buildUpdateRequest(draft.value)
  loading.saving = true
  try {
    const saved = await promptAuditAPI.updateConfig(request)
    serverConfig.value = configToDraft(saved)
    if (draftFingerprint(draft.value) === submitted) draft.value = configToDraft(saved)
    else if (draft.value) draft.value.config_version = saved.config_version
    appStore.showSuccess(t('admin.promptAudit.messages.saved'))
    await Promise.allSettled([loadRuntime(), loadPolicyVersions()])
  } catch (error) {
    const code = extractApiErrorCode(error)
    appStore.showError(errorMessage(error, code === 'prompt_audit_config_conflict' ? 'admin.promptAudit.errors.prompt_audit_config_conflict' : 'admin.promptAudit.errors.saveConfig'))
  } finally {
    loading.saving = false
  }
}
function requestPolicyRollback(configVersion: number) {
  if (dirty.value || rollingBackVersion.value) return
  policyRollbackTarget.value = configVersion
}
async function confirmPolicyRollback() {
  const target = policyRollbackTarget.value
  const expected = serverConfig.value?.config_version || 0
  policyRollbackTarget.value = 0
  if (!target || !expected || dirty.value || rollingBackVersion.value) return
  rollingBackVersion.value = target
  try {
    const saved = await promptAuditAPI.rollbackPolicy(target, expected)
    serverConfig.value = configToDraft(saved)
    draft.value = configToDraft(saved)
    appStore.showSuccess(t('admin.promptAudit.messages.policyRolledBack', { version: target }))
    await Promise.allSettled([loadRuntime(), loadPolicyVersions()])
  } catch (error) {
    appStore.showError(errorMessage(error, 'admin.promptAudit.errors.rollbackPolicy'))
  } finally {
    rollingBackVersion.value = 0
  }
}
async function runProbe(endpoint: PromptAuditEndpointDraft) {
  if (probingIds.value.includes(endpoint.id)) return
  probingIds.value = [...probingIds.value, endpoint.id]
  try {
    const result = await promptAuditAPI.probeEndpoint(endpoint)
    probeResults[endpoint.id] = result
    if (result.ok) appStore.showSuccess(t('admin.promptAudit.messages.probeSucceeded'))
    else appStore.showError(`${result.error_code || result.status}: ${result.message}`)
  } catch (error) {
    appStore.showError(errorMessage(error, 'admin.promptAudit.errors.probe'))
  } finally {
    probingIds.value = probingIds.value.filter((id) => id !== endpoint.id)
  }
}

function handleFiltersChanged(value: PromptEventFilters) {
  filters.value = cloneData(value)
  clearDeletePreview()
}
function applyEventFilters(value: PromptEventFilters) {
  filters.value = cloneData(value)
  appliedFilters.value = cloneData(value)
  events.page = 1
  clearDeletePreview()
  void loadEvents()
}
function changePage(value: number) { events.page = value; void loadEvents() }
function changePageSize(value: number) { events.page_size = value; events.page = 1; void loadEvents() }
function changeAdaptiveStatus(value: string) { adaptiveStatus.value = value; adaptiveSamples.page = 1; void loadAdaptiveSamples() }
function changeAdaptivePage(value: number) { adaptiveSamples.page = value; void loadAdaptiveSamples() }
function changeAdaptivePageSize(value: number) { adaptiveSamples.page_size = value; adaptiveSamples.page = 1; void loadAdaptiveSamples() }
async function reviewAdaptiveSample(id: number, decision: 'allow' | 'block') {
  if (reviewingSampleId.value) return
  reviewingSampleId.value = id
  try {
    await promptAuditAPI.reviewAdaptiveSample(id, decision)
    appStore.showSuccess(t('admin.promptAudit.messages.adaptiveReviewed'))
    await Promise.allSettled([loadAdaptiveSamples(), loadRuntime()])
  } catch (error) {
    appStore.showError(errorMessage(error, 'admin.promptAudit.errors.reviewAdaptive'))
  } finally {
    reviewingSampleId.value = 0
  }
}
async function openEvent(id: number) {
  const ticket = detailGate.begin()
  showEventDetail.value = true
  loading.detail = true
  activeEvent.value = null
  try {
    const event = await promptAuditAPI.getEvent(id)
    if (detailGate.isCurrent(ticket)) activeEvent.value = event
  } catch (error) {
    if (detailGate.isCurrent(ticket)) {
      appStore.showError(errorMessage(error, 'admin.promptAudit.errors.loadDetail'))
      showEventDetail.value = false
    }
  } finally {
    if (detailGate.isCurrent(ticket)) loading.detail = false
  }
}
function closeEventDetail() {
  detailGate.invalidate()
  showEventDetail.value = false
  activeEvent.value = null
  loading.detail = false
}
function requestSingleDelete(id: number) { deleteRequest.mode = 'single'; deleteRequest.ids = [id] }
function requestBatchDelete() { if (selectedEventIds.value.length) { deleteRequest.mode = 'batch'; deleteRequest.ids = [...selectedEventIds.value] } }
function clearDeleteRequest() { deleteRequest.mode = ''; deleteRequest.ids = [] }
async function confirmIDDelete() {
  const mode = deleteRequest.mode
  const ids = [...deleteRequest.ids]
  clearDeleteRequest()
  if (!mode || ids.length === 0) return
  loading.deleting = true
  try {
    const result = mode === 'single' ? await promptAuditAPI.deleteEvent(ids[0]) : await promptAuditAPI.batchDeleteEvents(ids)
    appStore.showSuccess(t('admin.promptAudit.messages.deleted', { count: result.deleted_events }))
    await Promise.allSettled([loadEvents(), loadRuntime()])
  } catch (error) { appStore.showError(errorMessage(error, 'admin.promptAudit.errors.delete')) }
  finally { loading.deleting = false }
}
function clearDeletePreview() {
  previewGate.invalidate()
  loading.previewing = false
  deletePreview.value = null
  deletePreviewFilters.value = null
}
function requestFilterDeletePreview() {
  clearDeletePreview()
  showFilterDelete.value = true
}
function closeFilterDelete() {
  showFilterDelete.value = false
  clearDeletePreview()
}
async function runFilterDeletePreview(value: PromptEventFilters) {
  const ticket = previewGate.begin()
  const criteria = cloneData(value)
  deletePreview.value = null
  deletePreviewFilters.value = null
  loading.previewing = true
  try {
    const preview = await promptAuditAPI.previewDelete(criteria)
    if (!previewGate.isCurrent(ticket)) return
    deletePreview.value = preview
    deletePreviewFilters.value = criteria
  } catch (error) {
    if (previewGate.isCurrent(ticket)) {
      clearDeletePreview()
      appStore.showError(errorMessage(error, 'admin.promptAudit.errors.previewDelete'))
    }
  } finally {
    if (previewGate.isCurrent(ticket)) loading.previewing = false
  }
}
async function confirmFilterDelete(filters?: PromptEventFilters) {
  if (loading.deleting) return
  loading.deleting = true
  try {
    const preview = deletePreview.value
    const previewFilters = deletePreviewFilters.value ? cloneData(deletePreviewFilters.value) : null
    // Never mint a destructive confirmation token in the delete action itself.
    // The administrator must see and confirm the exact preview first.
    if (!preview || !previewFilters || loading.previewing ||
        (filters && JSON.stringify(filters) !== JSON.stringify(previewFilters))) {
      clearDeletePreview()
      appStore.showError(locale.value.startsWith('zh')
        ? '请先预览当前筛选范围并核对数量，再确认删除。'
        : 'Preview the current filters and inspect the count before confirming deletion.')
      return
    }
    const result = await promptAuditAPI.deleteEventsByFilter(previewFilters, preview)
    closeFilterDelete()
    appStore.showSuccess(t('admin.promptAudit.messages.deleted', { count: result.deleted_events }))
    await Promise.allSettled([loadEvents(), loadRuntime()])
  } catch (error) {
    clearDeletePreview()
    appStore.showError(errorMessage(error, 'admin.promptAudit.errors.deleteConfirmation'))
  } finally { loading.deleting = false }
}
function formatDate(value: string): string {
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return '—'
  return new Intl.DateTimeFormat(locale.value, { dateStyle: 'medium', timeStyle: 'medium' }).format(parsed)
}

onMounted(loadInitial)
</script>
