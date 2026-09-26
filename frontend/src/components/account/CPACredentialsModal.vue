<template>
  <BaseDialog :show="show" :title="text('title')" width="wide" @close="!saving && emit('close')">
    <p class="mb-4 text-sm text-gray-600 dark:text-gray-300">{{ text('scope') }}</p>
    <p v-if="error" role="alert" class="mb-3 text-sm text-red-600">{{ error }}</p>
    <p v-if="saved" role="status" class="mb-3 text-sm text-emerald-600">{{ text('saved') }}</p>
    <p v-if="loading">{{ text('loading') }}</p>
    <form v-else-if="items.length" class="space-y-4" @submit.prevent="save">
      <select v-if="!authName" class="input" :value="selected?.name || ''" :disabled="saving" data-testid="cpa-credential-choice" @change="select(($event.target as HTMLSelectElement).value)">
        <option value="">{{ text('chooseCredential') }}</option>
        <option v-for="item in items" :key="item.name" :value="item.name">{{ item.email || item.name }} — {{ item.disabled ? 'Disabled' : item.status }}</option>
      </select>
      <template v-if="selected">
      <p class="break-all text-xs text-gray-500">{{ selected.name }}</p>
      <p class="rounded-lg bg-slate-50 p-3 text-sm text-slate-700 dark:bg-dark-800 dark:text-dark-200" data-testid="cpa-routing-status">{{ routingDescription }}</p>
      <p v-if="selected.proxy_configured && !selected.proxy_id" class="text-sm text-amber-600">{{ text('unmanaged') }}</p>
      <fieldset :disabled="saving"><CPARuntimeFields :model-value="selected" :proxies="proxies" @update:model-value="edit" /></fieldset>
      <button class="btn btn-primary" type="submit" :disabled="saving">{{ text('save') }}</button>
      </template>
      <p v-else-if="!authName" class="text-sm text-gray-500">{{ text('chooseCredential') }}</p>
    </form>
    <p v-else>{{ text('empty') }}</p>
  </BaseDialog>
</template>
<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import BaseDialog from '@/components/common/BaseDialog.vue'
import CPARuntimeFields from './CPARuntimeFields.vue'
import { useCPAText } from './cpaRuntimeText'
import { listCPACredentials, updateCPACredential, type CPACredentialSettings, type CPACredentialUpdate } from '@/api/admin/accounts'
import { getAll } from '@/api/admin/proxies'
import type { Proxy } from '@/types'
const props = defineProps<{show: boolean; authName?: string}>()
const emit = defineEmits<{close: []}>()
const text = useCPAText()
const items = ref<CPACredentialSettings[]>([])
const selected = ref<CPACredentialSettings | null>(null)
const proxies = ref<Proxy[]>([])
const loading = ref(false), saving = ref(false), saved = ref(false), error = ref('')
function message(e: unknown) { const v = e as {response?: {data?: {message?: string}}}; return v?.response?.data?.message || text('failed') }
function edit(next: CPACredentialUpdate) { if (selected.value) selected.value = {...selected.value, ...next}; saved.value = false }
function select(name: string) { const item = items.value.find(i => i.name === name); selected.value = item ? {...item} : null; saved.value = false }
const routingDescription = computed(() => {
  if (selected.value?.business_backend === 'pi') return text('piRouting')
  if (selected.value?.cpa_routing_enabled === true) return text('cpaRouting')
  if (selected.value?.cpa_routing_enabled === false) return text('cpaDormant')
  return text('unknownRouting')
})
let loadVersion = 0
watch([() => props.show, () => props.authName], async ([show, authName]) => {
  const version = ++loadVersion
  selected.value = null
  if (!show) return
  error.value = ''; saved.value = false; loading.value = true
  try {
    const [credentials, availableProxies] = await Promise.all([listCPACredentials(), getAll()])
    if (version !== loadVersion) return
    items.value = credentials; proxies.value = availableProxies
    if (authName) {
      const exact = credentials.find(item => item.name === authName)
      if (exact) selected.value = {...exact}
      else error.value = text('credentialMissing')
    }
  }
  catch (e) { if (version === loadVersion) { error.value = message(e); selected.value = null } }
  finally { if (version === loadVersion) loading.value = false }
}, {immediate: true})
async function save() {
  if (!selected.value || saving.value) return
  const version = loadVersion
  const requested = {...selected.value}
  saving.value = true; saved.value = false; error.value = ''
  try {
    const next = await updateCPACredential(requested)
    if (version !== loadVersion) return
    items.value = items.value.map(item => item.name === next.name ? next : item)
    selected.value = {...requested, ...next}; saved.value = true
  }
  catch (e) { if (version === loadVersion) error.value = message(e) }
  finally { saving.value = false }
}
</script>
