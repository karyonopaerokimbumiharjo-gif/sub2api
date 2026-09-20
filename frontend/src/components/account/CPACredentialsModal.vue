<template>
  <BaseDialog :show="show" :title="text('title')" width="wide" @close="!saving && emit('close')">
    <p class="mb-4 text-sm text-gray-600 dark:text-gray-300">{{ text('scope') }}</p>
    <p v-if="error" role="alert" class="mb-3 text-sm text-red-600">{{ error }}</p>
    <p v-if="saved" role="status" class="mb-3 text-sm text-emerald-600">{{ text('saved') }}</p>
    <p v-if="loading">{{ text('loading') }}</p>
    <form v-else-if="selected" class="space-y-4" @submit.prevent="save">
      <select class="input" :value="selected.name" :disabled="saving" @change="select(($event.target as HTMLSelectElement).value)">
        <option v-for="item in items" :key="item.name" :value="item.name">{{ item.email || item.name }} — {{ item.disabled ? 'Disabled' : item.status }}</option>
      </select>
      <p class="break-all text-xs text-gray-500">{{ selected.name }}</p>
      <p v-if="selected.proxy_configured && !selected.proxy_id" class="text-sm text-amber-600">{{ text('unmanaged') }}</p>
      <fieldset :disabled="saving"><CPARuntimeFields :model-value="selected" :proxies="proxies" @update:model-value="edit" /></fieldset>
      <button class="btn btn-primary" type="submit" :disabled="saving">{{ text('save') }}</button>
    </form>
    <p v-else>{{ text('empty') }}</p>
  </BaseDialog>
</template>
<script setup lang="ts">
import { ref, watch } from 'vue'
import BaseDialog from '@/components/common/BaseDialog.vue'
import CPARuntimeFields from './CPARuntimeFields.vue'
import { useCPAText } from './cpaRuntimeText'
import { listCPACredentials, updateCPACredential, type CPACredentialSettings, type CPACredentialUpdate } from '@/api/admin/accounts'
import { getAll } from '@/api/admin/proxies'
import type { Proxy } from '@/types'
const props = defineProps<{show: boolean}>()
const emit = defineEmits<{close: []}>()
const text = useCPAText()
const items = ref<CPACredentialSettings[]>([])
const selected = ref<CPACredentialSettings | null>(null)
const proxies = ref<Proxy[]>([])
const loading = ref(false), saving = ref(false), saved = ref(false), error = ref('')
function message(e: unknown) { const v = e as {response?: {data?: {message?: string}}}; return v?.response?.data?.message || text('failed') }
function edit(next: CPACredentialUpdate) { if (selected.value) selected.value = {...selected.value, ...next}; saved.value = false }
function select(name: string) { selected.value = {...items.value.find(i => i.name === name)!}; saved.value = false }
watch(() => props.show, async show => {
  if (!show) return
  error.value = ''; saved.value = false; loading.value = true
  try { [items.value, proxies.value] = await Promise.all([listCPACredentials(), getAll()]); const first = items.value.find(i => !i.disabled) || items.value[0]; selected.value = first ? {...first} : null }
  catch (e) { error.value = message(e); selected.value = null }
  finally { loading.value = false }
}, {immediate: true})
async function save() {
  if (!selected.value || saving.value) return
  saving.value = true; saved.value = false; error.value = ''
  try { const next = await updateCPACredential(selected.value); items.value = items.value.map(i => i.name === next.name ? next : i); selected.value = next; saved.value = true }
  catch (e) { error.value = message(e) }
  finally { saving.value = false }
}
</script>
