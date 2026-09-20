<template>
  <BaseDialog :show="show" :title="t('admin.proxies.clashImportTitle')" width="normal" close-on-click-outside @close="handleClose">
    <form id="clash-proxy-import-form" class="space-y-4" @submit.prevent="handleImport">
      <p class="text-sm text-gray-600 dark:text-dark-300">{{ t('admin.proxies.clashImportHint') }}</p>
      <div class="flex flex-wrap gap-2">
        <button type="button" class="btn btn-secondary text-xs" @click="copyTemplate">{{ t('admin.proxies.clashImportCopyTemplate') }}</button>
        <button type="button" class="btn btn-secondary text-xs" @click="downloadTemplate">{{ t('admin.proxies.clashImportDownloadTemplate') }}</button>
      </div>
      <div class="rounded-lg border border-blue-200 bg-blue-50 p-3 text-xs text-blue-700 dark:border-blue-800 dark:bg-blue-900/20 dark:text-blue-300">
        {{ t('admin.proxies.clashImportSupported') }}
      </div>
      <div>
        <label class="input-label">{{ t('admin.proxies.clashImportFile') }}</label>
        <div class="flex items-center justify-between gap-3 rounded-lg border border-dashed border-gray-300 bg-gray-50 px-4 py-3 dark:border-dark-600 dark:bg-dark-800">
          <div class="min-w-0">
            <div class="truncate text-sm text-gray-700 dark:text-dark-200">{{ fileName || t('admin.proxies.clashImportSelectFile') }}</div>
            <div class="text-xs text-gray-500 dark:text-dark-400">Clash YAML / JSON / proxy URL</div>
          </div>
          <button type="button" class="btn btn-secondary shrink-0" @click="openFilePicker">{{ t('common.chooseFile') }}</button>
        </div>
        <input ref="fileInput" type="file" class="hidden" accept=".yaml,.yml,.json,.txt,text/yaml,application/json,text/plain" @change="handleFileChange" />
      </div>
      <textarea v-model="rawText" rows="8" class="input font-mono text-xs" :placeholder="t('admin.proxies.clashImportPastePlaceholder')" @input="parseInput"></textarea>
      <div v-if="parseResult" class="space-y-2 rounded-xl border border-gray-200 p-4 text-sm dark:border-dark-700">
        <div class="flex flex-wrap gap-3">
          <span class="text-green-600 dark:text-green-400">{{ t('admin.proxies.clashImportValid', { count: parseResult.candidates.length }) }}</span>
          <span v-if="parseResult.unsupported.length" class="text-amber-600 dark:text-amber-400">{{ t('admin.proxies.clashImportUnsupported', { count: parseResult.unsupported.length }) }}</span>
          <span v-if="parseResult.invalid.length" class="text-red-600 dark:text-red-400">{{ t('admin.proxies.clashImportInvalid', { count: parseResult.invalid.length }) }}</span>
        </div>
        <div v-if="parseResult.unsupported.length || parseResult.invalid.length" class="max-h-36 overflow-auto rounded-lg bg-gray-50 p-3 text-xs dark:bg-dark-800">
          <div v-for="(item, index) in [...parseResult.unsupported, ...parseResult.invalid]" :key="index" class="whitespace-pre-wrap">{{ item.name || '-' }} — {{ item.reason }}</div>
        </div>
      </div>
    </form>
    <template #footer>
      <div class="flex justify-end gap-3">
        <button class="btn btn-secondary" type="button" :disabled="importing" @click="handleClose">{{ t('common.cancel') }}</button>
        <button class="btn btn-primary" type="submit" form="clash-proxy-import-form" :disabled="importing || !parseResult?.candidates.length">
          {{ importing ? t('admin.proxies.clashImporting') : t('admin.proxies.clashImportButton') }}
        </button>
      </div>
    </template>
  </BaseDialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import { adminAPI } from '@/api/admin'
import { useAppStore } from '@/stores/app'
import { parseClashProxyConfig, type ClashProxyParseResult } from '@/utils/clashProxyParser'

interface Props { show: boolean }
const props = defineProps<Props>()
const emit = defineEmits<{ (e: 'close'): void; (e: 'imported'): void }>()
const { t } = useI18n()
const appStore = useAppStore()
const fileInput = ref<HTMLInputElement | null>(null)
const file = ref<File | null>(null)
const rawText = ref('')
const parseResult = ref<ClashProxyParseResult | null>(null)
const importing = ref(false)
const fileName = computed(() => file.value?.name || '')

const clashTemplate = `proxies:
  - name: office-http
    type: http
    server: proxy.example.com
    port: 8080
    username: your-user
    password: your-password
  - name: office-socks5
    type: socks5
    server: 192.0.2.10
    port: 1080
`

watch(() => props.show, (open) => {
  if (open) {
    file.value = null
    rawText.value = ''
    parseResult.value = null
    if (fileInput.value) fileInput.value.value = ''
  }
})

const openFilePicker = () => fileInput.value?.click()
const copyTemplate = async () => {
  try {
    await navigator.clipboard.writeText(clashTemplate)
    appStore.showSuccess(t('admin.proxies.clashImportTemplateCopied'))
  } catch {
    appStore.showError(t('admin.proxies.clashImportTemplateCopyFailed'))
  }
}
const downloadTemplate = () => {
  const blob = new Blob([clashTemplate], { type: 'text/yaml;charset=utf-8' })
  const link = document.createElement('a')
  link.href = URL.createObjectURL(blob)
  link.download = 'sub2api-clash-proxies.yaml'
  link.click()
  URL.revokeObjectURL(link.href)
}
const parseInput = () => { parseResult.value = rawText.value.trim() ? parseClashProxyConfig(rawText.value) : null }
const handleFileChange = async (event: Event) => {
  const target = event.target as HTMLInputElement
  file.value = target.files?.[0] || null
  if (!file.value) return
  rawText.value = await file.value.text()
  parseInput()
}
const handleClose = () => { if (!importing.value) emit('close') }
const handleImport = async () => {
  if (!parseResult.value?.candidates.length) {
    appStore.showError(t('admin.proxies.clashImportNoValid'))
    return
  }
  importing.value = true
  try {
    const result = await adminAPI.proxies.batchCreate(parseResult.value.candidates.map((item, index) => ({ ...item, name: item.name || `clash-${index + 1}` })))
    appStore.showSuccess(t('admin.proxies.clashImportSuccess', result))
    emit('imported')
  } catch (error: any) {
    appStore.showError(error?.response?.data?.detail || error?.message || t('admin.proxies.clashImportFailed'))
  } finally {
    importing.value = false
  }
}
</script>
