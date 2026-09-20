<template>
  <BaseDialog :show="show" :title="text('导入 CPA 账号', 'Import CPA account')" width="wide" @close="close">
    <div class="space-y-5">
      <p class="rounded-lg bg-emerald-50 p-3 text-sm text-emerald-800 dark:bg-emerald-900/20 dark:text-emerald-200" data-testid="cpa-only-notice">
        {{ text('授权凭证导入 CPA 账号池，不会自动创建或恢复业务桥接账号。对外调用仍需单独配置本站桥接、分组和计费。', 'Credentials are imported into the CPA pool without creating or restoring a business bridge. Serving requests still requires this site’s bridge, groups and billing configuration.') }}
      </p>
      <CPABridgeSetup :show="show" :disabled="busy" :refresh-key="bridgeRefresh" @updated="routingWarning = false; emit('created')" />
      <div class="flex gap-2" role="tablist">
        <button v-for="tab in tabs" :key="tab.id" type="button" class="btn" :class="mode === tab.id ? 'btn-primary' : 'btn-secondary'" :disabled="busy" :data-testid="`cpa-tab-${tab.id}`" role="tab" :aria-selected="mode === tab.id" @click="mode = tab.id">{{ tab.label }}</button>
      </div>
      <div v-if="mode === 'oauth'" class="space-y-3">
        <button type="button" class="btn btn-secondary" :disabled="busy || oauth.loading.value" data-testid="cpa-generate-auth" @click="oauth.generateAuthUrl(runtime.proxy_id)">{{ text('生成 OpenAI 授权链接', 'Generate OpenAI authorization link') }}</button>
        <a v-if="oauth.authUrl.value" :href="oauth.authUrl.value" target="_blank" rel="noopener noreferrer" class="block break-all text-sm text-primary-600">{{ text('打开授权页面', 'Open authorization page') }}</a>
        <label class="block text-sm">
          {{ text('授权完成后粘贴完整回调地址', 'Paste the full callback URL after authorization') }}
          <input v-model="callback" class="input mt-2 w-full" autocomplete="off" data-testid="cpa-callback" />
        </label>
      </div>
      <label v-else-if="mode === 'refresh'" class="block text-sm">
        {{ text('OpenAI Refresh Token（每行一个）', 'OpenAI refresh tokens (one per line)') }}
        <textarea v-model="refreshTokens" class="input mt-2 w-full font-mono" rows="5" autocomplete="off" spellcheck="false" data-testid="cpa-refresh-tokens" />
      </label>
      <div v-else class="space-y-3">
        <p class="text-sm text-gray-500">{{ text('支持 Codex auth.json，以及 CPA 原生 OpenAI、Claude、Gemini、Antigravity OAuth 文件。无法识别的文件会显示错误。', 'Supports Codex auth.json and native CPA OAuth files for OpenAI, Claude, Gemini and Antigravity. Unsupported files return an error.') }}</p>
        <input type="file" accept=".json,application/json" multiple :disabled="busy" data-testid="cpa-files" @change="readFiles" />
        <label class="block text-sm">
          {{ text('或粘贴授权 JSON（支持数组）', 'Or paste authorization JSON (arrays supported)') }}
          <textarea v-model="content" class="input mt-2 w-full font-mono" rows="7" autocomplete="off" spellcheck="false" data-testid="cpa-json" />
        </label>
        <p v-if="fileContents.length" class="text-sm text-gray-500">{{ text(`已读取 ${fileContents.length} 个文件`, `${fileContents.length} files loaded`) }}</p>
      </div>
      <fieldset :disabled="busy" class="space-y-3 border-t pt-4">
        <p class="text-sm text-gray-500">{{ cpaText('importScope') }}</p>
        <CPARuntimeFields v-model="runtime" :proxies="proxies || []" />
      </fieldset>
      <p v-if="error || oauth.error.value" role="alert" class="whitespace-pre-wrap text-sm text-red-600">{{ error || oauth.error.value }}</p>
      <p v-if="summary" role="status" class="whitespace-pre-wrap text-sm text-emerald-700">{{ summary }}</p>
      <p v-if="routingWarning" data-testid="cpa-routing-warning" class="rounded-lg bg-amber-50 p-3 text-sm text-amber-800 dark:bg-amber-900/20 dark:text-amber-200">{{ text('凭证已入池，但尚未配置业务桥接；此次导入没有恢复旧账号或分组，暂不能通过本站对外调用。', 'Credentials are in the pool, but no business bridge is configured. No old account or group was restored; this does not enable serving requests through this site.') }}</p>
    </div>
    <template #footer>
      <div class="flex justify-end gap-3">
        <button type="button" class="btn btn-secondary" :disabled="busy" @click="close">{{ t('common.close') }}</button>
        <button type="button" class="btn btn-primary" :disabled="busy || oauth.loading.value" data-testid="cpa-import-submit" @click="submit">{{ busy ? text('正在导入…', 'Importing…') : text('导入 CPA', 'Import into CPA') }}</button>
      </div>
    </template>
  </BaseDialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import CPARuntimeFields from './CPARuntimeFields.vue'
import CPABridgeSetup from './CPABridgeSetup.vue'
import { useCPAText } from './cpaRuntimeText'
import type { CPACredentialUpdate } from '@/api/admin/accounts'
import { adminAPI } from '@/api/admin'
import { useOpenAIOAuth } from '@/composables/useOpenAIOAuth'
import { extractApiErrorMessage } from '@/utils/apiError'
import type { AdminGroup, Proxy } from '@/types'

const props = defineProps<{ show: boolean; proxies?: Proxy[]; groups?: AdminGroup[] }>()
const emit = defineEmits<{ (event: 'close'): void; (event: 'created'): void }>()
const { t, locale } = useI18n()
const text = (zh: string, en: string) => locale.value.startsWith('zh') ? zh : en
const oauth = useOpenAIOAuth()
const cpaText = useCPAText()
const newRuntime = (): CPACredentialUpdate => ({name:'new-credential',disabled:false,proxy_id:null,priority:0,weight:1,request_retry:0})
const runtime = ref(newRuntime())
const mode = ref<'oauth' | 'refresh' | 'json'>('json')
const tabs = computed(() => [
  { id: 'json' as const, label: text('授权文件', 'Authorization files') },
  { id: 'oauth' as const, label: 'OpenAI OAuth' },
  { id: 'refresh' as const, label: 'Refresh Token' }
])
const content = ref('')
const callback = ref('')
const refreshTokens = ref('')
const fileContents = ref<string[]>([])
const busy = ref(false)
const error = ref('')
const summary = ref('')
const routingWarning = ref(false)
const bridgeRefresh = ref(0)

watch(() => props.show, (show) => { if (!show) reset() })
function reset() {
  content.value = callback.value = refreshTokens.value = error.value = summary.value = ''
  fileContents.value = []
  routingWarning.value = false
  runtime.value = newRuntime()
  oauth.resetState()
}
function close() { if (!busy.value) { reset(); emit('close') } }
async function readFiles(event: Event) {
  const files = Array.from((event.target as HTMLInputElement).files || [])
  fileContents.value = []
  if (files.length > 100 || files.reduce((sum, file) => sum + file.size, 0) > 3 * 1024 * 1024) {
    error.value = text('每次最多 100 个文件，总大小不超过 3 MB。', 'At most 100 files and 3 MB per import.')
    return
  }
  busy.value = true
  try { fileContents.value = await Promise.all(files.map((file) => file.text())); error.value = '' }
  catch { error.value = text('读取文件失败。', 'Could not read files.') }
  finally { busy.value = false }
}
async function submit() {
  if (busy.value) return
  busy.value = true
  error.value = summary.value = ''
  routingWarning.value = false
  let imported = 0
  const failures: string[] = []
  try {
    if (mode.value === 'json') {
      const contents = [...fileContents.value, ...(content.value.trim() ? [content.value.trim()] : [])]
      if (!contents.length) throw new Error(text('请选择文件或粘贴授权 JSON。', 'Select files or paste authorization JSON.'))
      const result = await adminAPI.accounts.importCPAAuthFiles(contents, runtime.value)
      imported = result.created + result.updated
      routingWarning.value = (result.items || []).some((item) => item.action !== 'failed' && !item.account_id)
      for (const item of result.errors || []) failures.push(`#${item.index}: ${item.message}`)
    } else if (mode.value === 'refresh') {
      const tokens = refreshTokens.value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean)
      if (!tokens.length || tokens.length > 100) throw new Error(text('请提供 1–100 个 Refresh Token。', 'Provide 1–100 refresh tokens.'))
      for (let index = 0; index < tokens.length; index++) {
        try {
          const tokenInfo = await oauth.validateRefreshToken(tokens[index], runtime.value.proxy_id)
          if (!tokenInfo) throw new Error(oauth.error.value || 'OAuth refresh failed')
          const credentials = oauth.buildCredentials(tokenInfo)
          credentials.refresh_token ||= tokens[index]
          const result = await adminAPI.accounts.importOpenAIOAuthToCPA(credentials, runtime.value)
          routingWarning.value ||= result.bridge_account_id === 0
          imported++
        } catch (err) { failures.push(`#${index + 1}: ${extractApiErrorMessage(err, 'Import failed')}`) }
      }
    } else {
      const url = new URL(callback.value.trim())
      const code = url.searchParams.get('code') || ''
      const state = url.searchParams.get('state') || ''
      if (!state || state !== oauth.oauthState.value || !code) throw new Error(text('回调地址与本次授权不匹配。', 'Callback does not match this authorization.'))
      const tokenInfo = await oauth.exchangeAuthCode(code, oauth.sessionId.value, state, runtime.value.proxy_id)
      if (!tokenInfo) throw new Error(oauth.error.value || 'OAuth exchange failed')
      const result = await adminAPI.accounts.importOpenAIOAuthToCPA(oauth.buildCredentials(tokenInfo), runtime.value)
      routingWarning.value = result.bridge_account_id === 0
      imported = 1
    }
    summary.value = imported > 0 ? text(`已导入 CPA：${imported} 个账号。`, `Imported into CPA: ${imported} account(s).`) : ''
    error.value = failures.join('\n')
    if (imported > 0) {
      bridgeRefresh.value++
      emit('created')
      if (!failures.length) { content.value = refreshTokens.value = callback.value = ''; fileContents.value = [] }
    }
  } catch (err) { error.value = extractApiErrorMessage(err, text('导入失败。', 'Import failed.')) }
  finally { busy.value = false }
}
</script>
