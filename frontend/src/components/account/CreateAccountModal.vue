<template>
  <BaseDialog :show="show" :title="text('导入账号', 'Import account')" width="wide" @close="close">
    <div class="space-y-5">
      <p class="rounded-lg bg-emerald-50 p-3 text-sm text-emerald-800 dark:bg-emerald-900/20 dark:text-emerald-200" data-testid="cpa-only-notice">
        {{ text('完成授权后点击导入，账号会自动加入所选分组。同一账号重复授权会更新原账号，并保留原有 CPA / Pi 调用方式。', 'Authorize and import to add the account to the selected group. Reauthorizing updates the existing account and preserves its CPA / Pi backend.') }}
      </p>
      <label class="block text-sm">
        {{ text('账号分组', 'Account group') }}
        <select v-model="groupId" class="input mt-2 w-full" :disabled="busy" data-testid="cpa-import-group">
          <option value="">{{ text('请选择已启用的 OpenAI 分组', 'Select an active OpenAI group') }}</option>
          <option v-for="group in openAIGroups" :key="group.id" :value="group.id">{{ group.name }}</option>
        </select>
        <span v-if="!openAIGroups.length" class="mt-1 block text-amber-700">{{ text('请先创建并启用 OpenAI 分组，再导入账号。', 'Create and enable an OpenAI group before importing accounts.') }}</span>
      </label>
      <div class="flex gap-2" role="tablist">
        <button v-for="tab in tabs" :key="tab.id" type="button" class="btn" :class="mode === tab.id ? 'btn-primary' : 'btn-secondary'" :disabled="busy" :data-testid="`cpa-tab-${tab.id}`" role="tab" :aria-selected="mode === tab.id" @click="mode = tab.id">{{ tab.label }}</button>
      </div>
      <div v-if="mode === 'oauth'" class="space-y-3">
        <button type="button" class="btn btn-secondary" :disabled="busy || oauth.loading.value" data-testid="cpa-generate-auth" @click="generateAuthUrl">{{ text('生成 OpenAI 授权链接', 'Generate OpenAI authorization URL') }}</button>
        <a v-if="oauth.authUrl.value" :href="oauth.authUrl.value" target="_blank" rel="noopener noreferrer" class="block break-all text-sm text-primary-600">{{ text('打开授权页面', 'Open authorization page') }}</a>
        <div v-if="oauth.authUrl.value" class="space-y-2">
          <input :value="oauth.authUrl.value" readonly class="input w-full text-xs" :aria-label="text('本次 OpenAI 授权链接', 'Current OpenAI authorization URL')" data-testid="cpa-auth-url" />
          <button type="button" class="btn btn-secondary" data-testid="cpa-copy-auth" @click="copyAuthUrl">{{ authLinkCopied ? text('已复制', 'Copied') : text('复制授权链接', 'Copy authorization link') }}</button>
        </div>
        <p class="text-sm text-gray-500">{{ text('点击生成链接并登录 OpenAI；完成后将地址栏中的完整回调 URL 粘贴到下方。如果 localhost 回调页面无法打开，仍可复制该地址。不需要把授权码或令牌发到聊天里。', 'Generate a link and sign in to OpenAI, then paste the full callback URL below. If the localhost callback page cannot open, copy its address anyway. Do not send authorization codes or tokens in chat.') }}</p>
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
        <p class="text-sm text-gray-500">{{ text('支持 Codex auth.json 和 OpenAI OAuth 授权文件。', 'Supports Codex auth.json and OpenAI OAuth authorization files.') }}</p>
        <input type="file" accept=".json,application/json" multiple :disabled="busy" data-testid="cpa-files" @change="readFiles" />
        <label class="block text-sm">
          {{ text('或粘贴授权 JSON（支持数组）', 'Or paste authorization JSON (arrays supported)') }}
          <textarea v-model="content" class="input mt-2 w-full font-mono" rows="7" autocomplete="off" spellcheck="false" data-testid="cpa-json" />
        </label>
        <p v-if="fileContents.length" class="text-sm text-gray-500">{{ text(`已读取 ${fileContents.length} 个文件`, `${fileContents.length} files loaded`) }}</p>
      </div>
      <details class="border-t pt-4">
        <summary class="cursor-pointer text-sm text-gray-600">{{ text('高级设置（可选）', 'Advanced settings (optional)') }}</summary>
        <fieldset :disabled="busy" class="mt-3 space-y-3">
          <p class="text-sm text-gray-500">{{ cpaText('importScope') }}</p>
          <CPARuntimeFields v-model="runtime" :proxies="proxies || []" :allow-preserve="false" />
        </fieldset>
      </details>
      <p v-if="error || oauth.error.value" role="alert" class="whitespace-pre-wrap text-sm text-red-600">{{ error || oauth.error.value }}</p>
      <p v-if="summary" role="status" class="whitespace-pre-wrap text-sm text-emerald-700">{{ summary }}</p>
    </div>
    <template #footer>
      <div class="flex justify-end gap-3">
        <button type="button" class="btn btn-secondary" :disabled="busy" @click="close">{{ t('common.close') }}</button>
        <button type="button" class="btn btn-primary" :disabled="busy || oauth.loading.value" data-testid="cpa-import-submit" @click="submit">{{ busy ? text('正在导入…', 'Importing…') : text('导入账号', 'Import account') }}</button>
      </div>
    </template>
  </BaseDialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import CPARuntimeFields from './CPARuntimeFields.vue'
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
const newRuntime = (): CPACredentialUpdate => ({ name: 'new-credential', disabled: false, proxy_id: 0, priority: 0, weight: 1, request_retry: 0 })
const runtime = ref(newRuntime())
const mode = ref<'oauth' | 'refresh' | 'json'>('json')
const authLinkCopied = ref(false)
const tabs = computed(() => [
  { id: 'json' as const, label: text('授权文件', 'Authorization files') },
  { id: 'oauth' as const, label: 'OpenAI OAuth' },
  { id: 'refresh' as const, label: 'Refresh Token' }
])
const content = ref('')
const callback = ref('')
// Authorization codes are single-use. Keep exchanged credentials in memory for an import retry.
let pendingOAuth: { key: string; credentials: ReturnType<typeof oauth.buildCredentials> } | null = null
watch(callback, () => { pendingOAuth = null })
const refreshTokens = ref('')
const fileContents = ref<string[]>([])
const busy = ref(false)
const error = ref('')
const summary = ref('')
const groupId = ref<number | ''>('')
const openAIGroups = computed(() => (props.groups || []).filter(group => group.platform === 'openai' && group.status === 'active'))
function selectedGroupId(): number {
  const id = Number(groupId.value)
  if (!Number.isSafeInteger(id) || id < 1 || !openAIGroups.value.some(group => group.id === id)) {
    throw new Error(text('请先选择一个已启用的 OpenAI 分组。', 'Select an active OpenAI group first.'))
  }
  return id
}
watch([() => props.show, openAIGroups], ([show]) => {
  if (!show) { reset(); return }
  if (!openAIGroups.value.some(group => group.id === Number(groupId.value))) {
    groupId.value = openAIGroups.value.length === 1 ? openAIGroups.value[0]!.id : ''
  }
}, { immediate: true })
function reset() {
  pendingOAuth = null
  content.value = callback.value = refreshTokens.value = error.value = summary.value = ''
  fileContents.value = []
  runtime.value = newRuntime()
  groupId.value = ''
  mode.value = 'json'
  authLinkCopied.value = false
  oauth.resetState()
}
function close() { if (!busy.value) { reset(); emit('close') } }
async function copyAuthUrl() {
  try { await navigator.clipboard.writeText(oauth.authUrl.value); authLinkCopied.value = true }
  catch { error.value = text('复制失败，请选中上方授权链接手动复制。', 'Copy failed. Select and copy the authorization URL manually.') }
}
async function generateAuthUrl() {
  try {
    selectedGroupId()
    error.value = ''
    authLinkCopied.value = false
    callback.value = ''
    pendingOAuth = null
    oauth.harnessKind.value = ''
    await oauth.generateAuthUrl(runtime.value.proxy_id)
  } catch (err) { error.value = extractApiErrorMessage(err, 'Authorization failed') }
}
async function readFiles(event: Event) {
  const files = Array.from((event.target as HTMLInputElement).files || [])
  fileContents.value = []
  if (files.length > 100 || files.reduce((sum, file) => sum + file.size, 0) > 3 * 1024 * 1024) {
    error.value = text('每次最多 100 个文件，总大小不超过 3 MB。', 'At most 100 files and 3 MB per import.'); return
  }
  busy.value = true
  try { fileContents.value = await Promise.all(files.map(file => file.text())); error.value = '' }
  catch { error.value = text('读取文件失败。', 'Could not read files.') }
  finally { busy.value = false }
}
async function submit() {
  if (busy.value || oauth.loading.value) return
  busy.value = true
  error.value = summary.value = ''
  const importedAccountIDs = new Set<number>()
  const failures: string[] = []
  function acceptAccountIDs(ids: number[] | undefined) {
    if (!ids?.length || ids.some(id => !Number.isSafeInteger(id) || id < 1)) {
      throw new Error(text('账号导入未完成，请重试。', 'Account import did not complete. Please retry.'))
    }
    ids.forEach(id => importedAccountIDs.add(id))
  }
  try {
    const servingGroupId = selectedGroupId()
    oauth.harnessKind.value = ''
    if (mode.value === 'json') {
      const contents = [...fileContents.value, ...(content.value.trim() ? [content.value.trim()] : [])]
      if (!contents.length) throw new Error(text('请选择文件或粘贴授权 JSON。', 'Select files or paste authorization JSON.'))
      const result = await adminAPI.accounts.importCPAAuthFiles(contents, runtime.value, [servingGroupId])
      for (const item of result.items || []) {
        if (item.action !== 'failed') acceptAccountIDs(item.account_id ? [item.account_id] : undefined)
      }
      for (const item of result.errors || []) failures.push(`#${item.index}: ${item.message}`)
    } else if (mode.value === 'refresh') {
      const tokens = refreshTokens.value.split(String.fromCharCode(10)).map(value => value.trim()).filter(Boolean)
      if (!tokens.length || tokens.length > 100) throw new Error(text('请提供 1–100 个 Refresh Token。', 'Provide 1–100 refresh tokens.'))
      for (let index = 0; index < tokens.length; index++) {
        try {
          const tokenInfo = await oauth.validateRefreshToken(tokens[index]!, runtime.value.proxy_id)
          if (!tokenInfo) throw new Error(oauth.error.value || 'OAuth refresh failed')
          const credentials = oauth.buildCredentials(tokenInfo)
          credentials.refresh_token ||= tokens[index]
          const result = await adminAPI.accounts.importOpenAIOAuthToCPA(credentials, runtime.value, [servingGroupId])
          acceptAccountIDs(result.account_ids)
        } catch (err) { failures.push(`#${index + 1}: ${extractApiErrorMessage(err, 'Import failed')}`) }
      }
    } else {
      const url = new URL(callback.value.trim())
      const code = url.searchParams.get('code') || ''
      const state = url.searchParams.get('state') || ''
      if (!state || state !== oauth.oauthState.value || !code) throw new Error(text('回调地址与本次授权不匹配。', 'Callback does not match this authorization.'))
      const pendingKey = `${oauth.sessionId.value}:${code}:${state}`
      if (!pendingOAuth || pendingOAuth.key !== pendingKey) {
        const tokenInfo = await oauth.exchangeAuthCode(code, oauth.sessionId.value, state, runtime.value.proxy_id)
        if (!tokenInfo) throw new Error(oauth.error.value || 'OAuth exchange failed')
        pendingOAuth = { key: pendingKey, credentials: oauth.buildCredentials(tokenInfo) }
      }
      const result = await adminAPI.accounts.importOpenAIOAuthToCPA(pendingOAuth.credentials, runtime.value, [servingGroupId])
      acceptAccountIDs(result.account_ids)
    }
    if (importedAccountIDs.size > 0) {
      summary.value = runtime.value.disabled
        ? text(`已导入 ${importedAccountIDs.size} 个账号，按设置保持停用。`, `Imported ${importedAccountIDs.size} accounts, disabled as requested.`)
        : text(`已导入 ${importedAccountIDs.size} 个账号，可以使用。`, `Imported ${importedAccountIDs.size} accounts, ready to use.`)
      emit('created')
      if (!failures.length) { content.value = refreshTokens.value = callback.value = ''; fileContents.value = [] }
    } else if (!failures.length) {
      throw new Error(text('账号导入未完成，请重试。', 'Account import did not complete. Please retry.'))
    }
    error.value = failures.join(String.fromCharCode(10))
  } catch (err) { error.value = extractApiErrorMessage(err, text('导入失败。', 'Import failed.')) }
  finally { busy.value = false }
}
</script>
