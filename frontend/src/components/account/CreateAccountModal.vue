<template>
  <BaseDialog :show="show" :title="basisPointsEnabled ? text('Excel / Basis Points 授权导入', 'Authorize Excel / Basis Points') : text('导入账号', 'Import account')" width="wide" @close="close">
    <div class="space-y-5">
      <p class="rounded-lg bg-emerald-50 p-3 text-sm text-emerald-800 dark:bg-emerald-900/20 dark:text-emerald-200" data-testid="cpa-only-notice">
        {{ text('授权文件可选择 CPA 或独立 Pi 后端；Refresh Token 导入 CPA。账号与分组以账号列表为准。', 'Authorization files can use CPA or the isolated Pi backend; refresh tokens go to CPA. The account list shows the actual accounts and groups.') }}
      </p>
      <div class="rounded-lg border border-primary-200 bg-primary-50 p-3 space-y-2 dark:border-primary-800 dark:bg-primary-900/20" data-testid="basispoints-import-options">
        <p class="text-xs" data-testid="basispoints-auth-method">{{ text('第三方插件复用 CPA / Codex OAuth 凭据，不是微软 Excel 内官方加载项的登录。授权不能增加账号原本没有的模型权限。', 'This third-party plugin reuses CPA / Codex OAuth credentials, not the official Excel add-in sign-in. Authorization does not grant additional model access.') }}</p>
        <label class="flex items-start gap-2 text-sm font-medium">
          <input v-model="basisPointsEnabled" type="checkbox" :disabled="busy || oauth.harnessKind.value === 'pi' || (mode === 'json' && jsonBackend === 'pi')" data-testid="basispoints-import-enabled" />
          {{ text('使用 Excel / Basis Points 插件覆盖原模型后端', 'Override the original backend with Excel / Basis Points') }}
        </label>
        <p class="text-sm text-gray-600 dark:text-gray-300">{{ text('需要 OpenAI 账号授权。插件复用 CPA 的 ChatGPT / Codex OAuth，并非免授权，也没有另一套插件专用 OAuth。', 'OpenAI account authorization is required. The plugin reuses CPA ChatGPT / Codex OAuth; it is not authorization-free and has no separate plugin OAuth.') }}</p>
        <p v-if="basisPointsEnabled" class="text-sm text-gray-600 dark:text-gray-300">{{ text('覆盖此账号已获授权的模型系列；Excel / Basis Points 标签仅供管理端识别，用户模型列表、请求模型名保持原名。上游未开放的模型或 Excel 权限不会因授权自动获得。', 'Covers the model families authorized for this account. Excel / Basis Points labels are admin-only; public model names and request IDs stay unchanged. OAuth does not grant missing upstream model or Excel access.') }}</p>
      </div>
      <div class="flex gap-2" role="tablist">
        <button v-for="tab in tabs" :key="tab.id" type="button" class="btn" :class="mode === tab.id ? 'btn-primary' : 'btn-secondary'" :disabled="busy" :data-testid="`cpa-tab-${tab.id}`" role="tab" :aria-selected="mode === tab.id" @click="mode = tab.id">{{ tab.label }}</button>
      </div>
      <div v-if="mode === 'oauth'" class="space-y-3">
        <div class="rounded-lg border border-gray-200 bg-gray-50 p-3 dark:border-dark-500 dark:bg-dark-700/40">
          <label class="block text-sm font-medium">
            {{ text('执行后端', 'Execution backend') }}
            <select v-model="oauth.harnessKind.value" class="input mt-2 w-full" data-testid="openai-harness-kind" :disabled="busy || basisPointsEnabled || oauth.loading.value || !!oauth.authUrl.value">
              <option value="">{{ text('CPA（默认）', 'CPA (default)') }}</option>
              <option value="pi">Pi（独立会话运行时）</option>
            </select>
          </label>
          <label v-if="oauth.harnessKind.value === 'pi'" class="mt-3 block text-sm font-medium">
            {{ text('Pi 归属用户 ID', 'Pi owner user ID') }}
            <input v-model.number="oauth.piOwnerUserId.value" type="number" min="1" step="1" class="input mt-2 w-full" data-testid="pi-owner-user-id" :disabled="busy || oauth.loading.value || !!oauth.authUrl.value" />
            <span class="mt-1 block text-xs font-normal text-gray-500">{{ text('填写凭据归属用户 ID；获所选分组授权的用户可以共享账号，彼此会话独立。', 'Credential owner ID. Authorized users in the selected group may share the account with isolated sessions.') }}</span>
          </label>
          <label v-if="oauth.harnessKind.value === 'pi'" class="mt-3 block text-sm font-medium">
            {{ text('业务分组', 'Business group') }}
            <select v-model.number="piGroupId" class="input mt-2 w-full" data-testid="pi-group-id" :disabled="busy || oauth.loading.value || !piOpenAIGroups.length">
              <option value="">{{ text('请选择已启用的 OpenAI 分组', 'Select an active OpenAI group') }}</option>
              <option v-for="group in piOpenAIGroups" :key="group.id" :value="group.id">{{ group.name }}</option>
            </select>
            <span class="mt-1 block text-xs font-normal text-gray-500">{{ text('可以选择现有 OpenAI 分组，与 CPA 共用；默认启用、参与调度，账号并发为 10。', 'Use an existing OpenAI group, including one shared with CPA. Accounts start enabled and schedulable with concurrency 10.') }}</span>
          </label>
          <p v-if="oauth.harnessKind.value === 'pi' && !piOpenAIGroups.length" data-testid="pi-no-groups" class="mt-2 text-sm text-amber-700 dark:text-amber-300">{{ text('没有可用的 OpenAI 分组，请先创建或启用分组。', 'No active OpenAI group is available. Create or enable one first.') }}</p>
        </div>
        <button type="button" class="btn btn-secondary" :disabled="busy || oauth.loading.value" data-testid="cpa-generate-auth" @click="generateAuthUrl">{{ basisPointsEnabled ? text('生成 OpenAI 授权（CPA / Codex）', 'Authorize OpenAI (CPA / Codex)') : text('生成 OpenAI 授权链接', 'Generate OpenAI authorization link') }}</button>
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
        <label class="block text-sm font-medium">
          {{ text('授权文件执行后端', 'Authorization file backend') }}
            <select v-model="jsonBackend" class="input mt-2 w-full" data-testid="pi-auth-backend" :disabled="busy || basisPointsEnabled">
            <option value="cpa">CPA</option>
            <option value="pi">Pi（独立会话运行时）</option>
          </select>
        </label>
        <template v-if="jsonBackend === 'pi'">
          <p class="text-sm text-amber-700 dark:text-amber-300" data-testid="pi-auth-rotation-warning">{{ text('只接受单个本机 Codex auth.json。导入时只读验证当前 Access Token，不会轮换 Refresh Token，也不会改写本机文件；这不能证明后续 Refresh Token 一定可续期。导入后本机与服务器共用 Refresh Token，后续自动刷新可能相互覆盖；建议使用独立授权。新账号默认启用，并发为 10。', 'Import one local Codex auth.json. Import validates the current access token without rotating the refresh token or changing the local file; this does not prove a future refresh will succeed. Local Codex and the server then share a refresh token, so later refreshes may conflict. A separate authorization is recommended. The new account starts enabled with concurrency 10.') }}</p>
          <label class="block text-sm font-medium">
            {{ text('Pi 归属用户 ID', 'Pi owner user ID') }}
            <input v-model.number="oauth.piOwnerUserId.value" type="number" min="1" step="1" class="input mt-2 w-full" data-testid="pi-auth-owner-user-id" :disabled="busy" />
          </label>
          <label class="block text-sm font-medium">
            {{ text('业务分组', 'Business group') }}
            <select v-model.number="piGroupId" class="input mt-2 w-full" data-testid="pi-auth-group-id" :disabled="busy || !piOpenAIGroups.length">
              <option value="">{{ text('请选择已启用的 OpenAI 分组', 'Select an active OpenAI group') }}</option>
              <option v-for="group in piOpenAIGroups" :key="group.id" :value="group.id">{{ group.name }}</option>
            </select>
            <span class="mt-1 block text-xs font-normal text-gray-500">{{ text('可以选择已有 CPA 账号的 OpenAI 分组；默认启用、参与调度，账号并发为 10。', 'Existing CPA groups are supported. Accounts start enabled and schedulable with concurrency 10.') }}</span>
          </label>
        </template>
        <p v-else class="text-sm text-gray-500">{{ text('支持 Codex auth.json，以及 CPA 原生 OpenAI、Claude、Gemini、Antigravity OAuth 文件。无法识别的文件会显示错误。', 'Supports Codex auth.json and native CPA OAuth files for OpenAI, Claude, Gemini and Antigravity. Unsupported files return an error.') }}</p>
        <input type="file" accept=".json,application/json" :multiple="jsonBackend === 'cpa'" :disabled="busy" data-testid="cpa-files" @change="readFiles" />
        <label class="block text-sm">
          {{ jsonBackend === 'pi' ? text('或粘贴单个 auth.json', 'Or paste one auth.json') : text('或粘贴授权 JSON（支持数组）', 'Or paste authorization JSON (arrays supported)') }}
          <textarea v-model="content" class="input mt-2 w-full font-mono" rows="7" autocomplete="off" spellcheck="false" data-testid="cpa-json" />
        </label>
        <p v-if="fileContents.length" class="text-sm text-gray-500">{{ text(`已读取 ${fileContents.length} 个文件`, `${fileContents.length} files loaded`) }}</p>
      </div>
      <fieldset v-if="(mode === 'oauth' && oauth.harnessKind.value !== 'pi') || mode === 'refresh' || (mode === 'json' && jsonBackend === 'cpa')" :disabled="busy" class="space-y-3 border-t pt-4">
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
        <button type="button" class="btn btn-primary" :disabled="busy || oauth.loading.value" data-testid="cpa-import-submit" @click="submit">{{ busy ? text('正在导入…', 'Importing…') : text('导入账号', 'Import account') }}</button>
      </div>
    </template>
  </BaseDialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import { apiClient } from '@/api/client'
import {syncCPAAccounts} from '@/api/admin/accounts'
import CPARuntimeFields from './CPARuntimeFields.vue'
import { useCPAText } from './cpaRuntimeText'
import type { CPACredentialUpdate } from '@/api/admin/accounts'
import { adminAPI } from '@/api/admin'
import { useOpenAIOAuth } from '@/composables/useOpenAIOAuth'
import { extractApiErrorMessage } from '@/utils/apiError'
import type { AdminGroup, Proxy } from '@/types'

const props = defineProps<{ show: boolean; initialBackend?: 'cpa' | 'basispoints'; proxies?: Proxy[]; groups?: AdminGroup[]; currentUserId?: number }>()
const emit = defineEmits<{ (event: 'close'): void; (event: 'created'): void }>()
const { t, locale } = useI18n()
const text = (zh: string, en: string) => locale.value.startsWith('zh') ? zh : en
const oauth = useOpenAIOAuth()
const cpaText = useCPAText()
const newRuntime = (): CPACredentialUpdate => ({name:'new-credential',disabled:false,proxy_id:null,priority:0,weight:1,request_retry:0})
const runtime = ref(newRuntime())
const mode = ref<'oauth' | 'refresh' | 'json'>('json')
const basisPointsEnabled = ref(false)
const authLinkCopied = ref(false)
const jsonBackend = ref<'cpa' | 'pi'>('cpa')
const tabs = computed(() => [
  { id: 'json' as const, label: text('授权文件', 'Authorization files') },
  { id: 'oauth' as const, label: 'OpenAI OAuth' },
  { id: 'refresh' as const, label: 'Refresh Token' }
])
const content = ref('')
const callback = ref('')
// OAuth codes are single-use. Retain exchanged credentials only in memory until import.
let pendingOAuth: { key: string; credentials: ReturnType<typeof oauth.buildCredentials> } | null = null
watch(callback, () => { pendingOAuth = null })
const refreshTokens = ref('')
const fileContents = ref<string[]>([])
const busy = ref(false)
const error = ref('')
const summary = ref('')
const routingWarning = ref(false)
const bridgeRefresh = ref(0)
const piGroupId = ref<number | ''>('')
const piOpenAIGroups = computed(() => (props.groups || []).filter((group) => group.platform === 'openai' && group.status === 'active'))

function selectedPiGroupId(): number | null {
  const id = Number(piGroupId.value)
  return Number.isSafeInteger(id) && id > 0 && piOpenAIGroups.value.some((group) => group.id === id) ? id : null
}

watch(() => props.show, (show) => {
  if (!show) reset()
  else {
    basisPointsEnabled.value = props.initialBackend === 'basispoints'
    mode.value = basisPointsEnabled.value ? 'oauth' : 'json'
    if (!oauth.piOwnerUserId.value && Number.isSafeInteger(props.currentUserId) && (props.currentUserId || 0) > 0) oauth.piOwnerUserId.value = props.currentUserId
  }
}, { immediate: true })
function reset() {
  pendingOAuth = null
  content.value = callback.value = refreshTokens.value = error.value = summary.value = ''
  fileContents.value = []
  routingWarning.value = false
  runtime.value = newRuntime()
  piGroupId.value = ''
  jsonBackend.value = 'cpa'
  basisPointsEnabled.value = false
  authLinkCopied.value = false
  oauth.resetState()
}
function close() { if (!busy.value) { reset(); emit('close') } }
async function copyAuthUrl() {
  try {
    await navigator.clipboard.writeText(oauth.authUrl.value)
    authLinkCopied.value = true
  } catch {
    error.value = text('复制失败，请选中上方授权链接手动复制。', 'Copy failed. Select and copy the authorization URL manually.')
  }
}
async function generateAuthUrl() {
  if (oauth.harnessKind.value === 'pi' && (!Number.isInteger(oauth.piOwnerUserId.value) || !oauth.piOwnerUserId.value || oauth.piOwnerUserId.value < 1)) {
    error.value = text('Pi 归属用户 ID 必须是正整数。', 'Pi owner user ID must be a positive integer.')
    return
  }
  if (oauth.harnessKind.value === 'pi' && selectedPiGroupId() === null) {
    error.value = text('请先选择一个已启用的 OpenAI 分组。', 'Select an active OpenAI group first.')
    return
  }
  error.value = ''
  authLinkCopied.value = false
  callback.value = ''
  pendingOAuth = null
  await oauth.generateAuthUrl(oauth.harnessKind.value === 'pi' ? null : runtime.value.proxy_id)
}
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
  const importedAuthNames: string[] = []
  const failures: string[] = []
  try {
    if (mode.value === 'json') {
      const contents = [...fileContents.value, ...(content.value.trim() ? [content.value.trim()] : [])]
      if (!contents.length) throw new Error(text('请选择文件或粘贴授权 JSON。', 'Select files or paste authorization JSON.'))
      if (jsonBackend.value === 'pi') {
        const groupId = selectedPiGroupId()
        if (contents.length !== 1) throw new Error(text('Pi 每次只能导入一份 auth.json。', 'Pi accepts exactly one auth.json per import.'))
        if (!Number.isSafeInteger(oauth.piOwnerUserId.value) || !oauth.piOwnerUserId.value || oauth.piOwnerUserId.value < 1) throw new Error(text('Pi 归属用户 ID 必须是正整数。', 'Pi owner user ID must be a positive integer.'))
        if (groupId === null) throw new Error(text('请先选择一个已启用的 OpenAI 分组。', 'Select an active OpenAI group first.'))
        await apiClient.post('/admin/openai/import-pi-auth', { content: contents[0], pi_owner_user_id: oauth.piOwnerUserId.value, group_ids: [groupId] })
        summary.value = text('账号已导入所选分组，已启用并参与调度，并发为 10。', 'Account imported into the selected group, enabled and schedulable with concurrency 10.')
        content.value = ''
        fileContents.value = []
        emit('created')
        return
      }
      const result = await adminAPI.accounts.importCPAAuthFiles(contents, runtime.value)
      imported = result.created + result.updated
      for(const item of result.items || []) {const name=(item as {auth_name?:string}).auth_name;if(name)importedAuthNames.push(name)}
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
          importedAuthNames.push(result.auth_name)
          imported++
        } catch (err) { failures.push(`#${index + 1}: ${extractApiErrorMessage(err, 'Import failed')}`) }
      }
    } else {
      const url = new URL(callback.value.trim())
      const code = url.searchParams.get('code') || ''
      const state = url.searchParams.get('state') || ''
      if (!state || state !== oauth.oauthState.value || !code) throw new Error(text('回调地址与本次授权不匹配。', 'Callback does not match this authorization.'))
      if (oauth.harnessKind.value === 'pi') {
        const groupId = selectedPiGroupId()
        if (groupId === null) throw new Error(text('请先选择一个已启用的 OpenAI 分组。', 'Select an active OpenAI group first.'))
        await apiClient.post('/admin/openai/create-pi-account', {session_id: oauth.sessionId.value, code, state, pi_owner_user_id: oauth.piOwnerUserId.value, group_ids: [groupId]})
        summary.value = text('账号已导入所选分组，已启用并参与调度，并发为 10。', 'Account imported into the selected group, enabled and schedulable with concurrency 10.')
        callback.value = ''
        emit('created')
        return
      }
      const pendingKey = `${oauth.sessionId.value}:${code}:${state}`
      if (!pendingOAuth || pendingOAuth.key !== pendingKey) {
        const tokenInfo = await oauth.exchangeAuthCode(code, oauth.sessionId.value, state, runtime.value.proxy_id)
        if (!tokenInfo) throw new Error(oauth.error.value || 'OAuth exchange failed')
        pendingOAuth = {key: pendingKey, credentials: oauth.buildCredentials(tokenInfo)}
      }
      const result = await adminAPI.accounts.importOpenAIOAuthToCPA(pendingOAuth.credentials, runtime.value)
      pendingOAuth = null
      routingWarning.value = result.bridge_account_id === 0
      importedAuthNames.push(result.auth_name)
      imported = 1
    }
    summary.value = imported > 0 ? text(`已处理 ${imported} 份授权，实际账号数以列表去重结果为准。`, `Processed ${imported} credentials; the account list deduplicates identities.`) : ''
    error.value = failures.join('\n')
    if (imported > 0) {
      try {
        const synced = await syncCPAAccounts(importedAuthNames)
        if (basisPointsEnabled.value) {
          if (!synced.account_ids?.length) throw new Error(text('没有返回可绑定的账号 ID，未启用插件覆盖。', 'No exact account IDs were returned; plugin override was not enabled.'))
          for (const id of synced.account_ids) {
            const account = await adminAPI.accounts.getById(id)
            if (account.platform !== 'openai' || !account.extra?.cpa_auth_id) throw new Error(text('导入账号未绑定 OpenAI CPA 授权，未启用插件覆盖。', 'Imported account is not bound to OpenAI CPA authorization; plugin override was not enabled.'))
            await adminAPI.accounts.update(id, {extra: {...account.extra, openai_basispoints_enabled: true}})
          }
          summary.value += text(' 已启用 Excel / Basis Points 覆盖，用户模型名保持不变。新账号默认不参与调度，请在账号编辑中配置分组并启用。', ' Excel / Basis Points override is enabled; public model names are unchanged. New accounts remain unscheduled until a group is configured and the account is enabled in account settings.')
        }
        if (synced.created + synced.updated > 0) routingWarning.value = false
      } catch (err) {
        routingWarning.value = true
        failures.push(text('授权已导入，但业务账号同步或插件绑定失败，请修复后重试：', 'Credentials imported, but account synchronization or plugin binding failed. Fix and retry: ') + extractApiErrorMessage(err, 'Sync failed'))
        error.value = failures.join('\n')
      }
      bridgeRefresh.value++
      emit('created')
      if (!failures.length) { content.value = refreshTokens.value = callback.value = ''; fileContents.value = [] }
    }
  } catch (err) { error.value = extractApiErrorMessage(err, text('导入失败。', 'Import failed.')) }
  finally { busy.value = false }
}
</script>
