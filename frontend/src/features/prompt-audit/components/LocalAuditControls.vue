<template>
  <section class="my-5 rounded-xl border border-gray-200 bg-white p-5 dark:border-dark-700 dark:bg-dark-900">
    <div class="flex items-center justify-between gap-4">
      <div><h3 class="font-semibold">本地审计 · 内容审计设置</h3><p class="mt-1 text-sm text-gray-500">命中通知、拦截提示和关键字与原生审计共用；当前选中的审核方式执行这些设置。</p></div>
      <button type="button" class="btn btn-primary" data-test="open-local-audit-controls" @click="open">内容审计设置</button>
    </div>
    <BaseDialog :show="visible" title="本地审计 · 内容审计设置" width="wide" @close="visible = false">
      <p v-if="loading" role="status">正在加载…</p>
      <p v-if="error" role="alert" class="text-red-600">{{ error }}</p>
      <div v-if="form" class="space-y-5">
        <div class="flex gap-2 border-b pb-3"><button class="btn btn-secondary" @click="tab = 'response'">命中通知</button><button class="btn btn-secondary" @click="tab = 'keywords'">关键字拦截</button></div>
        <div v-show="tab === 'response'" class="grid gap-4 sm:grid-cols-2">
          <label>拦截 HTTP 状态码<input v-model.number="form.block_status" type="number" min="400" max="599" class="input mt-2 w-full" /></label>
          <label>自定义拦截提示<input v-model="form.block_message" class="input mt-2 w-full" /></label>
          <label class="flex items-center gap-2"><input v-model="form.email_on_hit" type="checkbox" />命中后发送邮件</label>
          <label class="flex items-center gap-2"><input v-model="form.auto_ban_enabled" type="checkbox" />自动封禁用户</label>
          <label>封禁触发次数<input v-model.number="form.ban_threshold" type="number" min="1" class="input mt-2 w-full" /></label>
          <label>累计窗口（小时）<input v-model.number="form.violation_window_hours" type="number" min="1" class="input mt-2 w-full" /></label>
          <label class="flex items-center gap-2 sm:col-span-2"><input v-model="form.cyber_policy_exclude_from_ban_count" type="checkbox" />上游 cyber_policy 命中不计入封号次数</label>
          <p class="text-sm text-gray-500 sm:col-span-2">审核失败、待复核与已确认命中分别记录；同一请求的重复审核结果不会重复通知或累计违规。</p>
        </div>
        <div v-show="tab === 'keywords'" class="space-y-3">
          <label class="block">拦截方式<select v-model="form.keyword_blocking_mode" class="input mt-2 w-full"><option value="keyword_and_api">关键字与模型审核</option><option value="api_only">只使用模型审核</option><option value="keyword_only">只使用关键字</option></select></label>
          <label class="block">拦截关键字（每行一个）<textarea v-model="keywords" class="input mt-2 min-h-48 w-full" :disabled="form.keyword_blocking_mode === 'api_only'" /></label>
          <p class="text-sm text-gray-500">关键字按字面匹配。CTF／破甲全局规则有独立开关，不受此处的“只使用关键字”限制。</p>
        </div>
      </div>
      <template #footer><button class="btn btn-secondary" @click="visible = false">取消</button><button class="btn btn-primary" :disabled="loading || saving || !form" @click="save">{{ saving ? '保存中…' : '保存内容审计配置' }}</button></template>
    </BaseDialog>
  </section>
</template>
<script setup lang="ts">
import { ref } from 'vue'
import BaseDialog from '@/components/common/BaseDialog.vue'
import { adminAPI } from '@/api/admin'
import type { ContentModerationConfig } from '@/api/admin/riskControl'
const visible = ref(false), loading = ref(false), saving = ref(false), error = ref(''), keywords = ref('')
const tab = ref<'response' | 'keywords'>('response')
const form = ref<ContentModerationConfig | null>(null)
async function open() {
  visible.value = true; loading.value = true; error.value = ''; form.value = null
  try { form.value = await adminAPI.riskControl.getConfig(); keywords.value = form.value.blocked_keywords.join('\n') }
  catch { error.value = '配置加载失败，请重试' }
  finally { loading.value = false }
}
async function save() {
  if (!form.value) return
  const value = form.value
  saving.value = true; error.value = ''
  try {
    // Partial update: engine, credentials, audit scope and retention stay with
    // their owning controls even if another administrator updated them.
    await adminAPI.riskControl.updateConfig({ block_status: value.block_status, block_message: value.block_message,
      email_on_hit: value.email_on_hit, auto_ban_enabled: value.auto_ban_enabled, ban_threshold: value.ban_threshold,
      violation_window_hours: value.violation_window_hours, cyber_policy_exclude_from_ban_count: value.cyber_policy_exclude_from_ban_count,
      keyword_blocking_mode: value.keyword_blocking_mode, blocked_keywords: [...new Set(keywords.value.split('\n').map(s => s.trim()).filter(Boolean))] })
    visible.value = false
  } catch { error.value = '保存失败，请检查设置后重试' }
  finally { saving.value = false }
}
</script>
