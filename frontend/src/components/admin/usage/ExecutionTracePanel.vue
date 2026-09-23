<template>
  <details class="card p-4" @toggle="onToggle">
    <summary class="cursor-pointer font-semibold">GPT-6J 调用详情</summary>
    <p class="mt-3 text-sm text-gray-500 dark:text-gray-400">
      显示本实例最近 6 小时的请求阶段、独立安全审计结论与 GPT 上游结果。工具由客户端执行；这里只标记客户端回传的工具结果，不保存提示词、工具输出或凭据。流式 HTTP 200 仍需结合失败步骤判断。
    </p>
    <div class="my-3 flex flex-wrap gap-2">
      <input
        v-model="requestID"
        class="input max-w-md"
        placeholder="按请求 ID 查找"
        aria-label="请求 ID"
        @keydown.enter="refresh"
      />
      <button class="btn btn-secondary" :disabled="loading" @click="refresh">刷新调用详情</button>
    </div>
    <p v-if="error" role="alert" class="text-red-600">{{ error }}</p>
    <p v-else-if="loading" class="text-sm text-gray-500">正在读取...</p>
    <p v-else-if="!groups.length" class="text-sm text-gray-500">
      暂无记录。这里只显示此版本上线后、本实例内存中保留的请求。
    </p>
    <details v-for="group in groups" :key="group.id" class="my-2 rounded-lg border p-3">
      <summary class="cursor-pointer break-all text-sm">
        {{ new Date(group.time).toLocaleString() }} · {{ group.id }} · {{ group.events.length }} 个步骤
      </summary>
      <ol class="mt-3 space-y-3 text-sm">
        <li v-for="(event, index) in group.events" :key="index" class="rounded bg-gray-50 p-3 dark:bg-dark-800">
          <strong>{{ labels[event.stage] || event.stage }}</strong>
          <span v-if="event.model"> · {{ event.model }}</span>
          <span v-if="event.actual_model"> · 实际返回 {{ event.actual_model }}</span>
          <span v-if="event.account_id"> · 账号 #{{ event.account_id }}</span>
          <p v-if="event.events_dropped">诊断容量受限，省略 {{ event.events_dropped }} 条中间记录；保留终态。</p>
          <p v-if="event.history_sample">历史窗口采样<span v-if="event.tool_results_seen">：发现 {{ event.tool_results_seen }} 条，省略 {{ event.tool_results_omitted || 0 }} 条较旧结果</span>，不代表本轮实际执行。</p>
          <p v-if="event.tool">工具结果类型：{{ event.tool }}</p>
          <p v-if="event.call_id" class="break-all">工具调用标识摘要：{{ event.call_id }}</p>
          <p v-if="event.response_id" class="break-all">响应 ID：{{ event.response_id }}</p>
          <p v-if="event.reason">结果代码：{{ event.reason }}</p>
          <p v-if="event.duration_ms">耗时 {{ event.duration_ms }} ms</p>
          <p v-if="event.status">HTTP {{ event.status }}</p>
        </li>
      </ol>
    </details>
  </details>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import apiClient from '@/api/client'

type TraceEvent = {
  events_dropped?: number
  history_sample?: boolean
  tool_results_seen?: number
  tool_results_omitted?: number
  time: number
  request_id: string
  response_id?: string
  account_id?: number
  stage: string
  model?: string
  actual_model?: string
  tool?: string
  call_id?: string
  reason?: string
  status?: number
  duration_ms?: number
}

const events = ref<TraceEvent[]>([])
const requestID = ref('')
const loading = ref(false)
const error = ref('')
const labels: Record<string, string> = {
  request: '收到 GPT-6J 请求',
  client_tool_result: '收到客户端工具结果',
  guard_result: '独立安全审计结论',
  gpt_handoff: '交由 GPT 上游处理',
  gpt_response: 'GPT 上游返回',
  request_failed: '请求失败',
  request_end: '本次 HTTP 请求结束',
}
const groups = computed(() => {
  const map = new Map<string, { id: string; time: number; events: TraceEvent[] }>()
  for (const event of events.value) {
    let group = map.get(event.request_id)
    if (!group) {
      group = { id: event.request_id, time: event.time, events: [] }
      map.set(event.request_id, group)
    }
    group.events.unshift(event)
  }
  return [...map.values()]
})

async function refresh() {
  loading.value = true
  error.value = ''
  try {
    const response = await apiClient.get<TraceEvent[]>('/admin/usage/execution-traces', {
      params: { request_id: requestID.value.trim(), limit: 200 },
    })
    events.value = response.data
  } catch {
    error.value = '读取调用详情失败，请重试。'
  } finally {
    loading.value = false
  }
}

function onToggle(event: Event) {
  if ((event.target as HTMLDetailsElement)?.open) refresh()
}
</script>
