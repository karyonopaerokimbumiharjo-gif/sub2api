<template>
  <div class="rounded-lg border border-violet-200 bg-violet-50/60 p-4 dark:border-violet-900/60 dark:bg-violet-950/20">
    <label class="flex items-start justify-between gap-4">
      <span>
        <span class="block font-semibold">{{ zh ? 'J 协作' : 'J cooperation' }}</span>
        <span class="mt-1 block text-xs leading-5 text-gray-600 dark:text-gray-300">
          {{ zh ? '保存在此 API Key。开启后可调用基础模型对应的 -j 模型；普通模型调用保持原方式。安全审计独立配置。' : 'Saved for this API key. Enables derived -j models; ordinary model calls remain available. Safety is configured separately.' }}
        </span>
      </span>
      <input data-testid="j-key-toggle" type="checkbox" :checked="enabled" :disabled="busy || !apiKeyId" @change="changeToggle" />
    </label>
    <p v-if="error" role="alert" class="mt-2 text-sm text-red-600">{{ error }}</p>
    <label v-if="enabled" class="mt-3 block text-sm">
      {{ zh ? '基础模型' : 'Base model' }}
      <select class="input mt-1 w-full" :value="baseModel" :disabled="!models.length" @change="$emit('update:baseModel', ($event.target as HTMLSelectElement).value)">
        <option v-if="!models.length" value="">{{ zh ? '请先加载此 Key 的模型目录' : 'Load this key’s model catalogue first' }}</option>
        <option v-for="model in models" :key="model" :value="model">{{ model }}</option>
      </select>
    </label>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import apiClient from '@/api/client'
const props = defineProps<{ apiKeyId?: number; enabled: boolean; baseModel: string; models: string[] }>()
const emit = defineEmits<{ 'update:enabled': [boolean]; 'update:baseModel': [string]; changed: [] }>()
const { locale } = useI18n()
const zh = computed(() => locale.value.startsWith('zh'))
const busy = ref(false), error = ref('')
let generation = 0
watch(() => props.apiKeyId, async (id) => {
  const current = ++generation
  emit('update:enabled', false)
  error.value = ''
  if (!id) return
  busy.value = true
  try {
    const { data } = await apiClient.get<{ enabled: boolean }>(`/keys/${id}/j`)
    if (current === generation) { emit('update:enabled', data.enabled); if (data.enabled) emit('changed') }
  } catch {
    if (current === generation) error.value = zh.value ? '读取 J 设置失败，请重新打开。' : 'Failed to load J settings. Reopen this dialog.'
  } finally { if (current === generation) busy.value = false }
}, { immediate: true })
watch(() => props.models, (models) => {
  if (!models.includes(props.baseModel)) emit('update:baseModel', models[0] || '')
}, { immediate: true })
function changeToggle(event: Event) {
 const target = event.target as HTMLInputElement
 const requested = target.checked
 target.checked = props.enabled
 void save(requested)
}
async function save(enabled: boolean) {
  const id = props.apiKeyId, current = generation
  if (!id || busy.value) return
  busy.value = true; error.value = ''
  try {
    const { data } = await apiClient.put<{ enabled: boolean }>(`/keys/${id}/j`, { enabled })
    if (current === generation) { emit('update:enabled', data.enabled); emit('changed') }
  } catch {
    if (current === generation) error.value = zh.value ? '保存失败，原设置未改变。' : 'Save failed. The previous setting is unchanged.'
  } finally { if (current === generation) busy.value = false }
}
</script>
