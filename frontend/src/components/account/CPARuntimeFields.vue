<template>
  <div class="space-y-3" data-testid="cpa-runtime-fields">
    <label class="flex items-center gap-2 text-sm"><input type="checkbox" :checked="!modelValue.disabled" @change="change('disabled', !($event.target as HTMLInputElement).checked)" />{{ text('enabled') }}</label>
    <label class="block"><span class="input-label">{{ text('proxy') }}</span>
      <select class="input" :value="modelValue.proxy_id ?? ''" @change="change('proxy_id', ($event.target as HTMLSelectElement).value ? Number(($event.target as HTMLSelectElement).value) : null)">
        <option value="">{{ text('direct') }}</option>
        <option v-for="proxy in available" :key="proxy.id" :value="proxy.id">{{ proxy.name }}</option>
      </select>
      <span class="input-hint">{{ text('proxyHint') }}</span>
    </label>
    <div class="grid grid-cols-1 gap-3 sm:grid-cols-3">
      <label><span class="input-label">{{ text('priority') }}</span><input class="input" type="number" min="-10000" max="10000" step="1" :value="modelValue.priority" @input="change('priority', Number(($event.target as HTMLInputElement).value))" /></label>
      <label><span class="input-label">{{ text('weight') }}</span><input class="input" type="number" min="1" max="1000000" step="1" :value="modelValue.weight" @input="change('weight', Number(($event.target as HTMLInputElement).value))" /></label>
      <label><span class="input-label">{{ text('retry') }}</span><input class="input" type="number" min="0" max="10" step="1" :value="modelValue.request_retry" @input="change('request_retry', Number(($event.target as HTMLInputElement).value))" /></label>
    </div>
  </div>
</template>
<script setup lang="ts">
import { computed } from 'vue'
import type { CPACredentialUpdate } from '@/api/admin/accounts'
import type { Proxy } from '@/types'
import { useCPAText } from './cpaRuntimeText'
const props = defineProps<{modelValue: CPACredentialUpdate; proxies: Proxy[]}>()
const emit = defineEmits<{ 'update:modelValue': [value: CPACredentialUpdate] }>()
const text = useCPAText()
const available = computed(() => props.proxies.filter(p => p.status === 'active' && !p.expires_at && (!p.fallback_mode || p.fallback_mode === 'none')))
function change<K extends keyof CPACredentialUpdate>(key: K, value: CPACredentialUpdate[K]) { emit('update:modelValue', {...props.modelValue, [key]: value}) }
</script>
