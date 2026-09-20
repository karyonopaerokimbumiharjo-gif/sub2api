<template>
  <section class="rounded-xl border border-teal-200 bg-teal-50/50 p-4 dark:border-teal-800 dark:bg-teal-950/20" data-testid="cpa-bridge-setup">
    <div class="mb-3 flex flex-wrap items-center justify-between gap-2">
      <h3 class="font-semibold">{{ text('CPA 账号与业务桥接', 'CPA accounts and business bridge') }}</h3>
      <button type="button" class="btn btn-secondary" :disabled="loading || saving || disabled" @click="load">{{ text('刷新账号', 'Refresh accounts') }}</button>
    </div>
    <p class="mb-3 text-sm text-gray-600 dark:text-gray-300">{{ text('桥接负责本站分组和计费；下方选择用于额度展示，实际 API 由 CPA 启用账号池调度，不会限制为单个账号。', 'The bridge handles site groups and billing. Select the quota-display identity below; API requests are scheduled across enabled CPA credentials, not pinned to one account.') }}</p>
    <p v-if="options?.bridge" class="mb-3 text-sm font-medium" data-testid="cpa-current-bridge">{{ text('当前桥接', 'Current bridge') }} #{{ options.bridge.account_id }} · {{ options.bridge.email }}</p>
    <p v-if="loading" class="text-sm">{{ text('正在读取 CPA 授权池…', 'Loading CPA credentials…') }}</p>
    <template v-else-if="options">
      <fieldset :disabled="disabled || saving">
        <legend class="mb-2 text-sm font-semibold">{{ text('选择额度展示账号', 'Select quota-display account') }}</legend>
        <div v-if="options.candidates.length" class="max-h-64 space-y-2 overflow-y-auto">
          <label v-for="item in options.candidates" :key="item.name" class="flex items-start gap-3 rounded-lg border bg-white p-3 dark:bg-gray-900" :class="item.can_bridge ? 'cursor-pointer border-gray-200 dark:border-gray-700' : 'border-gray-100 opacity-65 dark:border-gray-800'">
            <input v-model="authName" type="radio" name="bridge-auth" :value="item.name" :disabled="!item.can_bridge" class="mt-1" />
            <span class="min-w-0 flex-1">
              <span class="block break-all font-medium">{{ item.email || item.name }}</span>
              <span class="block text-xs text-gray-500">{{ item.provider }} · {{ item.status }} · {{ item.can_bridge ? text('可桥接', 'Available') : item.reason }}</span>
              <span class="block break-all text-xs text-gray-400">{{ item.name }}</span>
            </span>
          </label>
        </div>
        <p v-else class="rounded-lg bg-white p-3 text-sm dark:bg-gray-900">{{ text('授权池为空，请先在下方上传 auth.json 或完成 OAuth 授权。', 'No credentials yet. Import auth.json or authorize with OAuth below.') }}</p>
        <p class="mb-2 mt-4 text-sm font-semibold">{{ text('允许调用的业务分组（至少一个）', 'Business groups (select at least one)') }}</p>
        <div class="flex flex-wrap gap-3">
          <label v-for="group in options.groups" :key="group.id" class="flex items-center gap-2 rounded-lg border border-gray-200 bg-white px-3 py-2 dark:border-gray-700 dark:bg-gray-900">
            <input v-model="groupIDs" type="checkbox" :value="group.id" name="bridge-group" /> {{ group.name }}
          </label>
          <p v-if="!options.groups.length" class="text-sm text-amber-700">{{ text('没有启用的 OpenAI 分组，请先到分组管理创建。', 'Create an active OpenAI group in group management first.') }}</p>
        </div>
      </fieldset>
      <p v-if="!groupIDs.length" class="mt-3 text-sm text-amber-700">{{ text('未绑定分组时，站内测试可能成功，但外部 API 没有可调度账号。', 'Without a group, an admin test may pass but external API requests have no schedulable account.') }}</p>
      <button type="button" class="btn btn-primary mt-4" data-testid="cpa-save-bridge" :disabled="!canSave || saving || disabled" @click="save">{{ saving ? text('保存中…', 'Saving…') : options.bridge ? text('保存桥接绑定', 'Save bridge binding') : text('创建桥接并绑定分组', 'Create bridge and bind groups') }}</button>
    </template>
    <p v-if="error" role="alert" class="mt-3 text-sm text-red-600">{{ error }}</p>
    <p v-if="success" role="status" class="mt-3 text-sm text-emerald-700">{{ success }}</p>
  </section>
</template>
<script setup lang="ts">
import {computed,ref,watch} from 'vue'
import {useI18n} from 'vue-i18n'
import {getCPABridgeOptions,ensureCPAQuotaBridge,type CPABridgeOptions} from '@/api/admin/accounts'
import {extractApiErrorMessage} from '@/utils/apiError'
const props=defineProps<{show:boolean;disabled?:boolean;refreshKey?:number}>()
const emit=defineEmits<{updated:[]}>()
const {locale}=useI18n()
const text=(zh:string,en:string)=>locale.value.startsWith('zh')?zh:en
const options=ref<CPABridgeOptions|null>(null),authName=ref(''),groupIDs=ref<number[]>([])
const loading=ref(false),saving=ref(false),error=ref(''),success=ref('')
const canSave=computed(()=>options.value?.candidates.some(c=>c.name===authName.value&&c.can_bridge)&&groupIDs.value.length>0)
let revision=0
async function load() {
 const current=++revision;loading.value=true;error.value='';success.value=''
 try {
  const result=await getCPABridgeOptions();if(current!==revision)return
  options.value=result
  authName.value=result.bridge?.auth_name||''
  groupIDs.value=(result.bridge?.group_ids||[]).filter(id=>result.groups.some(g=>g.id===id))
 } catch(e){if(current===revision){options.value=null;error.value=extractApiErrorMessage(e,text('读取账号失败，请重试。','Could not load accounts.'))}}
 finally{if(current===revision)loading.value=false}
}
watch(()=>[props.show,props.refreshKey],()=>{if(props.show)void load();else{revision++;options.value=null;authName.value='';groupIDs.value=[]}}, {immediate:true})
async function save(){
 if(!canSave.value||saving.value||props.disabled)return
 saving.value=true;error.value='';success.value=''
 try{
  const r=await ensureCPAQuotaBridge(authName.value,groupIDs.value)
  await load()
  success.value=text(`桥接 #${r.account_id} 已保存，额度展示账号：${r.email}。已绑定所选分组，原计费设置保持不变。`,`Bridge #${r.account_id} saved. Quota identity: ${r.email}. Selected groups are bound; billing settings are unchanged.`)
  emit('updated')
 }catch(e){error.value=extractApiErrorMessage(e,text('保存失败，请刷新核对。','Save failed. Refresh to check.'))}
 finally{saving.value=false}
}
</script>
