<template>
  <details class="my-6 rounded-xl border border-gray-200 p-4 dark:border-dark-700" @toggle="open">
    <summary class="cursor-pointer font-semibold">{{ zh ? '生物安全分级与科研核验档案' : 'Biology policy and verified research profiles' }}</summary>
    <p class="mt-3 text-sm text-gray-500">{{ zh ? '核验档案绑定用户和 Key，最长 90 天。只记录核验范围，不自动放行 B2，不解除 B3/B4 或本地明确绕过与已知破甲特征规则的拦截。修改范围需重新审批。' : 'Approvals bind a user and key for up to 90 days. They record verified scope without bypassing review, hard rules or tool grants. Scope changes require a new approval.' }}</p>
    <p v-if="error" role="alert" class="mt-3 text-red-600">{{ error }}</p>
    <table v-if="tiers.length" class="my-4 w-full text-left text-sm"><thead><tr><th>{{ zh ? '等级' : 'Tier' }}</th><th>{{ zh ? '定义' : 'Description' }}</th><th>{{ zh ? '处理' : 'Action' }}</th></tr></thead><tbody><tr v-for="tier in tiers" :key="tier.tier"><td class="p-2 font-semibold">{{ tier.tier }}</td><td class="p-2">{{ tier.description }}</td><td class="p-2">{{ tier.action }}</td></tr></tbody></table>
    <form class="grid gap-3 sm:grid-cols-2" @submit.prevent="approve">
      <label>{{ zh ? '用户 ID' : 'User ID' }}<input v-model.number="draft.user_id" type="number" min="1" required class="input mt-1 w-full" /></label>
      <label>{{ zh ? 'API Key ID' : 'API key ID' }}<input v-model.number="draft.api_key_id" type="number" min="1" required class="input mt-1 w-full" /></label>
      <label>{{ zh ? '已核验组织' : 'Verified organization' }}<input v-model="draft.organization" maxlength="512" required class="input mt-1 w-full" /></label>
      <label>{{ zh ? '研究用途' : 'Research purpose' }}<input v-model="draft.purpose" maxlength="512" required class="input mt-1 w-full" /></label>
      <label class="sm:col-span-2">{{ zh ? '核验记录编号或内部链接' : 'Verification record or internal reference' }}<input v-model="draft.verification_reference" maxlength="512" required class="input mt-1 w-full" /></label>
      <label v-for="field in scopeFields" :key="field.id">{{ zh ? field.zh : field.en }}<textarea v-model="scopes[field.id]" required class="input mt-1 w-full" :placeholder="zh ? '每行一个明确范围；不支持通配符，无工具时填写 none' : 'One explicit scope per line; no wildcards; none for no tools'" /></label>
      <label>{{ zh ? '失效时间' : 'Expires at' }}<input v-model="expires" type="datetime-local" required class="input mt-1 w-full" /></label>
      <button type="submit" class="btn btn-primary sm:col-span-2" :disabled="busy">{{ zh ? '确认核验并保存审批' : 'Confirm verification and approve' }}</button>
    </form>
    <div class="mt-5 flex items-center justify-between"><span class="font-medium">{{ zh ? '最近 100 份审批（保留历史）' : 'Latest 100 approvals, including history' }}</span><button class="btn btn-secondary btn-sm" :disabled="busy" @click="load">{{ zh ? '刷新' : 'Refresh' }}</button></div>
    <div v-for="profile in profiles" :key="profile.id" class="mt-3 rounded-lg border p-3 text-sm dark:border-dark-700">
      <p>#{{ profile.id }} · {{ profile.organization }} · User {{ profile.user_id }} / Key {{ profile.api_key_id }}</p>
      <p>{{ profile.purpose }} · {{ new Date(profile.expires_at).toLocaleString() }} · {{ profile.revoked_at ? (zh ? '已撤销' : 'Revoked') : Date.parse(profile.expires_at) <= Date.now() ? (zh ? '已过期' : 'Expired') : (zh ? '核验有效' : 'Verified') }}</p>
      <p>{{ profile.verification_reference }}</p><p>{{ profile.projects.join(' · ') }} / {{ profile.resources.join(' · ') }} / {{ profile.tools.join(' · ') }}</p>
      <p class="text-gray-500">{{ zh ? '审批人' : 'Reviewer' }} #{{ profile.approved_by }} · {{ new Date(profile.approved_at).toLocaleString() }}</p>
      <div v-if="!profile.revoked_at" class="mt-2 flex gap-2"><input v-model="reasons[profile.id]" class="input min-w-0 flex-1" :placeholder="zh ? '撤销原因' : 'Revocation reason'" /><button class="btn btn-secondary btn-sm" :disabled="busy || !reasons[profile.id]?.trim()" @click="revoke(profile.id)">{{ zh ? '撤销' : 'Revoke' }}</button></div>
      <p v-else>{{ profile.revoke_reason }}</p>
    </div>
  </details>
</template>
<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import api from '@/api/client'
const { locale } = useI18n(), zh = computed(() => locale.value.startsWith('zh'))
interface Profile { id: number; user_id: number; api_key_id: number; organization: string; purpose: string; verification_reference: string; projects: string[]; resources: string[]; tools: string[]; approved_by: number; approved_at: string; expires_at: string; revoked_at: string | null; revoke_reason: string }
const tiers = ref<{ tier: string; description: string; action: string }[]>([]), profiles = ref<Profile[]>([])
const busy = ref(false), error = ref(''), loaded = ref(false), expires = ref(''), reasons = reactive<Record<number, string>>({})
const draft = reactive({ user_id: 0, api_key_id: 0, organization: '', purpose: '', verification_reference: '' })
const scopes = reactive({ projects: '', resources: '', tools: '' })
const scopeFields = [{ id: 'projects' as const, zh: '项目范围', en: 'Projects' }, { id: 'resources' as const, zh: '资源范围', en: 'Resources' }, { id: 'tools' as const, zh: '工具范围', en: 'Tools' }]
const fail = (e: unknown) => { const r = e as { response?: { data?: { message?: string } } }; error.value = r.response?.data?.message || (zh.value ? '操作失败，请重试；未确认保存成功。' : 'Operation failed; success was not confirmed.') }
async function load() { busy.value = true; error.value = ''; try { const [a,b] = await Promise.all([api.get('/admin/prompt-audit/bio-catalog'), api.get('/admin/prompt-audit/research-profiles')]); tiers.value = a.data.tiers; profiles.value = b.data; loaded.value = true } catch(e) { fail(e) } finally { busy.value = false } }
function open(event: Event) { if ((event.target as HTMLDetailsElement).open && !loaded.value) void load() }
async function approve() { busy.value = true; error.value = ''; try { await api.post('/admin/prompt-audit/research-profiles', { ...draft, projects: scopes.projects.split('\n').filter(Boolean), resources: scopes.resources.split('\n').filter(Boolean), tools: scopes.tools.split('\n').filter(Boolean), expires_at: new Date(expires.value).toISOString() }); await load() } catch(e) { fail(e) } finally { busy.value = false } }
async function revoke(id: number) { busy.value = true; error.value = ''; try { await api.delete(`/admin/prompt-audit/research-profiles/${id}`, { data: { reason: reasons[id] } }); await load() } catch(e) { fail(e) } finally { busy.value = false } }
</script>
