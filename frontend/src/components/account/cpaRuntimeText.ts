import { useI18n } from 'vue-i18n'

const labels = {
  basispointsLabel: ['Excel / Basis Points：覆盖原始模型后端', 'Excel / Basis Points: override model backend'],
  basispointsHint: ['模型列表名称不变；勾选后仅使用本账号的 Excel 插件后端，不会回退到普通模型或其他账号。沿用 CPA OAuth 授权或重新授权后导入；账号须已具备 ChatGPT for Excel 权限，授权本身不会开通权限。插件暂为整段回放流式输出。', 'Model names stay unchanged. Uses only this account’s Excel backend, without fallback. Import or renew CPA OAuth first; existing ChatGPT for Excel access is required. OAuth does not grant entitlement. Streaming is currently buffered.'],
  title: ['CPA 凭证设置', 'CPA credential settings'],
  scope: ['此处管理该账号的实际授权和上游出口。分组、计费、并发及到期设置在同一账号行的“编辑”中管理。', 'Manage this account’s authorization and upstream egress here. Edit groups, billing, concurrency and expiry from the same account row.'],
  importScope: ['导入后会自动关联实际账号。分组、计费、并发和到期设置可在账号列表中编辑。', 'Imported credentials are linked to actual accounts. Edit groups, billing, concurrency and expiry in the account list.'],
  proxy: ['出口代理（CPA → 上游）', 'Egress proxy (CPA → upstream)'],
  proxyHint: ['代理来自 IP管理；支持无到期、无自动回退的代理。绑定后修改代理地址会同步到 CPA；删除或停用前需要先解绑。', 'Uses proxies from IP Management without automatic expiry/fallback. Address edits sync to CPA; unbind before disabling or deleting.'],
  direct: ['未指定代理（使用 CPA 默认出口）', 'No override (CPA default egress)'],
  priority: ['优先级（数值越大越优先）', 'Priority (higher is preferred)'],
  weight: ['调度权重', 'Scheduling weight'],
  retry: ['凭证重试次数', 'Credential retries'],
  enabled: ['启用凭证', 'Enable credential'],
  save: ['保存并核对 CPA', 'Save and verify CPA'],
  saved: ['CPA 配置已保存并回读核对', 'CPA settings saved and verified'],
  loading: ['正在读取 CPA…', 'Reading CPA…'],
  empty: ['暂无 CPA 凭证', 'No CPA credentials'],
  unmanaged: ['此授权已有配置的代理；未选择新代理时保留现有出口。', 'This credential has an existing proxy. It is preserved unless a new proxy is selected.'],
  failed: ['CPA 配置操作失败，请刷新核对', 'CPA settings operation failed; refresh to check'],
  bridgeProxy: ['此账号连接内部 CPA。上游出口代理请在账号页的“CPA 凭证设置”中修改。', 'This account connects to internal CPA. Set upstream egress in “CPA credential settings” on the accounts page.']
} as const

export function useCPAText() {
  const { locale } = useI18n()
  return (key: keyof typeof labels) => labels[key][(locale?.value || 'zh').startsWith('zh') ? 0 : 1]
}
