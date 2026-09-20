import { useI18n } from 'vue-i18n'

const labels = {
  title: ['CPA 凭证设置', 'CPA credential settings'],
  scope: ['此处控制 CPA 的实际凭证。用户权限、分组和计费仍在 Sub2 管理；业务和审计共用桥接账号并发上限。', 'Manage actual CPA credentials here. Users, groups and billing stay in Sub2; business and audit requests share the bridge concurrency limit.'],
  importScope: ['下列设置会随凭证导入 CPA。分组、计费、业务并发和到期设置请在现有 CPA bridge 账号中管理。', 'These settings are imported into CPA with the credential. Manage groups, billing, concurrency and expiry on the existing CPA bridge account.'],
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
  unmanaged: ['此凭证已有外部配置的代理；保存时会按下方选择替换。', 'This credential has an externally configured proxy; saving replaces it with the selection below.'],
  failed: ['CPA 配置操作失败，请刷新核对', 'CPA settings operation failed; refresh to check'],
  bridgeProxy: ['此账号连接内部 CPA。上游出口代理请在账号页的“CPA 凭证设置”中修改。', 'This account connects to internal CPA. Set upstream egress in “CPA credential settings” on the accounts page.']
} as const

export function useCPAText() {
  const { locale } = useI18n()
  return (key: keyof typeof labels) => labels[key][(locale?.value || 'zh').startsWith('zh') ? 0 : 1]
}
