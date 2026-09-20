import type { Account } from '@/types'

export const accountSupportsBatchUsage = (account: Account): boolean => {
  if (account.platform === 'anthropic') {
    return account.type === 'oauth' || account.type === 'setup-token'
  }
  if (account.platform === 'gemini') return true
  if (account.platform === 'antigravity') return account.type === 'oauth'
  if (account.platform === 'openai') {
    return (
      account.type === 'oauth' ||
      (account.type === 'apikey' && account.extra?.openai_quota_via_compatible_upstream === true)
    )
  }
  if (account.platform === 'grok') return account.type === 'oauth'
  return false
}
