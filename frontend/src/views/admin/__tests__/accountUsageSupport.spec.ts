import { describe, expect, it } from 'vitest'

import type { Account } from '@/types'
import { accountSupportsBatchUsage } from '../accountUsageSupport'

const makeAccount = (overrides: Partial<Account>): Account => ({
  id: 1,
  name: 'account',
  platform: 'openai',
  type: 'apikey',
  status: 'active',
  schedulable: true,
  rate_multiplier: 1,
  created_at: '2026-08-25T00:00:00Z',
  updated_at: '2026-08-25T00:00:00Z',
  ...overrides
} as Account)

describe('accountSupportsBatchUsage', () => {
  it('loads usage for an explicitly configured OpenAI CPA quota bridge', () => {
    expect(accountSupportsBatchUsage(makeAccount({
      extra: { openai_quota_via_compatible_upstream: true }
    }))).toBe(true)
  })

  it('does not treat an ordinary OpenAI API key as a quota bridge', () => {
    expect(accountSupportsBatchUsage(makeAccount({}))).toBe(false)
  })

  it('keeps OpenAI OAuth usage loading enabled', () => {
    expect(accountSupportsBatchUsage(makeAccount({ type: 'oauth' }))).toBe(true)
  })
})
