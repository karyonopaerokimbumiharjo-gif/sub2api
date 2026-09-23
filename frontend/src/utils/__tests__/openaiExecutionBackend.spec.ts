import { describe, expect, it } from 'vitest'
import { isPiHarnessKind } from '../openaiExecutionBackend'

describe('isPiHarnessKind', () => {
  it('recognizes native and shared Pi accounts', () => {
    expect(isPiHarnessKind('pi')).toBe(true)
    expect(isPiHarnessKind('pi_shared')).toBe(true)
  })

  it('does not classify CPA or missing credentials as Pi', () => {
    expect(isPiHarnessKind('cpa')).toBe(false)
    expect(isPiHarnessKind(undefined)).toBe(false)
  })
})
