import { describe, expect, it } from 'vitest'
import { sanitizeOpsErrorMessage } from '../errorMessage'

describe('sanitizeOpsErrorMessage', () => {
  it('hides the internal backend name in current and historical messages', () => {
    expect(sanitizeOpsErrorMessage('Pi does not support a tool type declared in this request'))
      .toBe('selected execution backend does not support a tool type declared in this request')
    expect(sanitizeOpsErrorMessage('{"error":{"type":"pi_request_error","message":"Pi runtime unavailable"}}'))
      .toBe('{"error":{"type":"invalid_request_error","message":"selected execution backend runtime unavailable"}}')
  })

  it('does not rewrite unrelated words containing pi', () => {
    expect(sanitizeOpsErrorMessage('api request failed')).toBe('api request failed')
  })
})
