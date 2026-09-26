import { describe, expect, it } from 'vitest'
import { formatOutputTokensPerSecond, outputTokensPerSecond } from '../usageThroughput'

describe('output TPS', () => {
  const stream = { output_tokens: 100, duration_ms: 2500, first_token_ms: 500, stream: true }
  it('excludes first-token waiting from streaming output speed', () => {
    expect(outputTokensPerSecond(stream)).toBe(50)
    expect(formatOutputTokensPerSecond(stream)).toBe('50.0 tok/s')
  })
  it('uses the same calculation for WebSocket streaming', () => {
    expect(outputTokensPerSecond({ ...stream, stream: false, request_type: 'ws_v2' })).toBe(50)
  })
  it('uses total duration for non-streaming requests', () => {
    expect(outputTokensPerSecond({ ...stream, stream: false })).toBe(40)
  })
  it('calculates historical records without first-token timing from duration', () => {
    expect(outputTokensPerSecond({ ...stream, first_token_ms: null })).toBe(40)
  })
  it('rounds presentation to one decimal without changing stored measurements', () => {
    expect(outputTokensPerSecond({ output_tokens: 101, duration_ms: 345 })).toBe(292.8)
  })
  it('distinguishes measured zero output from missing data', () => {
    expect(outputTokensPerSecond({ ...stream, output_tokens: 0 })).toBe(0)
    expect(outputTokensPerSecond({ ...stream, output_tokens: null })).toBeNull()
  })
  it.each([
    { duration_ms: null }, { duration_ms: 0 }, { duration_ms: -1 },
    { duration_ms: Number.NaN }, { output_tokens: Number.POSITIVE_INFINITY },
    { output_tokens: -1 }, { first_token_ms: 2500 }, { first_token_ms: 3000 },
    { first_token_ms: -1 }, { first_token_ms: Number.NaN },
    { image_count: 1 }, { image_output_tokens: 10 },
  ])('does not invent speed for invalid or image measurements: %j', (overrides) => {
    expect(outputTokensPerSecond({ ...stream, ...overrides })).toBeNull()
    expect(formatOutputTokensPerSecond({ ...stream, ...overrides })).toBe('-')
  })
})
