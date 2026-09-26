import { describe, expect, it } from 'vitest'
import { formatOutputTokensPerSecond, outputTokensPerSecond } from '../usageThroughput'

describe('average output TPS', () => {
  it('does not inflate a short buffered response using its final eight milliseconds', () => {
    const row = { output_tokens: 6, duration_ms: 1846, first_token_ms: 1838, stream: true }
    expect(outputTokensPerSecond(row)).toBe(3.3)
    expect(formatOutputTokensPerSecond(row)).toBe('3.3 tok/s')
  })
  const stream = { output_tokens: 100, duration_ms: 2500, first_token_ms: 500, stream: true }
  it('includes first-token waiting in the request-level streaming average', () => {
    expect(outputTokensPerSecond(stream)).toBe(40)
    expect(formatOutputTokensPerSecond(stream)).toBe('40.0 tok/s')
  })
  it('uses the same calculation for WebSocket streaming', () => {
    expect(outputTokensPerSecond({ ...stream, stream: false, request_type: 'ws_v2' })).toBe(40)
  })
  it('uses total duration for non-streaming requests', () => {
    expect(outputTokensPerSecond({ ...stream, stream: false })).toBe(40)
  })
  it('calculates historical records without first-token timing from duration', () => {
    expect(outputTokensPerSecond({ ...stream, first_token_ms: null })).toBe(40)
  })
  it.each([0, 2499, 2500, 3000, -1, Number.NaN, Number.POSITIVE_INFINITY])(
    'does not use first-token timing (%s) as a generation window', (first_token_ms) => {
      expect(outputTokensPerSecond({ ...stream, first_token_ms })).toBe(40)
    },
  )
  it('handles the seven-millisecond production delivery burst without a speed cap', () => {
    const row = Object.freeze({ output_tokens: 67, duration_ms: 3922, first_token_ms: 3915, stream: true })
    expect(outputTokensPerSecond(row)).toBe(17.1)
    expect(row).toEqual({ output_tokens: 67, duration_ms: 3922, first_token_ms: 3915, stream: true })
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
    { output_tokens: -1 }, { duration_ms: Number.POSITIVE_INFINITY },
    { image_count: 1 }, { image_output_tokens: 10 },
  ])('does not invent speed for invalid or image measurements: %j', (overrides) => {
    expect(outputTokensPerSecond({ ...stream, ...overrides })).toBeNull()
    expect(formatOutputTokensPerSecond({ ...stream, ...overrides })).toBe('-')
  })
})
