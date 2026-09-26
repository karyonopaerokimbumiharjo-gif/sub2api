import type { UsageRequestTypeLike } from './usageRequestType'

interface UsageThroughputLike extends UsageRequestTypeLike {
  output_tokens?: number | null
  duration_ms?: number | null
  first_token_ms?: number | null
  image_count?: number | null
  image_output_tokens?: number | null
}

// Request-level average over the recorded total duration, including first-token wait.
// TTFT is a delivery timestamp, not a reliable generation-start timestamp: short or
// buffered streams can deliver all output in milliseconds and inflate a TTFT-subtracted
// rate. This is not model decoding speed; stored usage measurements are unchanged.
export function outputTokensPerSecond(row: UsageThroughputLike): number | null {
  const tokens = row.output_tokens
  const duration = row.duration_ms
  if (tokens == null || duration == null || !Number.isFinite(tokens) || !Number.isFinite(duration) || tokens < 0 || duration <= 0) return null
  if ((row.image_count ?? 0) > 0 || (row.image_output_tokens ?? 0) > 0) return null
  const rate = tokens * 1000 / duration
  return Number.isFinite(rate) ? Number(rate.toFixed(1)) : null
}

export function formatOutputTokensPerSecond(row: UsageThroughputLike): string {
  const value = outputTokensPerSecond(row)
  return value == null ? '-' : `${value.toFixed(1)} tok/s`
}
