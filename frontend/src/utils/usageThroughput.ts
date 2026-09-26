import { resolveUsageRequestType, type UsageRequestTypeLike } from './usageRequestType'

interface UsageThroughputLike extends UsageRequestTypeLike {
  output_tokens?: number | null
  duration_ms?: number | null
  first_token_ms?: number | null
  image_count?: number | null
  image_output_tokens?: number | null
}

// Presentation-only output throughput. Stored usage measurements are unchanged.
export function outputTokensPerSecond(row: UsageThroughputLike): number | null {
  const tokens = row.output_tokens
  const duration = row.duration_ms
  if (tokens == null || duration == null || !Number.isFinite(tokens) || !Number.isFinite(duration) || tokens < 0 || duration <= 0) return null
  if ((row.image_count ?? 0) > 0 || (row.image_output_tokens ?? 0) > 0) return null
  const kind = resolveUsageRequestType(row)
  const streamed = kind === 'stream' || kind === 'ws_v2' || ((kind === 'unknown' || kind === 'cyber' || kind === 'live') && !!row.stream)
  let windowMs = duration
  if (streamed && row.first_token_ms != null) {
    if (!Number.isFinite(row.first_token_ms) || row.first_token_ms < 0 || row.first_token_ms >= duration) return null
    windowMs -= row.first_token_ms
  }
  const rate = tokens * 1000 / windowMs
  return Number.isFinite(rate) ? Number(rate.toFixed(1)) : null
}

export function formatOutputTokensPerSecond(row: UsageThroughputLike): string {
  const value = outputTokensPerSecond(row)
  return value == null ? '-' : `${value.toFixed(1)} tok/s`
}
