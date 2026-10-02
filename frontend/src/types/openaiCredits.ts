/** Decimal values stay as strings; upstream spend-control units are not declared. */
export interface OpenAICredits {
  has_credits: boolean
  unlimited: boolean
  balance: string | null
  remaining?: string | null
}

export interface OpenAIIndividualLimit {
  source?: string | null
  limit?: string | null
  used?: string | null
  remaining?: string | null
  used_percent?: number | null
  remaining_percent?: number | null
  reset_at?: number | null
  reset_after_seconds?: number | null
}

export interface OpenAISpendControl {
  reached?: boolean | null
  individual_limit?: OpenAIIndividualLimit | null
}

export interface OpenAICreditsSnapshot {
  credits?: OpenAICredits | null
  spend_control?: OpenAISpendControl | null
  rate_limit_reached_type?: { type: string } | null
  fetched_at: number
}
