package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"
)

const openAICreditsSchedulingMaxAge = 5 * time.Minute

// Accept the official decimal strings and numeric JSON from compatible bridges
// without rounding either through float64. Output is always a decimal string.
func decodeOpenAIQuotaAmount(raw json.RawMessage) (*string, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		var number json.Number
		if err := json.Unmarshal(raw, &number); err != nil {
			return nil, fmt.Errorf("invalid upstream quota amount")
		}
		value = number.String()
	}
	return &value, nil
}

func (credits *OpenAICredits) UnmarshalJSON(data []byte) error {
	type plain OpenAICredits
	wire := struct {
		*plain
		Balance   json.RawMessage `json:"balance"`
		Remaining json.RawMessage `json:"remaining"`
	}{plain: (*plain)(credits)}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	var err error
	if credits.Balance, err = decodeOpenAIQuotaAmount(wire.Balance); err != nil {
		return err
	}
	credits.Remaining, err = decodeOpenAIQuotaAmount(wire.Remaining)
	return err
}

func (limit *OpenAISpendControlLimit) UnmarshalJSON(data []byte) error {
	type plain OpenAISpendControlLimit
	wire := struct {
		*plain
		Limit     json.RawMessage `json:"limit"`
		Used      json.RawMessage `json:"used"`
		Remaining json.RawMessage `json:"remaining"`
	}{plain: (*plain)(limit)}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	for _, field := range []struct {
		raw json.RawMessage
		dst **string
	}{{wire.Limit, &limit.Limit}, {wire.Used, &limit.Used}, {wire.Remaining, &limit.Remaining}} {
		value, err := decodeOpenAIQuotaAmount(field.raw)
		if err != nil {
			return err
		}
		*field.dst = value
	}
	return nil
}

func codexCreditsSnapshotFromUsage(usage *OpenAIQuotaUsage) openAICreditsSnapshot {
	return openAICreditsSnapshot{
		Credits: usage.Credits, SpendControl: usage.SpendControl,
		RateLimit: usage.RateLimit, RateLimitReachedType: usage.RateLimitReachedType,
		FetchedAt: usage.FetchedAt,
	}
}

func readCodexCreditsSnapshot(extra map[string]any) *openAICreditsSnapshot {
	raw, ok := extra[openaiQuotaCreditsKey]
	if !ok || raw == nil {
		return nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var snapshot openAICreditsSnapshot
	if json.Unmarshal(encoded, &snapshot) != nil {
		return nil
	}
	return &snapshot
}

// Parsing is for eligibility only. The original strings remain the API/display
// values. Bound exponents before allocating arbitrary-precision numbers.
func codexNonnegativeAmount(raw *string) (*big.Rat, bool) {
	if raw == nil {
		return nil, false
	}
	value := strings.TrimSpace(*raw)
	if value == "" || len(value) > 256 {
		return nil, false
	}
	if index := strings.IndexAny(value, "eE"); index >= 0 {
		exponent, err := strconv.Atoi(value[index+1:])
		if err != nil || exponent < -1000 || exponent > 1000 {
			return nil, false
		}
	}
	number, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsNaN(number) || math.IsInf(number, 0) || number < 0 {
		return nil, false
	}
	exact, ok := new(big.Rat).SetString(value)
	return exact, ok && exact.Sign() >= 0
}

// A credit snapshot only relaxes the inferred 100% subscription-window pause.
// It never clears account/model cooldowns, authorization errors, admin disables,
// explicit earlier pause thresholds, or upstream spending/organization denials.
func openAICreditsAllowExhaustedWindow(account *Account, now time.Time) bool {
	if account == nil || account.IsShadow() || (!account.IsOAuth() && !account.IsOpenAICompatibleQuotaBridge()) {
		return false
	}
	snapshot := readCodexCreditsSnapshot(account.Extra)
	if snapshot == nil || snapshot.FetchedAt <= 0 {
		return false
	}
	age := now.Sub(time.Unix(snapshot.FetchedAt, 0))
	if age < 0 || age >= openAICreditsSchedulingMaxAge {
		return false
	}
	// The official Codex client discards rate_limit.allowed/limit_reached when
	// mapping its usage snapshot. They describe the subscription bucket, not a
	// reliable veto on credit-backed use. Actual request failures still follow
	// the existing account/model cooldown and authorization gates.
	if snapshot.RateLimitReachedType != nil {
		switch strings.TrimSpace(snapshot.RateLimitReachedType.Type) {
		case "rate_limit_reached":
			// An exhausted subscription window may continue using credits.
		case "workspace_owner_credits_depleted", "workspace_member_credits_depleted",
			"workspace_owner_usage_limit_reached", "workspace_member_usage_limit_reached":
			return false
		default:
			return false // Unknown or malformed denial types cannot be overridden.
		}
	}
	budgetAvailable := false
	if spend := snapshot.SpendControl; spend != nil {
		if spend.Reached != nil && *spend.Reached {
			return false
		}
		if limit := spend.IndividualLimit; limit != nil {
			if limit.ResetAt != nil && *limit.ResetAt > 0 && now.Unix() >= *limit.ResetAt {
				return false // This snapshot belongs to a previous budget cycle.
			}
			if limit.ResetAt == nil && limit.ResetAfterSeconds != nil && age >= time.Duration(*limit.ResetAfterSeconds)*time.Second {
				return false
			}
			for _, percent := range []*float64{limit.UsedPercent, limit.RemainingPercent} {
				if percent != nil && (math.IsNaN(*percent) || math.IsInf(*percent, 0) || *percent < 0 || *percent > 100) {
					return false
				}
			}
			if limit.Remaining != nil {
				remaining, valid := codexNonnegativeAmount(limit.Remaining)
				if !valid || remaining.Sign() <= 0 {
					return false
				}
				budgetAvailable = true
			}
			var total, used *big.Rat
			var valid bool
			if limit.Limit != nil {
				total, valid = codexNonnegativeAmount(limit.Limit)
				if !valid || total.Sign() <= 0 {
					return false
				}
			}
			if limit.Used != nil {
				used, valid = codexNonnegativeAmount(limit.Used)
				if !valid {
					return false
				}
			}
			if total != nil && used != nil {
				if total.Cmp(used) <= 0 {
					return false
				}
				budgetAvailable = true
			}
			// Rounded percentages may say 0% while a positive decimal amount
			// remains. Exact upstream amounts take precedence in that case.
			if !budgetAvailable && ((limit.UsedPercent != nil && *limit.UsedPercent >= 100) || (limit.RemainingPercent != nil && *limit.RemainingPercent <= 0)) {
				return false
			}
		}
	}
	if credits := snapshot.Credits; credits != nil {
		amount := credits.Remaining
		if amount == nil {
			amount = credits.Balance
		}
		if amount != nil {
			balance, valid := codexNonnegativeAmount(amount)
			if !valid {
				return false
			}
			// Unlimited is an independent upstream entitlement; a valid zero
			// amount may be its placeholder. Invalid/negative amounts still fail.
			return credits.Unlimited || balance.Sign() > 0
		}
		// The upstream may confirm usable credits without exposing the balance.
		// An explicit zero/invalid balance was handled above and cannot use this
		// fallback to turn a spending cap or has_credits flag into money.
		return credits.Unlimited || credits.HasCredits || budgetAvailable
	}
	return budgetAvailable
}

func openAICreditsOverrideWindowPause(account *Account, window string, threshold, utilization float64, now time.Time) bool {
	// Both an explicit per-account threshold and a global earlier threshold
	// express an administrator's stop policy and retain precedence.
	if threshold < 1 || utilization < 1 {
		return false
	}
	if explicit, ok := resolveAccountExtraNumber(account.Extra, "auto_pause_"+window+"_threshold"); ok && explicit > 0 {
		return false
	}
	return openAICreditsAllowExhaustedWindow(account, now)
}
