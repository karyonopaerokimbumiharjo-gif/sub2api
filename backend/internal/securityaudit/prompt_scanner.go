package securityaudit

import (
	"errors"
	"sort"
	"strings"
	"time"
)

func SplitRunes(value string, limit int) []string {
	if limit <= 0 {
		return nil
	}
	segments := strings.Split(value, promptAuditPrioritySeparator)
	chunks := make([]string, 0, len(segments))
	for _, segment := range segments {
		runes := []rune(segment)
		for start := 0; start < len(runes); start += limit {
			end := start + limit
			if end > len(runes) {
				end = len(runes)
			}
			chunks = append(chunks, string(runes[start:end]))
		}
	}
	return chunks
}

func AggregateResults(results []*NormalizedResult, latency time.Duration) (*NormalizedResult, error) {
	if len(results) == 0 {
		return nil, errors.New("prompt guard produced no complete result")
	}
	aggregated := &NormalizedResult{
		Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow,
		Categories: []string{}, IntentCategories: []string{},
		ContentCategories: []string{}, MatchedScanners: []string{},
		ScannerScores: map[string]float64{}, ScannerEvidence: map[string]string{}, ChunkTotal: len(results),
		LatencyMS: int(latency.Milliseconds()),
	}
	categories := map[string]struct{}{}
	intentCategories := map[string]struct{}{}
	contentCategories := map[string]struct{}{}
	matched := map[string]struct{}{}
	unknown := map[string]struct{}{}
	var selected *NormalizedResult
	for _, result := range results {
		if result == nil {
			return nil, errors.New("prompt guard partial result is not allowed")
		}
		// Keep the verdict and all provenance fields from one result. Mixing a
		// hard-coded backend with another chunk's endpoint/version misattributes
		// Jev and other providers in persisted audit events. Equal severity is
		// resolved by stable chunk order.
		if selected == nil || resultSeverity(result.Decision) > resultSeverity(selected.Decision) {
			selected = result
			aggregated.Decision = result.Decision
			aggregated.RiskLevel = result.RiskLevel
			aggregated.Action = result.Action
			aggregated.Safety = result.Safety
			aggregated.ScannerBackend = result.ScannerBackend
			aggregated.GuardEndpointID = result.GuardEndpointID
			aggregated.ScannerVersion = result.ScannerVersion
			aggregated.PolicyID = result.PolicyID
			aggregated.PolicyVersion = result.PolicyVersion
		}
		if result.BioTier > aggregated.BioTier {
			aggregated.BioTier = result.BioTier
		}
		for _, category := range result.Categories {
			categories[category] = struct{}{}
		}
		for _, category := range result.IntentCategories {
			intentCategories[category] = struct{}{}
		}
		for _, category := range result.ContentCategories {
			contentCategories[category] = struct{}{}
		}
		for _, scanner := range result.MatchedScanners {
			matched[scanner] = struct{}{}
		}
		for scanner, score := range result.ScannerScores {
			if score > aggregated.ScannerScores[scanner] {
				aggregated.ScannerScores[scanner] = score
			}
		}
		for scanner, evidence := range result.ScannerEvidence {
			if _, exists := aggregated.ScannerEvidence[scanner]; !exists {
				aggregated.ScannerEvidence[scanner] = RedactPreview(evidence, 160)
			}
		}
		for _, category := range result.UnknownCategories {
			unknown[category] = struct{}{}
		}
	}
	if aggregated.BioTier != "" {
		aggregated.ScannerEvidence["bio_tier"] = aggregated.BioTier
		aggregated.ScannerEvidence["bio_policy_version"] = BioPolicyVersion
	}
	aggregated.Categories = orderedScannerKeys(categories)
	aggregated.IntentCategories = orderedScannerKeys(intentCategories)
	aggregated.ContentCategories = orderedContentCategoryKeys(contentCategories)
	aggregated.MatchedScanners = orderedScannerKeys(matched)
	aggregated.UnknownCategories = sortedKeys(unknown)
	return aggregated, nil
}

func orderedContentCategoryKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	remaining := make(map[string]struct{}, len(values))
	for key := range values {
		remaining[key] = struct{}{}
	}
	for _, category := range AllContentCategoryIDs {
		if _, ok := remaining[category]; ok {
			result = append(result, category)
			delete(remaining, category)
		}
	}
	return append(result, sortedKeys(remaining)...)
}

func resultSeverity(decision EventDecision) int {
	switch decision {
	case EventCritical:
		return 4
	case EventReviewRequired:
		return 3
	case EventFlag:
		return 2
	default:
		return 1
	}
}

func sortedKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func orderedScannerKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	remaining := make(map[string]struct{}, len(values))
	for key := range values {
		remaining[key] = struct{}{}
	}
	for _, scannerID := range AllScannerIDs {
		if _, ok := remaining[scannerID]; ok {
			result = append(result, scannerID)
			delete(remaining, scannerID)
		}
	}
	result = append(result, sortedKeys(remaining)...)
	return result
}
