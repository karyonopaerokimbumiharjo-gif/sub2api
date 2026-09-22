package securityaudit

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAggregateResultsKeepsWinningVerdictAndProviderTogether(t *testing.T) {
	jevPass := &NormalizedResult{
		Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow, Safety: "Safe",
		ScannerBackend: "typesafe-jev", ScannerVersion: "jev-1.13.0", GuardEndpointID: "jev-native-acer",
		PolicyID: "jev-policy", PolicyVersion: 2,
	}
	qwenPass := &NormalizedResult{
		Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow, Safety: "Safe",
		ScannerBackend: "qwen3guard-openai", ScannerVersion: "qwen3guard", GuardEndpointID: "qwen-node",
		PolicyID: "qwen-policy", PolicyVersion: 1,
	}
	jevFlag := &NormalizedResult{
		Decision: EventFlag, RiskLevel: RiskHigh, Action: ActionWarn, Safety: "Controversial",
		ScannerBackend: "typesafe-jev", ScannerVersion: "jev-1.13.0", GuardEndpointID: "jev-native-acer",
		PolicyID: "jev-policy", PolicyVersion: 2,
	}
	jevBlock := &NormalizedResult{
		Decision: EventCritical, RiskLevel: RiskCritical, Action: ActionBlock, Safety: "Unsafe",
		ScannerBackend: "typesafe-jev", ScannerVersion: "jev-1.13.0", GuardEndpointID: "jev-native-acer",
		PolicyID: "jev-policy", PolicyVersion: 2,
	}
	qwenBlock := &NormalizedResult{
		Decision: EventCritical, RiskLevel: RiskCritical, Action: ActionBlock, Safety: "Unsafe",
		ScannerBackend: "qwen3guard-openai", ScannerVersion: "qwen3guard", GuardEndpointID: "qwen-node",
		PolicyID: "qwen-policy", PolicyVersion: 1,
	}
	jevPassWithoutEndpoint := *jevPass
	jevPassWithoutEndpoint.GuardEndpointID = ""

	for _, tc := range []struct {
		name   string
		inputs []*NormalizedResult
		winner *NormalizedResult
	}{
		{name: "single Jev pass", inputs: []*NormalizedResult{jevPass}, winner: jevPass},
		{name: "later Jev flag outranks qwen pass", inputs: []*NormalizedResult{qwenPass, jevFlag}, winner: jevFlag},
		{name: "later Jev block outranks qwen pass", inputs: []*NormalizedResult{qwenPass, jevBlock}, winner: jevBlock},
		{name: "later qwen block outranks Jev pass", inputs: []*NormalizedResult{jevPass, qwenBlock}, winner: qwenBlock},
		{name: "earlier Jev block survives qwen pass", inputs: []*NormalizedResult{jevBlock, qwenPass}, winner: jevBlock},
		{name: "equal severity keeps first provider", inputs: []*NormalizedResult{qwenBlock, jevBlock}, winner: qwenBlock},
		{name: "missing endpoint does not borrow another provider", inputs: []*NormalizedResult{&jevPassWithoutEndpoint, qwenPass}, winner: &jevPassWithoutEndpoint},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AggregateResults(tc.inputs, 0)
			require.NoError(t, err)
			require.Equal(t, len(tc.inputs), got.ChunkTotal)
			require.Equal(t, tc.winner.Decision, got.Decision)
			require.Equal(t, tc.winner.RiskLevel, got.RiskLevel)
			require.Equal(t, tc.winner.Action, got.Action)
			require.Equal(t, tc.winner.Safety, got.Safety)
			require.Equal(t, tc.winner.ScannerBackend, got.ScannerBackend)
			require.Equal(t, tc.winner.ScannerVersion, got.ScannerVersion)
			require.Equal(t, tc.winner.GuardEndpointID, got.GuardEndpointID)
			require.Equal(t, tc.winner.PolicyID, got.PolicyID)
			require.Equal(t, tc.winner.PolicyVersion, got.PolicyVersion)
		})
	}
}
