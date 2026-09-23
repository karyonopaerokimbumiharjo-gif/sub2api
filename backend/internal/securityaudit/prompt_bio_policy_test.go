package securityaudit

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestBioTiersAreDistinctAndPreserveHardBlocks(t *testing.T) {
	for _, tc := range []struct {
		tier  string
		kind  DecisionKind
		allow bool
	}{{"B0", DecisionAllow, true}, {"B1", DecisionFlag, true}, {"B2", DecisionUnavailable, false}, {"B3", DecisionBlock, false}, {"B4", DecisionBlock, false}} {
		t.Run(tc.tier, func(t *testing.T) {
			r := &NormalizedResult{Decision: EventPass, Action: ActionAllow}
			applyBioTier(r, tc.tier)
			kind := decisionKindForResult(r)
			require.Equal(t, tc.kind, kind)
			p := &PromptDecision{Kind: kind, Result: r}
			if tc.tier == "B2" {
				p.ErrorCode = ErrorCodeReviewRequired
			}
			d := prioritize(nil, p)
			require.Equal(t, tc.allow, d.AllowNextStage)
			require.Equal(t, tc.tier == "B1", RequiresStrictOutput(&d))
			hard := &NormalizedResult{Decision: EventCritical, Action: ActionBlock, Categories: []string{"jailbreak"}}
			applyBioTier(hard, tc.tier)
			require.Equal(t, EventCritical, hard.Decision)
			require.Equal(t, ActionBlock, hard.Action)
		})
	}
}
func TestOutputToolArgumentsAreIncludedOnce(t *testing.T) {
	raw := []byte("data: {\"type\":\"response.function_call_arguments.delta\",\"delta\":\"marker\"}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"output\":[{\"type\":\"function_call\",\"name\":\"lookup\",\"arguments\":\"marker\"}]}}\n\n")
	require.Contains(t, extractOutputToolText(raw, true), "marker")
	chat := []byte("data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"read\",\"arguments\":\"mar\"}}]}}]}\n\ndata: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"ker\"}}]}}]}\n\ndata: [DONE]\n\n")
	require.Contains(t, extractOutputToolText(chat, true), "marker")
}
func TestBioUnknownNeverBecomesConfirmedViolation(t *testing.T) {
	p, c := .6, .6
	z := .1
	tier, ok := parseBioAnswer(jevAnswer{Type: "choice", Choice: "B3", Confidence: &c, Probabilities: map[string]*float64{"B0": &z, "B1": &z, "B2": &z, "B3": &p, "B4": &z}})
	require.True(t, ok)
	require.Equal(t, "B2", tier)
}
