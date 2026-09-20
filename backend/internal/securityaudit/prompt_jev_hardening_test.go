package securityaudit

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGPT6JCannotBypassDisabledOrExcludedGuard(t *testing.T) {
	group := int64(42)
	cfg := ActiveConfig{RiskControlEnabled: true, Enabled: true, BlockingEnabled: true, AllGroups: false, GroupIDs: []int64{7}, Endpoints: []ActiveEndpoint{jevTestEndpoint()}}
	cfg.Endpoints[0].Enabled = true
	manager := &ConfigManager{}
	manager.snapshot.Store(&activeConfigSnapshot{active: cfg})
	service := &PromptService{config: manager, evaluator: &GuardEvaluator{}}
	require.True(t, service.JevBlockingReady())
	_, err := service.Evaluate(context.Background(), Request{RequireJev: true, GroupID: &group, Body: []byte(`{"input":"hello"}`)})
	require.Error(t, err, "excluded group must not skip Jev")
	for _, coordinator := range []*Coordinator{nil, NewCoordinator(nil, nil)} {
		decision := coordinator.Check(context.Background(), Request{RequireJev: true})
		require.False(t, decision.AllowNextStage)
	}
}

func TestJevCompactionPreservesIncompleteOrNonTextCandidates(t *testing.T) {
	for _, content := range []any{
		strings.Repeat("x", jevCompactionExcerptRunes+1),
		[]any{map[string]any{"type": "output_text", "text": "summary"}, map[string]any{"type": "image", "url": "private"}},
		[]any{map[string]any{"type": "output_text", "text": "summary", "annotations": []any{map[string]any{"type": "citation", "url": "source"}}}},
	} {
		raw, err := json.Marshal(map[string]any{"type": "message", "role": "assistant", "content": content})
		require.NoError(t, err)
		_, complete := compactCandidateText(raw)
		require.False(t, complete)
		input := []json.RawMessage{raw}
		for range jevCompactionRecentItems {
			input = append(input, json.RawMessage(`{"type":"message","role":"user","content":"recent"}`))
		}
		candidates, _ := collectJevCompactionCandidates(input)
		require.Empty(t, candidates)
	}
	raw := json.RawMessage(`{"type":"message","role":"assistant","content":[{"type":"output_text","text":"complete text","annotations":[]}]}`)
	text, complete := compactCandidateText(raw)
	require.True(t, complete)
	require.Equal(t, "complete text", text)
}
