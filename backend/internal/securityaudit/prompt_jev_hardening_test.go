package securityaudit

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJevSafetyCannotBypassDisabledOrExcludedGuard(t *testing.T) {
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
