package securityaudit

import (
	"context"
	"errors"
	"testing"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/stretchr/testify/require"
)

func mixedAuditStorageConfig() storageConfig {
	cfg := DefaultStorageConfig()
	cfg.Enabled = true
	cfg.BlockingEnabled = true
	cfg.Endpoints = []StorageEndpoint{
		{ID: "jev-primary", Name: "Jev", Protocol: JevProtocol, Adapter: EndpointAdapterGenericLLM, BaseURL: JevBaseURL, Model: DefaultJevModel, TokenCiphertext: "enc:jev-token", TimeoutMS: 1000, InputLimit: 4000, Enabled: true},
		{ID: "deepseek-fallback", Name: "DeepSeek", Protocol: EndpointProtocolOpenAICompatible, Adapter: EndpointAdapterGenericLLM, BaseURL: openCodeAuditBaseURL, Model: "deepseek-v4-flash", TokenCiphertext: "enc:deepseek-token", TimeoutMS: 1000, InputLimit: 4000, Enabled: true},
	}
	return cfg
}

func TestMixedJevAndCompatibleConfigKeepsIndependentPools(t *testing.T) {
	cfg := mixedAuditStorageConfig()
	require.NoError(t, validateStorageConfig(cfg))
	active, err := ActiveFromStorage(cfg, true, prefixEncryptor{})
	require.NoError(t, err)
	require.Equal(t, []string{"deepseek-fallback"}, []string{active.EnabledEndpointsFor(false)[0].ID})
	require.Equal(t, []string{"jev-primary"}, []string{active.EnabledEndpointsFor(true)[0].ID})
	require.True(t, jevEndpointsReady(active), "a normal enabled endpoint must not make Jev appear unavailable")

	active.Endpoints[0].Enabled = false
	require.False(t, jevEndpointsReady(active), "DeepSeek must not satisfy RequireJev")
	require.Empty(t, active.EnabledEndpointsFor(true))
	require.Len(t, active.EnabledEndpointsFor(false), 1)
}

func TestMixedJevAndCompatibleConfigSavesThroughAdminPath(t *testing.T) {
	manager := &ConfigManager{encryptor: prefixEncryptor{}, encryptionKeyConfigured: true}
	req := promptAuditUpdateRequest(1, 1, "")
	req.BlockingEnabled = true
	req.BackgroundAuditMode = BackgroundAuditModeOff
	req.Endpoints = []UpdateEndpoint{
		{ID: "jev-primary", Name: "Jev", Protocol: JevProtocol, Adapter: EndpointAdapterGenericLLM, BaseURL: JevBaseURL, Model: DefaultJevModel, Token: "jev-token", TimeoutMS: 1000, InputLimit: 4000, Enabled: true},
		{ID: "deepseek-fallback", Name: "DeepSeek", Protocol: EndpointProtocolOpenAICompatible, Adapter: EndpointAdapterGenericLLM, BaseURL: openCodeAuditBaseURL, Model: "deepseek-v4-flash", Token: "deepseek-token", TimeoutMS: 1000, InputLimit: 4000, Enabled: true},
	}
	saved, err := manager.buildNextStorage(DefaultStorageConfig(), req, 1)
	require.NoError(t, err)
	active, err := ActiveFromStorage(saved, true, prefixEncryptor{})
	require.NoError(t, err)
	require.Len(t, active.EnabledEndpointsFor(true), 1)
	require.Len(t, active.EnabledEndpointsFor(false), 1)
}

func TestBackgroundAuditRequiresNormalEndpoint(t *testing.T) {
	cfg := mixedAuditStorageConfig()
	cfg.BlockingEnabled = false
	cfg.BackgroundAuditMode = BlockingAuditModeFull
	cfg.Endpoints[1].Enabled = false
	require.Equal(t, "prompt_audit_normal_endpoint_required", infraerrors.Reason(validateStorageConfig(cfg)))
	cfg.BlockingEnabled = true
	cfg.BackgroundAuditMode = BackgroundAuditModeOff
	require.NoError(t, validateStorageConfig(cfg), "Jev-only blocking configurations remain valid")
}

func TestForegroundProviderSelectionNeverCrossesPools(t *testing.T) {
	cfg := ActiveConfig{
		RiskControlEnabled: true, Enabled: true, BlockingEnabled: true, AllGroups: true,
		Scanners: []string{"jailbreak"},
		Endpoints: []ActiveEndpoint{
			{ID: "jev-primary", Protocol: JevProtocol, Token: "jev-token", Enabled: true, TimeoutMS: 1000, InputLimit: 4000},
			{ID: "deepseek-fallback", Protocol: EndpointProtocolOpenAICompatible, Enabled: true, TimeoutMS: 1000, InputLimit: 4000},
		},
	}
	var calls []string
	scanner := PromptScannerFunc(func(_ context.Context, endpoint ActiveEndpoint, _ string, _ []string) (*NormalizedResult, error) {
		calls = append(calls, endpoint.ID)
		if endpoint.Protocol == JevProtocol {
			return nil, &GuardError{Code: ErrorCodeUnavailable, Cause: errors.New("jev unavailable")}
		}
		return &NormalizedResult{Decision: EventPass, RiskLevel: RiskLow, Action: ActionAllow, GuardEndpointID: endpoint.ID}, nil
	})
	service := &PromptService{config: &fakeConfigStore{active: true, cfg: cfg}, evaluator: NewGuardEvaluator(scanner, nil, nil)}
	normal := Request{RequestID: "normal-request", Protocol: "openai_responses", Body: []byte(`{"input":"ordinary request"}`)}
	decision, err := service.Evaluate(context.Background(), normal)
	require.NoError(t, err)
	require.Equal(t, DecisionAllow, decision.Kind)
	require.Equal(t, []string{"deepseek-fallback"}, calls)

	calls = nil
	required := Request{RequestID: "jev-required", RequireJev: true, Protocol: "openai_responses", Body: []byte(`{"input":"required request"}`)}
	decision, err = service.Evaluate(context.Background(), required)
	require.Nil(t, decision)
	require.Error(t, err)
	require.Equal(t, []string{"jev-primary"}, calls, "a Jev failure must not fall back to DeepSeek")

	cfg.Endpoints[0].Enabled = false
	calls = nil
	service.config = &fakeConfigStore{active: true, cfg: cfg}
	decision, err = service.Evaluate(context.Background(), required)
	require.Nil(t, decision)
	require.Error(t, err)
	require.Empty(t, calls, "DeepSeek must not be invoked when Jev is disabled")
}

func TestAdaptiveShadowSelectionStaysWithPrimaryProvider(t *testing.T) {
	cfg := ActiveConfig{Endpoints: []ActiveEndpoint{
		{ID: "jev-a", Protocol: JevProtocol, Enabled: true},
		{ID: "normal-a", Protocol: EndpointProtocolOpenAICompatible, Enabled: true},
		{ID: "jev-b", Protocol: JevProtocol, Enabled: true},
		{ID: "normal-b", Protocol: EndpointProtocolOpenAICompatible, Enabled: true},
	}}
	jevShadow, ok := nextShadowEndpoint(enabledEndpointsForPrimary(cfg, "jev-a"), "jev-a")
	require.True(t, ok)
	require.Equal(t, "jev-b", jevShadow.ID)
	normalShadow, ok := nextShadowEndpoint(enabledEndpointsForPrimary(cfg, "normal-a"), "normal-a")
	require.True(t, ok)
	require.Equal(t, "normal-b", normalShadow.ID)
	require.Empty(t, enabledEndpointsForPrimary(cfg, "local-policy-cache"))
}

func TestRequiredJevWithoutActiveConfigFailsClosed(t *testing.T) {
	service := &PromptService{
		config: &fakeConfigStore{active: false},
		evaluator: NewGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
			t.Fatal("scanner must not run without a configured Jev pool")
			return nil, nil
		}), nil, nil),
	}
	decision, err := service.Evaluate(context.Background(), Request{RequireJev: true})
	require.Nil(t, decision)
	require.Error(t, err)
	require.Equal(t, ErrorCodeUnavailable, guardErrorCode(err))
}

func TestRequiredJevWithoutAuditableTextFailsClosed(t *testing.T) {
	cfg := ActiveConfig{
		RiskControlEnabled: true, Enabled: true, BlockingEnabled: true, AllGroups: true,
		Endpoints: []ActiveEndpoint{{ID: "jev", Protocol: JevProtocol, Token: "jev-token", Enabled: true, TimeoutMS: 1000, InputLimit: 4000}},
	}
	service := &PromptService{config: &fakeConfigStore{active: true, cfg: cfg}, evaluator: NewGuardEvaluator(PromptScannerFunc(func(context.Context, ActiveEndpoint, string, []string) (*NormalizedResult, error) {
		t.Fatal("scanner must not run without auditable text")
		return nil, nil
	}), nil, nil)}
	decision, err := service.Evaluate(context.Background(), Request{RequireJev: true, Protocol: "openai_responses", Body: []byte(`{"input":[]}`)})
	require.Nil(t, decision)
	require.Error(t, err)
	require.Equal(t, ErrorCodeInvalidResponse, guardErrorCode(err))
}
