package admin

import (
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCPACredentialBindingDistinguishesSavedProxyFromBusinessBackend(t *testing.T) {
	proxyID := int64(9)
	items := []service.CPACredentialSettings{
		{Name: "pi.json", AuthID: "pi-auth", Identity: "shared-identity", ProxyID: &proxyID},
		{Name: "orphan.json", AuthID: "orphan-auth", Identity: "orphan-identity", ProxyID: &proxyID},
		{Name: "cpa.json", AuthID: "cpa-auth", Identity: "cpa-identity", ProxyID: &proxyID},
	}
	accounts := []service.Account{
		{ID: 1, Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey, Status: service.StatusActive, Schedulable: true, Credentials: map[string]any{"base_url": "http://cpa:8317"}, Extra: map[string]any{"cpa_identity": "shared-identity"}},
		{ID: 50, Platform: service.PlatformOpenAI, Type: service.AccountTypeOAuth, Status: service.StatusActive, Schedulable: true, Credentials: map[string]any{"harness_kind": "pi"}, Extra: map[string]any{"cpa_auth_id": "pi-auth", "cpa_identity": "shared-identity"}},
		{ID: 51, Platform: service.PlatformOpenAI, Type: service.AccountTypeAPIKey, Status: service.StatusActive, Schedulable: true, Credentials: map[string]any{"base_url": "http://cpa:8317"}, Extra: map[string]any{"cpa_auth_id": "cpa-auth"}},
	}
	attachCPABusinessAccounts(items, accounts)
	require.Equal(t, int64(50), items[0].BusinessAccountID, "exact credential binding wins over shared identity")
	require.Equal(t, "pi", items[0].BusinessBackend)
	require.False(t, items[0].CPARoutingEnabled)
	require.Equal(t, &proxyID, items[0].ProxyID, "saved CPA binding remains distinct from Pi route")
	require.Zero(t, items[1].BusinessAccountID)
	require.False(t, items[1].CPARoutingEnabled)
	require.Equal(t, "cpa", items[2].BusinessBackend)
	require.True(t, items[2].CPARoutingEnabled)
	items[2].Disabled = true
	attachCPABusinessAccounts(items, accounts)
	require.False(t, items[2].CPARoutingEnabled)
}
