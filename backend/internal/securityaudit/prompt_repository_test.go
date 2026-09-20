package securityaudit

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShouldStorePromptAuditEvent(t *testing.T) {
	tests := []struct {
		name            string
		storePassEvents bool
		decision        EventDecision
		want            bool
	}{
		{name: "pass disabled", storePassEvents: false, decision: EventPass, want: false},
		{name: "flag disabled", storePassEvents: false, decision: EventFlag, want: true},
		{name: "critical disabled", storePassEvents: false, decision: EventCritical, want: true},
		{name: "pass enabled", storePassEvents: true, decision: EventPass, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldStorePromptAuditEvent(tt.decision, tt.storePassEvents); got != tt.want {
				t.Fatalf("shouldStorePromptAuditEvent(%q, %t) = %t, want %t", tt.decision, tt.storePassEvents, got, tt.want)
			}
		})
	}
}

func TestMarshalStringJSONArrayNormalizesNilToEmptyArray(t *testing.T) {
	require.JSONEq(t, `[]`, string(marshalStringJSONArray(nil)))
	require.JSONEq(t, `[]`, string(marshalStringJSONArray([]string{})))
	require.JSONEq(t, `["jailbreak"]`, string(marshalStringJSONArray([]string{"jailbreak"})))
}
