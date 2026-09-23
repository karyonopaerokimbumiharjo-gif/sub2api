package sseparse

import (
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestTerminalAcrossEveryFragmentBoundary(t *testing.T) {
	raw := "event: response.completed\r\ndata: {\"type\":\"response.completed\"}\r\n\r\n"
	for split := 0; split <= len(raw); split++ {
		var parser Parser
		var got []string
		emit := func(e Event) { got = append(got, e.Terminal()) }
		parser.Feed([]byte(raw[:split]), emit)
		parser.Feed([]byte(raw[split:]), emit)
		require.Equal(t, []string{"completed"}, got, "split %d", split)
	}
}

func TestGeneratedTextCannotTerminateStream(t *testing.T) {
	for _, value := range []string{"[DONE]", "response.completed", "message_stop"} {
		var parser Parser
		parser.Feed([]byte("event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\""+value+"\"}\n\n"), func(e Event) { require.Empty(t, e.Terminal()) })
	}
	require.Empty(t, (Event{Type: "response.completed", Data: []byte(`{"type":"response.output_text.delta"}`)}).Terminal())
}

func TestOversizedFrameIsDiscardedAndParserRecovers(t *testing.T) {
	var parser Parser
	var got []string
	raw := "data: " + strings.Repeat("x", MaxFrameBytes) + "\ndata: [DONE]\n\ndata: [DONE]\n\n"
	parser.Feed([]byte(raw), func(e Event) { got = append(got, e.Terminal()) })
	require.True(t, parser.Truncated)
	require.Equal(t, []string{"completed"}, got)
}
