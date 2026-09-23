package handler

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestJResponsesStreamReconstructsTextAndArgumentsOnce(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	raw := []byte(`{"id":"resp_one","status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Hello world","annotations":[]}]},{"type":"function_call","call_id":"call_one","name":"read","arguments":"{\"path\":\"a\"}"}]}`)
	require.NoError(t, writeJResponse(c, raw, "gpt-5.6-sol-j", true))
	text, args, sequence, completed := "", "", 0, 0
	for _, line := range strings.Split(w.Body.String(), "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var event map[string]any
		require.NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event))
		require.EqualValues(t, sequence, event["sequence_number"])
		sequence++
		switch event["type"] {
		case "response.output_item.added":
			item := event["item"].(map[string]any)
			if item["type"] == "message" {
				require.Empty(t, item["content"])
			}
			if item["type"] == "function_call" {
				require.Empty(t, item["arguments"])
			}
		case "response.output_text.delta":
			text += event["delta"].(string)
		case "response.function_call_arguments.delta":
			args += event["delta"].(string)
		case "response.completed":
			completed++
			require.Equal(t, "gpt-5.6-sol-j", event["response"].(map[string]any)["model"])
		}
	}
	require.Equal(t, "Hello world", text)
	require.JSONEq(t, `{"path":"a"}`, args)
	require.Equal(t, 1, completed)
}

func TestJCatalogKeepsBaseCapabilitiesAndKeyToggle(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Set(jCatalogContext, enabled)
		body := []byte(`{"models":[{"slug":"gpt-5.6-sol","context_window":200000,"prefer_websockets":true},{"slug":"gpt-image-2"},{"slug":"gpt-6j"}]}`)
		out := string(decorateJCatalogue(c, body))
		require.NotContains(t, out, "gpt-6j")
		require.NotContains(t, out, "gpt-image-2-j")
		if enabled {
			require.Contains(t, out, "gpt-5.6-sol-j")
			require.Contains(t, out, `"prefer_websockets":false`)
		} else {
			require.NotContains(t, out, "gpt-5.6-sol-j")
		}
		standard := decorateJCatalogue(c, []byte(`{"data":[{"id":"gpt-5.6-sol","owned_by":"openai"}]}`))
		c.Params = gin.Params{{Key: "model", Value: "gpt-5.6-sol-j"}}
		writeRetrievedModel(c, standard)
		if enabled {
			require.Equal(t, 200, w.Code)
			require.Contains(t, w.Body.String(), "pegasusailabs")
		} else {
			require.Equal(t, 404, w.Code)
		}
	}
}
