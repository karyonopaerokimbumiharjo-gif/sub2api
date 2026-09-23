package securityaudit

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Wei-Shaw/sub2api/internal/pkg/sseparse"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

type BlockingOutputEngine interface {
	GateOutput(context.Context, Request, []byte, bool) Decision
}

func (c *Coordinator) GateOutput(ctx context.Context, req Request, body []byte, stream bool) Decision {
	if c != nil && c.prompt != nil {
		if gate, ok := c.prompt.(BlockingOutputEngine); ok {
			return gate.GateOutput(ctx, req, body, stream)
		}
	}
	return prioritize(nil, unavailablePromptDecision(ErrorCodeUnavailable))
}

func (s *PromptService) GateOutput(ctx context.Context, req Request, body []byte, stream bool) Decision {
	deny := func() Decision { return prioritize(nil, unavailablePromptDecision(ErrorCodeUnavailable)) }
	if s == nil || s.config == nil || s.evaluator == nil || len(body) > 1<<20 {
		return deny()
	}
	cfg, ok := s.config.Active()
	if !ok || !cfg.Enabled || !cfg.IncludesGroup(req.GroupID) {
		return deny()
	}
	text := ExtractAssistantOutput(body, stream)
	// Tool arguments are part of the assistance, not an exemption from output review.
	if stream {
		text += extractOutputToolText(body, true)
	} else {
		text += extractOutputToolText(body, false)
	}
	if strings.TrimSpace(text) == "" || utf8.RuneCountInString(text) > DefaultFullPromptMaxRunes {
		return deny()
	}
	req.RequireJev = s.RequireJevSafety()
	req.OutputCapture = &OutputCapture{CapturedBytes: len(body), ObservedBytes: int64(len(body)), Complete: true, Terminal: "completed"}
	snapshot, err := BuildOutputPromptSnapshot(req, text)
	if err != nil {
		return deny()
	}
	snapshot.ResearchProfileID = s.activeResearchProfile(ctx, req.UserID, req.APIKeyID)
	cfg.StorePassEvents = true
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	decision, err := s.evaluator.EvaluateFor(ctx, cfg, snapshot, req.RequireJev)
	if err != nil {
		return prioritize(nil, unavailablePromptDecision(guardErrorCode(err)))
	}
	return prioritize(nil, decision)
}

func outputToolText(raw []byte) string {
	var document any
	if json.Unmarshal(raw, &document) != nil {
		return ""
	}
	var walk func(any) string
	walk = func(value any) string {
		switch v := value.(type) {
		case []any:
			out := ""
			for _, item := range v {
				out += walk(item)
			}
			return out
		case map[string]any:
			if v["type"] == "function_call" || v["type"] == "custom_tool_call" {
				raw, _ := json.Marshal(v)
				return "\nTool assistance: " + string(raw)
			}
			// Responses terminal output and Chat Completions tool_calls.
			out := ""
			for _, key := range []string{"response", "output", "choices", "message", "tool_calls", "function"} {
				if nested, ok := v[key]; ok {
					out += walk(nested)
				}
			}
			if args, ok := v["arguments"].(string); ok && v["name"] != nil {
				out += "\nTool assistance: " + args
			}
			return out
		}
		return ""
	}
	return walk(document)
}

// The terminal Responses snapshot is authoritative. Chat tool arguments arrive
// in fragments and must be reconstructed by choice/tool index before review.
func extractOutputToolText(raw []byte, stream bool) string {
	if !stream {
		return outputToolText(raw)
	}
	var parser sseparse.Parser
	final := ""
	type fragment struct{ Name, Arguments string }
	calls := map[string]*fragment{}
	parser.Feed(raw, func(event sseparse.Event) {
		if event.Terminal() == "completed" && string(event.Data) != "[DONE]" {
			final = outputToolText(event.Data)
		}
		var envelope struct {
			Choices []struct {
				Index int `json:"index"`
				Delta struct {
					ToolCalls []struct {
						Index    int `json:"index"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
		}
		if json.Unmarshal(event.Data, &envelope) != nil {
			return
		}
		for _, choice := range envelope.Choices {
			for _, tool := range choice.Delta.ToolCalls {
				key := fmt.Sprintf("%d:%d", choice.Index, tool.Index)
				if calls[key] == nil {
					calls[key] = &fragment{}
				}
				calls[key].Name += tool.Function.Name
				calls[key].Arguments += tool.Function.Arguments
			}
		}
	})
	if final != "" {
		return final
	}
	keys := make([]string, 0, len(calls))
	for k := range calls {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out strings.Builder
	for _, k := range keys {
		b, _ := json.Marshal(calls[k])
		out.WriteString("\nTool assistance: ")
		out.Write(b)
	}
	return out.String()
}
