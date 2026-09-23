// Package jruntime implements bounded cooperation between a finite-choice
// controller, an explicitly selected base model, and authorized tool execution.
// Neither model grants authority. All execution passes through the ToolRunner.
package jruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
)

const PolicyVersion = "j-cooperation-v1"
const HandoffTool = "sub2api_handoff_to_jev"

var (
	ErrBudget         = errors.New("j_execution_budget_exhausted")
	ErrModel          = errors.New("j_base_model_mismatch")
	ErrTool           = errors.New("j_tool_not_authorized")
	ErrSafety         = errors.New("j_safety_rejected")
	ErrUnknownOutcome = errors.New("j_tool_outcome_unknown")
)

type Binding struct {
	UserID, KeyID, AccountID     int64
	SessionID, TaskID, BaseModel string
}

type Tool struct {
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters"`
}

type Call struct {
	ID        string `json:"call_id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// Candidate contains exact values derived from a finite schema. Jev selects an
// index; it cannot invent arguments, a tool name, a model, or a permission.
type Candidate struct {
	ID   string `json:"id"`
	Call Call   `json:"call"`
}
type Choice struct {
	Candidate                 string
	Confidence                float64
	InputTokens, OutputTokens int64
}
type Choose func(context.Context, Binding, json.RawMessage, []Candidate) (Choice, error)
type BaseResult struct {
	Body                      json.RawMessage
	ActualModel, RequestID    string
	InputTokens, OutputTokens int64
}
type BaseCall func(context.Context, Binding, json.RawMessage) (BaseResult, error)

// ToolRunner must recheck the current grant and JSON schema before dispatch.
// Unknown side effects are terminal: never replay them on another account.
type ToolRunner interface {
	Authorize(context.Context, Binding, Tool, Call) error
	Run(context.Context, Binding, Call) (json.RawMessage, error)
}

type Event struct {
	Stage, Actor, Model, CallID, Tool, Outcome string
	InputTokens, OutputTokens                  int64
}
type Budget struct {
	Steps, BaseCalls, JevCalls int
	Duration                   time.Duration
	MaxBytes                   int
}

func DefaultBudget() Budget {
	return Budget{Steps: 24, BaseCalls: 8, JevCalls: 16, Duration: 3 * time.Minute, MaxBytes: 8 << 20}
}

type Engine struct {
	GuardCall    func(context.Context, Binding, Tool, Call) error
	GuardResult  func(context.Context, Binding, Call, json.RawMessage) error
	InitialActor string
	Choose       Choose
	Base         BaseCall
	Tools        ToolRunner
	Budget       Budget
	Record       func(context.Context, Binding, Event) error
}
type Result struct {
	History                                                            []json.RawMessage
	NextActor                                                          string
	Response                                                           json.RawMessage
	BaseCalls, JevCalls, ToolCalls                                     int
	BaseInputTokens, BaseOutputTokens, JevInputTokens, JevOutputTokens int64
	Fallback                                                           string
}

func (e *Engine) Run(ctx context.Context, binding Binding, body []byte) (result Result, err error) {
	if e.Base == nil || binding.UserID <= 0 || binding.KeyID <= 0 || binding.AccountID <= 0 || binding.BaseModel == "" || binding.TaskID == "" || binding.SessionID == "" {
		return result, errors.New("j_binding_required")
	}
	budget := e.Budget
	if budget.Steps <= 0 {
		budget = DefaultBudget()
	}
	if budget.BaseCalls < 1 || budget.JevCalls < 1 || budget.Duration <= 0 || budget.MaxBytes < 1024 {
		return result, ErrBudget
	}
	ctx, cancel := context.WithTimeout(ctx, budget.Duration)
	defer cancel()
	var request map[string]json.RawMessage
	if len(body) > budget.MaxBytes || validateJSON(body) != nil || json.Unmarshal(body, &request) != nil {
		return result, errors.New("j_invalid_request")
	}
	var tools []Tool
	if raw := request["tools"]; len(raw) > 0 && json.Unmarshal(raw, &tools) != nil {
		return result, errors.New("j_invalid_tools")
	}
	declared := map[string]Tool{}
	for _, tool := range tools {
		if tool.Name == HandoffTool {
			return result, ErrTool
		}
		if tool.Type == "function" || tool.Type == "custom" {
			if tool.Name == "" {
				return result, ErrTool
			}
			if _, ok := declared[tool.Name]; ok {
				return result, ErrTool
			}
			declared[tool.Name] = tool
		}
	}
	input, err := inputItems(request["input"])
	if err != nil {
		return result, err
	}
	// Stateful upstream IDs cannot be combined with server-owned tool history.
	if p := request["previous_response_id"]; len(p) > 0 && string(p) != "null" {
		return result, errors.New("j_requires_full_input")
	}
	request["model"], _ = json.Marshal(binding.BaseModel)
	request["stream"] = json.RawMessage("false")
	request["store"] = json.RawMessage("false")
	delete(request, "previous_response_id")
	actor := e.InitialActor
	if actor == "" {
		actor = "jev"
	}
	if actor != "jev" && actor != "base" {
		return result, errors.New("j_invalid_phase")
	}
	if e.Tools != nil && e.Record == nil {
		return result, errors.New("j_journal_required")
	}
	defer func() { result.NextActor = actor }()
	seen := map[string]bool{}
	record := func(event Event) error {
		if e.Record != nil {
			return e.Record(ctx, binding, event)
		}
		return nil
	}
	defer func() {
		outcome := "completed"
		if err != nil {
			outcome = "failed"
		}
		if ctx.Err() != nil {
			outcome = "cancelled"
		}
		// Recording may need to persist a cancellation after its request context ends.
		if e.Record != nil {
			finalCtx, done := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			defer done()
			_ = e.Record(finalCtx, binding, Event{Stage: "execution_end", Outcome: outcome})
		}
	}()
	for step := 0; step < budget.Steps; step++ {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		request["input"], _ = json.Marshal(input)
		requestBody, marshalErr := json.Marshal(request)
		if marshalErr != nil {
			return result, marshalErr
		}
		if len(requestBody) > budget.MaxBytes {
			return result, ErrBudget
		}
		var calls []Call
		if actor == "jev" {
			candidates := requestedCandidates(tools, request["tool_choice"], 64)
			// Long contexts use native base-model context management. Never truncate
			// the user's context to fit the decision model.
			if e.Choose == nil || len(candidates) == 0 || len(requestBody) > 32<<10 || result.JevCalls >= budget.JevCalls {
				result.Fallback = "base_required"
				actor = "base"
				continue
			}
			if err = record(Event{Stage: "decision_start", Actor: "jev"}); err != nil {
				return result, err
			}
			choice, chooseErr := e.Choose(ctx, binding, requestBody, candidates)
			result.JevCalls++
			if choice.InputTokens < 0 || choice.OutputTokens < 0 {
				return result, errors.New("j_invalid_usage")
			}
			result.JevInputTokens += choice.InputTokens
			result.JevOutputTokens += choice.OutputTokens
			outcome := "selected"
			if chooseErr != nil || math.IsNaN(choice.Confidence) || choice.Confidence < 0.75 || choice.Confidence > 1 {
				outcome = "base_fallback"
			}
			if err = record(Event{Stage: "decision", Actor: "jev", Outcome: outcome, InputTokens: choice.InputTokens, OutputTokens: choice.OutputTokens}); err != nil {
				return result, err
			}
			if chooseErr != nil || math.IsNaN(choice.Confidence) || choice.Confidence < 0.75 || choice.Confidence > 1 || choice.Candidate == "base" {
				result.Fallback = outcome
				actor = "base"
				continue
			}
			for _, candidate := range candidates {
				if candidate.ID == choice.Candidate {
					call := candidate.Call
					call.ID = "call_" + uuid.NewString()
					calls = []Call{call}
					break
				}
			}
			if len(calls) == 0 {
				result.Fallback = "invalid_choice"
				actor = "base"
				continue
			}
			if e.GuardCall != nil {
				if err = e.GuardCall(ctx, binding, declared[calls[0].Name], calls[0]); err != nil {
					return result, err
				}
			}
			input = append(input, callItem(calls[0]))
		} else {
			if result.BaseCalls >= budget.BaseCalls {
				return result, ErrBudget
			}
			baseRequest := cloneRequest(request)
			if e.Choose != nil {
				var rawTools []json.RawMessage
				_ = json.Unmarshal(baseRequest["tools"], &rawTools)
				handoff, _ := json.Marshal(Tool{Type: "function", Name: HandoffTool, Description: "Hand the next finite tool-selection phase to Jev when existing enum choices suffice. Do not use this to answer the user or to grant permissions.", Parameters: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`)})
				rawTools = append(rawTools, handoff)
				baseRequest["tools"], _ = json.Marshal(rawTools)
			}
			baseBody, _ := json.Marshal(baseRequest)
			if err = record(Event{Stage: "model_call_start", Actor: "base", Model: binding.BaseModel}); err != nil {
				return result, err
			}
			response, baseErr := e.Base(ctx, binding, baseBody)
			result.BaseCalls++
			if response.InputTokens < 0 || response.OutputTokens < 0 {
				return result, errors.New("j_invalid_usage")
			}
			result.BaseInputTokens += response.InputTokens
			result.BaseOutputTokens += response.OutputTokens
			if err = record(Event{Stage: "model_call", Actor: "base", Model: response.ActualModel, CallID: response.RequestID, InputTokens: response.InputTokens, OutputTokens: response.OutputTokens}); err != nil {
				return result, err
			}
			if baseErr != nil {
				return result, baseErr
			}
			if response.ActualModel != binding.BaseModel {
				return result, ErrModel
			}
			var envelope struct {
				Model  string            `json:"model"`
				Status string            `json:"status"`
				Output []json.RawMessage `json:"output"`
			}
			if len(response.Body) > budget.MaxBytes || json.Unmarshal(response.Body, &envelope) != nil || envelope.Model != binding.BaseModel || envelope.Status != "completed" {
				return result, errors.New("j_incomplete_base_response")
			}
			for _, item := range envelope.Output {
				var value struct {
					Type  string `json:"type"`
					Input string `json:"input"`
					Call
				}
				if json.Unmarshal(item, &value) != nil {
					return result, ErrTool
				}
				if value.Type == "custom_tool_call" {
					tool, exists := declared[value.Name]
					if e.Tools != nil || !exists || tool.Type != "custom" {
						return result, ErrTool
					}
				}
				if (value.Type == "function_call" || value.Type == "custom_tool_call") && value.Name != HandoffTool && e.GuardCall != nil {
					call := value.Call
					if value.Type == "custom_tool_call" {
						call.Arguments = value.Input
					}
					if err = e.GuardCall(ctx, binding, declared[value.Name], call); err != nil {
						return result, err
					}
				}
				if value.Type == "function_call" {
					calls = append(calls, value.Call)
				}
			}
			if len(calls) == 0 {
				result.Response = response.Body
				result.History = append(input, envelope.Output...)
				return result, nil
			} // No second polishing call.
			input = append(input, envelope.Output...)
			if len(calls) == 1 && calls[0].Name == HandoffTool {
				if strings.TrimSpace(calls[0].Arguments) != "{}" {
					return result, ErrTool
				}
				input = append(input, outputItem(calls[0].ID, json.RawMessage(`{"status":"handoff_accepted"}`)))
				actor = "jev"
				continue
			}
			if e.Tools == nil { // Ordinary Responses clients execute their own functions.
				for _, call := range calls {
					if _, ok := declared[call.Name]; !ok {
						return result, ErrTool
					}
				}
				result.Response = response.Body
				result.History = input
				return result, nil
			}
		}
		if e.Tools == nil {
			result.History = input
			result.Response, _ = json.Marshal(map[string]any{"id": "resp_" + uuid.NewString(), "object": "response", "status": "completed", "model": binding.BaseModel, "output": []json.RawMessage{callItem(calls[0])}, "usage": map[string]int{"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}})
			return result, nil
		}
		if result.ToolCalls+len(calls) > budget.Steps {
			return result, ErrBudget
		}
		// Authorize the entire batch before any tool can have an effect.
		for _, call := range calls {
			tool, ok := declared[call.Name]
			if !ok || call.ID == "" || seen[call.ID] || !json.Valid([]byte(call.Arguments)) {
				return result, ErrTool
			}
			if err = e.Tools.Authorize(ctx, binding, tool, call); err != nil {
				return result, err
			}
			seen[call.ID] = true
		}
		for _, call := range calls {
			if err = ctx.Err(); err != nil {
				return result, err
			}
			if err = record(Event{Stage: "tool_dispatch", Actor: actor, CallID: call.ID, Tool: call.Name}); err != nil {
				return result, err
			}
			output, runErr := e.Tools.Run(ctx, binding, call)
			result.ToolCalls++
			if runErr != nil {
				return result, fmt.Errorf("%w: %w", ErrUnknownOutcome, runErr)
			}
			if len(output) > budget.MaxBytes || !json.Valid(output) {
				return result, errors.New("j_invalid_tool_result")
			}
			if e.GuardResult != nil {
				if err = e.GuardResult(ctx, binding, call, output); err != nil {
					return result, err
				}
			}
			if err = record(Event{Stage: "tool_result", Actor: actor, CallID: call.ID, Tool: call.Name, Outcome: "completed"}); err != nil {
				return result, err
			}
			input = append(input, outputItem(call.ID, output))
		}
		// Deliberately keep the current actor after tool results. A base-owned
		// tool phase does not run Jev again unless the base explicitly hands off.
	}
	return result, ErrBudget
}

func inputItems(raw json.RawMessage) ([]json.RawMessage, error) {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		item, _ := json.Marshal(map[string]string{"role": "user", "content": text})
		return []json.RawMessage{item}, nil
	}
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return nil, errors.New("j_input_required")
	}
	return items, nil
}
func callItem(call Call) json.RawMessage {
	raw, _ := json.Marshal(struct {
		Type   string `json:"type"`
		ItemID string `json:"id"`
		Status string `json:"status"`
		Call
	}{"function_call", "fc_" + call.ID, "completed", call})
	return raw
}
func outputItem(id string, output json.RawMessage) json.RawMessage {
	raw, _ := json.Marshal(map[string]string{"type": "function_call_output", "call_id": id, "output": string(output)})
	return raw
}
func cloneRequest(in map[string]json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// Never override the caller's explicit function selection or tool prohibition.
func requestedCandidates(tools []Tool, raw json.RawMessage, limit int) []Candidate {
	var choice string
	if json.Unmarshal(raw, &choice) == nil {
		if choice == "none" {
			return nil
		}
		if choice != "auto" && choice != "required" {
			return nil
		}
	} else if len(raw) > 0 && string(raw) != "null" {
		var selected struct {
			Type string `json:"type"`
			Name string `json:"name"`
		}
		if json.Unmarshal(raw, &selected) != nil || selected.Type != "function" || selected.Name == "" {
			return nil
		}
		filtered := []Tool{}
		for _, tool := range tools {
			if tool.Name == selected.Name {
				filtered = append(filtered, tool)
			}
		}
		tools = filtered
	}
	return FiniteCandidates(tools, limit)
}
