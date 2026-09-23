package jruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var fixtureTool = Tool{Type: "function", Name: "check_job", Parameters: json.RawMessage(`{"type":"object","properties":{"job":{"type":"string","enum":["job-a"]}},"required":["job"],"additionalProperties":false}`)}

func fixtureBinding(model string) Binding {
	return Binding{UserID: 1, KeyID: 2, AccountID: 3, SessionID: "session", TaskID: "task", BaseModel: model}
}
func fixtureBody() []byte {
	raw, _ := json.Marshal(map[string]any{"model": "public-j", "input": "Check job until done, then answer naturally.", "tools": []Tool{fixtureTool}})
	return raw
}
func fixtureResponse(model string, items ...map[string]any) BaseResult {
	if len(items) == 0 {
		items = []map[string]any{{"type": "message", "role": "assistant", "content": []map[string]string{{"type": "output_text", "text": "The job is finished."}}}}
	}
	raw, _ := json.Marshal(map[string]any{"model": model, "status": "completed", "output": items})
	return BaseResult{Body: raw, ActualModel: model, InputTokens: 10, OutputTokens: 3}
}

type fixtureRunner struct {
	authorize func(Binding, Tool, Call) error
	run       func(context.Context, Binding, Call) (json.RawMessage, error)
	calls     int
}

func (r *fixtureRunner) Authorize(_ context.Context, b Binding, t Tool, c Call) error {
	if r.authorize != nil {
		return r.authorize(b, t, c)
	}
	return nil
}
func (r *fixtureRunner) Run(ctx context.Context, b Binding, c Call) (json.RawMessage, error) {
	r.calls++
	if r.run != nil {
		return r.run(ctx, b, c)
	}
	return json.RawMessage(`{"status":"done"}`), nil
}

func TestJevOwnsDependentToolsThenSelectedBaseAnswersOnce(t *testing.T) {
	for _, model := range []string{"gpt-6-astra", "gpt-5.6-sol"} {
		t.Run(model, func(t *testing.T) {
			runner := &fixtureRunner{}
			decisions := 0
			baseCalls := 0
			e := Engine{Record: fixtureRecord, Tools: runner, Choose: func(_ context.Context, b Binding, body json.RawMessage, candidates []Candidate) (Choice, error) {
				require.Equal(t, model, b.BaseModel)
				decisions++
				if decisions > 1 {
					require.Contains(t, string(body), "function_call_output")
				}
				if decisions < 3 {
					return Choice{Candidate: candidates[0].ID, Confidence: 0.95, InputTokens: 2, OutputTokens: 1}, nil
				}
				return Choice{Candidate: "base", Confidence: 1, InputTokens: 2, OutputTokens: 1}, nil
			}, Base: func(_ context.Context, b Binding, body json.RawMessage) (BaseResult, error) {
				baseCalls++
				require.Contains(t, string(body), "function_call_output")
				return fixtureResponse(b.BaseModel), nil
			}}
			result, err := e.Run(context.Background(), fixtureBinding(model), fixtureBody())
			require.NoError(t, err)
			require.Equal(t, 2, runner.calls)
			require.Equal(t, 1, baseCalls)
			require.Equal(t, 3, result.JevCalls)
			require.EqualValues(t, 6, result.JevInputTokens)
			require.EqualValues(t, 10, result.BaseInputTokens)
			require.Contains(t, string(result.Response), "The job is finished.")
		})
	}
}

func TestBaseOwnsToolsUntilExplicitHandoffAndNeverGetsPolished(t *testing.T) {
	var actors []string
	runner := &fixtureRunner{}
	decisions, bases := 0, 0
	engine := Engine{Record: fixtureRecord, Tools: runner, Choose: func(context.Context, Binding, json.RawMessage, []Candidate) (Choice, error) {
		decisions++
		actors = append(actors, "jev")
		if decisions == 2 {
			return Choice{Candidate: "tool_0", Confidence: 1}, nil
		}
		return Choice{Candidate: "base", Confidence: 1}, nil
	}, Base: func(_ context.Context, b Binding, _ json.RawMessage) (BaseResult, error) {
		bases++
		actors = append(actors, "base")
		switch bases {
		case 1:
			return fixtureResponse(b.BaseModel, map[string]any{"type": "function_call", "call_id": "base-tool", "name": "check_job", "arguments": `{"job":"job-a"}`}), nil
		case 2:
			return fixtureResponse(b.BaseModel, map[string]any{"type": "function_call", "call_id": "handoff", "name": HandoffTool, "arguments": "{}"}), nil
		}
		return fixtureResponse(b.BaseModel), nil
	}}
	_, err := engine.Run(context.Background(), fixtureBinding("gpt-6-astra"), fixtureBody())
	require.NoError(t, err)
	require.Equal(t, []string{"jev", "base", "base", "jev", "jev", "base"}, actors)
	require.Equal(t, 2, runner.calls)
}

func TestToolBatchIsAuthorizedBeforeAnyExecution(t *testing.T) {
	runner := &fixtureRunner{authorize: func(_ Binding, _ Tool, c Call) error {
		if c.ID == "denied" {
			return ErrTool
		}
		return nil
	}}
	engine := Engine{Record: fixtureRecord, Tools: runner, Base: func(_ context.Context, b Binding, _ json.RawMessage) (BaseResult, error) {
		return fixtureResponse(b.BaseModel,
			map[string]any{"type": "function_call", "call_id": "allowed", "name": "check_job", "arguments": "{}"},
			map[string]any{"type": "function_call", "call_id": "denied", "name": "check_job", "arguments": "{}"}), nil
	}}
	_, err := engine.Run(context.Background(), fixtureBinding("gpt-6-astra"), fixtureBody())
	require.ErrorIs(t, err, ErrTool)
	require.Zero(t, runner.calls)
}

func TestUnknownToolOutcomeIsTerminalWithoutReplay(t *testing.T) {
	runner := &fixtureRunner{run: func(context.Context, Binding, Call) (json.RawMessage, error) {
		return nil, errors.New("connection lost after dispatch")
	}}
	engine := Engine{Record: fixtureRecord, Tools: runner, Choose: func(context.Context, Binding, json.RawMessage, []Candidate) (Choice, error) {
		return Choice{Candidate: "tool_0", Confidence: 1}, nil
	}, Base: func(context.Context, Binding, json.RawMessage) (BaseResult, error) {
		t.Fatal("must not replay through base")
		return BaseResult{}, nil
	}}
	_, err := engine.Run(context.Background(), fixtureBinding("gpt-6-astra"), fixtureBody())
	require.ErrorIs(t, err, ErrUnknownOutcome)
	require.Equal(t, 1, runner.calls)
}

func TestControllerUncertaintyHandsOffWithoutInventingArguments(t *testing.T) {
	for _, choice := range []Choice{{Candidate: "not-declared", Confidence: 1}, {Candidate: "tool_0", Confidence: 0.2}} {
		runner := &fixtureRunner{}
		engine := Engine{Record: fixtureRecord, Tools: runner, Choose: func(context.Context, Binding, json.RawMessage, []Candidate) (Choice, error) { return choice, nil }, Base: func(_ context.Context, b Binding, _ json.RawMessage) (BaseResult, error) {
			return fixtureResponse(b.BaseModel), nil
		}}
		result, err := engine.Run(context.Background(), fixtureBinding("gpt-5.6-sol"), fixtureBody())
		require.NoError(t, err)
		require.Zero(t, runner.calls)
		require.Equal(t, 1, result.BaseCalls)
	}
}

func TestActualModelMismatchNeverBecomesSuccessfulJResponse(t *testing.T) {
	engine := Engine{Base: func(context.Context, Binding, json.RawMessage) (BaseResult, error) {
		return fixtureResponse("gpt-5.6-luna"), nil
	}}
	result, err := engine.Run(context.Background(), fixtureBinding("gpt-6-astra"), fixtureBody())
	require.ErrorIs(t, err, ErrModel)
	require.Empty(t, result.Response)
}

func TestBudgetCancellationAndDurableDispatchFailure(t *testing.T) {
	for _, mode := range []string{"budget", "cancel", "journal"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runner := &fixtureRunner{}
			budget := DefaultBudget()
			budget.Steps = 2
			engine := Engine{Record: fixtureRecord, Tools: runner, Budget: budget, Choose: func(context.Context, Binding, json.RawMessage, []Candidate) (Choice, error) {
				return Choice{Candidate: "tool_0", Confidence: 1}, nil
			}, Base: func(context.Context, Binding, json.RawMessage) (BaseResult, error) { return BaseResult{}, nil }}
			switch mode {
			case "cancel":
				cancel()
			case "journal":
				engine.Record = func(_ context.Context, _ Binding, e Event) error {
					if e.Stage == "tool_dispatch" {
						return errors.New("journal unavailable")
					}
					return nil
				}
			}
			_, err := engine.Run(ctx, fixtureBinding("gpt-6-astra"), fixtureBody())
			require.Error(t, err)
			if mode == "budget" {
				require.ErrorIs(t, err, ErrBudget)
				require.Equal(t, 2, runner.calls)
			} else {
				require.Zero(t, runner.calls)
			}
		})
	}
}

func TestOrdinaryResponsesClientReceivesStandardToolCall(t *testing.T) {
	engine := Engine{Choose: func(context.Context, Binding, json.RawMessage, []Candidate) (Choice, error) {
		return Choice{Candidate: "tool_0", Confidence: 1}, nil
	}, Base: func(context.Context, Binding, json.RawMessage) (BaseResult, error) {
		return BaseResult{}, errors.New("must not call base")
	}}
	result, err := engine.Run(context.Background(), fixtureBinding("gpt-6-astra"), fixtureBody())
	require.NoError(t, err)
	require.Contains(t, string(result.Response), "function_call")
	require.Zero(t, result.BaseCalls)
}

func TestFiniteCandidatesRejectsOpenEndedAndCombinatorialSchemas(t *testing.T) {
	candidates := FiniteCandidates([]Tool{fixtureTool}, 64)
	require.Len(t, candidates, 1)
	require.JSONEq(t, `{"job":"job-a"}`, candidates[0].Call.Arguments)
	for _, schema := range []string{`{"type":"object","properties":{"code":{"type":"string"}},"required":["code"],"additionalProperties":false}`, `{"type":"object","additionalProperties":true}`, `{"type":"object","additionalProperties":false,"oneOf":[]}`} {
		tool := fixtureTool
		tool.Parameters = json.RawMessage(schema)
		require.Empty(t, FiniteCandidates([]Tool{tool}, 64))
	}
	properties := []string{}
	for i := 0; i < 10; i++ {
		properties = append(properties, fmt.Sprintf(`"p%d":{"type":"string","enum":["a","b"]}`, i))
	}
	tool := fixtureTool
	tool.Parameters = json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{` + strings.Join(properties, ",") + `}}`)
	require.Empty(t, FiniteCandidates([]Tool{tool}, 64))
}

func fixtureRecord(context.Context, Binding, Event) error { return nil }

func TestJRequiresJournalBeforeEffects(t *testing.T) {
	e := Engine{Tools: &fixtureRunner{}, Base: func(context.Context, Binding, json.RawMessage) (BaseResult, error) {
		t.Fatal("must not call")
		return BaseResult{}, nil
	}}
	_, err := e.Run(context.Background(), fixtureBinding("gpt-5.6-sol"), fixtureBody())
	require.EqualError(t, err, "j_journal_required")
}
func TestFiniteCandidatesValidateTypesAndCallerChoice(t *testing.T) {
	for _, property := range []string{`{"type":"string","enum":[1]}`, `{"type":"string","const":"a","enum":["b"]}`, `{"type":"integer","enum":[1.5]}`, `{"type":"array","enum":[[]]}`} {
		tool := fixtureTool
		tool.Parameters = json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"x":` + property + `},"required":["x"]}`)
		require.Empty(t, FiniteCandidates([]Tool{tool}, 64))
	}
	require.Empty(t, requestedCandidates([]Tool{fixtureTool}, json.RawMessage(`"none"`), 64))
	require.Empty(t, requestedCandidates([]Tool{fixtureTool}, json.RawMessage(`{"type":"function","name":"different"}`), 64))
	require.Len(t, requestedCandidates([]Tool{fixtureTool}, json.RawMessage(`{"type":"function","name":"check_job"}`), 64), 1)
}

func TestJActionGuardRejectsBeforeClientOrBridgeExecution(t *testing.T) {
	for _, bridge := range []bool{false, true} {
		runner := &fixtureRunner{}
		e := Engine{Record: fixtureRecord, InitialActor: "base", Base: func(_ context.Context, b Binding, _ json.RawMessage) (BaseResult, error) {
			return fixtureResponse(b.BaseModel, map[string]any{"type": "function_call", "name": "check_job", "call_id": "guarded", "arguments": `{"job":"job-a"}`}), nil
		}, GuardCall: func(context.Context, Binding, Tool, Call) error { return errors.New("safety_rejected") }}
		if bridge {
			e.Tools = runner
		}
		result, err := e.Run(context.Background(), fixtureBinding("gpt-5.6-sol"), fixtureBody())
		require.ErrorContains(t, err, "safety_rejected")
		require.Zero(t, runner.calls)
		require.Empty(t, result.Response)
	}
}
func TestJResultGuardPreventsUnsafeToolResultConsumption(t *testing.T) {
	runner := &fixtureRunner{}
	base := 0
	e := Engine{Record: fixtureRecord, InitialActor: "base", Tools: runner, Base: func(_ context.Context, b Binding, _ json.RawMessage) (BaseResult, error) {
		base++
		return fixtureResponse(b.BaseModel, map[string]any{"type": "function_call", "name": "check_job", "call_id": "guarded", "arguments": `{"job":"job-a"}`}), nil
	}, GuardResult: func(context.Context, Binding, Call, json.RawMessage) error {
		return errors.New("result_safety_rejected")
	}}
	result, err := e.Run(context.Background(), fixtureBinding("gpt-5.6-sol"), fixtureBody())
	require.ErrorContains(t, err, "result_safety_rejected")
	require.Equal(t, 1, runner.calls)
	require.Equal(t, 1, base)
	require.Empty(t, result.Response)
}
