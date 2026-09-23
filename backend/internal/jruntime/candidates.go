package jruntime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
)

// FiniteCandidates only expands explicit enums/consts in flat object schemas.
// Unsupported or open-ended schemas belong to the base model, never guessed
// arguments. The tool authority must still validate a chosen call at dispatch.
func FiniteCandidates(tools []Tool, limit int) []Candidate {
	if limit < 1 || limit > 128 {
		limit = 64
	}
	var out []Candidate
	for _, tool := range tools {
		if tool.Type != "function" || tool.Name == "" || tool.Name == HandoffTool {
			continue
		}
		var schema struct {
			Type                 string                     `json:"type"`
			Properties           map[string]json.RawMessage `json:"properties"`
			Required             []string                   `json:"required"`
			AdditionalProperties any                        `json:"additionalProperties"`
		}
		if validateJSON(tool.Parameters) != nil || json.Unmarshal(tool.Parameters, &schema) != nil || schema.Type != "object" || schema.AdditionalProperties != false {
			continue
		}
		var rawSchema map[string]json.RawMessage
		_ = json.Unmarshal(tool.Parameters, &rawSchema)
		unsupported := false
		for k := range rawSchema {
			if k != "type" && k != "properties" && k != "required" && k != "additionalProperties" && k != "description" && k != "title" {
				unsupported = true
			}
		}
		if unsupported {
			continue
		}
		keys := make([]string, 0, len(schema.Properties))
		for k := range schema.Properties {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		required := map[string]bool{}
		for _, k := range schema.Required {
			if _, ok := schema.Properties[k]; !ok {
				unsupported = true
			}
			required[k] = true
		}
		args := []map[string]json.RawMessage{{}}
		for _, key := range keys {
			var property map[string]json.RawMessage
			if json.Unmarshal(schema.Properties[key], &property) != nil {
				unsupported = true
				break
			}
			// Validation keywords beyond these require a real schema evaluator;
			// leave them to the base/tool authority instead of approximating them.
			for k := range property {
				if k != "type" && k != "enum" && k != "const" && k != "description" && k != "title" {
					unsupported = true
				}
			}
			var values []json.RawMessage
			if constant, ok := property["const"]; ok {
				values = []json.RawMessage{constant}
			} else {
				_ = json.Unmarshal(property["enum"], &values)
			}
			if len(values) == 0 {
				if required[key] {
					unsupported = true
				}
				continue
			}
			for _, value := range values {
				if !finiteValueMatches(property, value) {
					unsupported = true
				}
			}
			if unsupported {
				break
			}
			if len(args)*(len(values)+1) > limit*2 {
				unsupported = true
				break
			}
			var next []map[string]json.RawMessage
			for _, arg := range args {
				if !required[key] {
					next = append(next, arg)
				}
				for _, value := range values {
					copy := make(map[string]json.RawMessage, len(arg)+1)
					for k, v := range arg {
						copy[k] = v
					}
					copy[key] = value
					next = append(next, copy)
				}
			}
			if len(next) > limit {
				unsupported = true
				break
			}
			args = next
		}
		if unsupported || len(out)+len(args) > limit {
			continue
		}
		for _, arg := range args {
			raw, err := json.Marshal(arg)
			if err != nil {
				continue
			}
			out = append(out, Candidate{ID: fmt.Sprintf("tool_%d", len(out)), Call: Call{Name: tool.Name, Arguments: string(raw)}})
		}
	}
	return out
}

func finiteValueMatches(property map[string]json.RawMessage, raw json.RawMessage) bool {
	var kind string
	if json.Unmarshal(property["type"], &kind) != nil {
		return false
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	switch kind {
	case "string":
		if _, ok := value.(string); !ok {
			return false
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return false
		}
	case "number", "integer":
		n, ok := value.(float64)
		if !ok || (kind == "integer" && math.Trunc(n) != n) {
			return false
		}
	case "null":
		if value != nil {
			return false
		}
	default:
		return false
	}
	if enum, exists := property["enum"]; exists {
		var values []json.RawMessage
		if json.Unmarshal(enum, &values) != nil {
			return false
		}
		found := false
		for _, candidate := range values {
			var v any
			if json.Unmarshal(candidate, &v) != nil {
				return false
			}
			lhs, _ := json.Marshal(v)
			rhs, _ := json.Marshal(value)
			if bytes.Equal(lhs, rhs) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
