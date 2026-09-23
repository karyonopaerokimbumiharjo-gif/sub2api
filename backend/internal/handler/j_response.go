package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Serialize a verified terminal response using the same incremental lifecycle
// as Responses. Added items are empty: delta consumers must not see text twice.
func writeJResponse(c *gin.Context, raw []byte, model string, stream bool) error {
	var body map[string]any
	if json.Unmarshal(raw, &body) != nil || body["status"] != "completed" {
		return errors.New("j_invalid_response")
	}
	if body["id"] == nil {
		body["id"] = "resp_" + uuid.NewString()
	}
	body["model"] = model
	items, _ := body["output"].([]any)
	for _, item := range items {
		if obj, ok := item.(map[string]any); ok {
			if obj["id"] == nil {
				obj["id"] = "item_" + uuid.NewString()
			}
			obj["status"] = "completed"
		}
	}
	if !stream {
		c.JSON(http.StatusOK, body)
		return nil
	}
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	sequence := 0
	emit := func(kind string, value map[string]any) error {
		value["type"], value["sequence_number"] = kind, sequence
		sequence++
		wire, err := json.Marshal(value)
		if err != nil {
			return err
		}
		_, err = c.Writer.Write(append(append([]byte("event: "+kind+"\ndata: "), wire...), '\n', '\n'))
		c.Writer.Flush()
		return err
	}
	initial := cloneJObject(body)
	initial["status"], initial["output"], initial["usage"] = "in_progress", []any{}, nil
	for _, kind := range []string{"response.created", "response.in_progress"} {
		if err := emit(kind, map[string]any{"response": initial}); err != nil {
			return err
		}
	}
	for i, item := range items {
		obj, ok := item.(map[string]any)
		if !ok {
			return errors.New("j_invalid_output_item")
		}
		added := cloneJObject(obj)
		added["status"] = "in_progress"
		switch obj["type"] {
		case "message":
			added["content"] = []any{}
		case "function_call":
			added["arguments"] = ""
		case "custom_tool_call":
			added["input"] = ""
		}
		if err := emit("response.output_item.added", map[string]any{"output_index": i, "item": added}); err != nil {
			return err
		}
		if obj["type"] == "function_call" || obj["type"] == "custom_tool_call" {
			field, event := "arguments", "function_call_arguments"
			if obj["type"] == "custom_tool_call" {
				field, event = "input", "custom_tool_call_input"
			}
			for _, stage := range []string{"delta", "done"} {
				value := map[string]any{"output_index": i, "item_id": obj["id"]}
				if stage == "delta" {
					value["delta"] = obj[field]
				} else {
					value[field], value["name"], value["call_id"] = obj[field], obj["name"], obj["call_id"]
				}
				if err := emit("response."+event+"."+stage, value); err != nil {
					return err
				}
			}
		}
		if obj["type"] == "message" {
			parts, _ := obj["content"].([]any)
			for j, part := range parts {
				objPart, ok := part.(map[string]any)
				if !ok {
					return errors.New("j_invalid_content_part")
				}
				startPart := cloneJObject(objPart)
				field, event := "text", "output_text"
				if objPart["type"] == "refusal" {
					field, event = "refusal", "refusal"
				}
				startPart[field] = ""
				value := func() map[string]any {
					return map[string]any{"output_index": i, "content_index": j, "item_id": obj["id"]}
				}
				v := value()
				v["part"] = startPart
				if err := emit("response.content_part.added", v); err != nil {
					return err
				}
				v = value()
				v["delta"] = objPart[field]
				if err := emit("response."+event+".delta", v); err != nil {
					return err
				}
				v = value()
				v[field] = objPart[field]
				if err := emit("response."+event+".done", v); err != nil {
					return err
				}
				v = value()
				v["part"] = objPart
				if err := emit("response.content_part.done", v); err != nil {
					return err
				}
			}
		}
		if err := emit("response.output_item.done", map[string]any{"output_index": i, "item": obj}); err != nil {
			return err
		}
	}
	return emit("response.completed", map[string]any{"response": body})
}

func cloneJObject(value map[string]any) map[string]any {
	out := make(map[string]any, len(value))
	for k, v := range value {
		out[k] = v
	}
	return out
}
