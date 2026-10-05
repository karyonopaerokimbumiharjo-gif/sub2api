package service

import (
	"encoding/json"
	"io"
	"net/http"
)

// Read only runtime-owned codes. Never pass a provider message, request body,
// credential, or arbitrary field name back to a client or operations log.
func nativePiClientRequestError(resp *http.Response) *nativePiRequestError {
	status := resp.StatusCode
	message := "The selected execution backend rejected the request format"
	if status == http.StatusConflict {
		message = "The selected execution backend session is busy; retry after the active request finishes"
	}
	if status == http.StatusRequestEntityTooLarge {
		message = "The request exceeds the selected execution backend's size limit; reduce attachments or conversation history"
	}
	var failure struct {
		Error string `json:"error"`
	}
	if resp.Body != nil {
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&failure)
	}
	switch failure.Error {
	case "unsupported_pi_tool_type":
		message = "The selected execution backend does not support a tool type in this request; remove that tool or use a compatible backend"
	case "invalid_pi_tools":
		message = "The selected execution backend requires tools to be an array of tool definitions"
	case "unsupported_pi_field", "unsupported_pi_field:max_output_tokens":
		message = "The request contains a parameter unsupported by the selected execution backend"
	case "model_required":
		message = "Model is required"
	case "input_required":
		message = "The selected execution backend requires input as text or a Responses input array"
	case "invalid_responses_request":
		message = "Invalid Responses request"
	case "oauth_account_mismatch":
		status = http.StatusBadGateway
		message = "The execution account binding mismatch requires reauthorization"
	}
	return &nativePiRequestError{status: status, message: message}
}
