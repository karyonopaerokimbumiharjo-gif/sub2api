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
	message := "Pi rejected the request format"
	if status == http.StatusConflict {
		message = "Pi session is busy; retry after the active request finishes"
	}
	var failure struct {
		Error string `json:"error"`
	}
	if resp.Body != nil {
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&failure)
	}
	switch failure.Error {
	case "unsupported_pi_tool_type":
		message = "Pi does not support a tool type declared in this request"
	case "invalid_pi_tools":
		message = "Pi requires tools to be an array of tool definitions"
	case "unsupported_pi_field", "unsupported_pi_field:max_output_tokens":
		message = "Pi request contains an unsupported parameter"
	case "model_required":
		message = "Model is required"
	case "input_required":
		message = "Pi requires input as text or a Responses input array"
	case "invalid_responses_request":
		message = "Invalid Responses request"
	case "oauth_account_mismatch":
		status = http.StatusBadGateway
		message = "Pi credential account binding mismatch; reauthorize this account"
	}
	return &nativePiRequestError{status: status, message: message}
}
