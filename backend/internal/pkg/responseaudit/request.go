package responseaudit

import (
	"encoding/json"
	"net/http"
)

type Metadata struct {
	Present     bool     `json:"present"`
	ValidObject bool     `json:"valid_object"`
	IDsPresent  []string `json:"ids_present"`
}
type Request struct {
	Originator                string   `json:"originator"`
	UserAgentFamily           string   `json:"user_agent_family"`
	VersionPresent            bool     `json:"version_present"`
	HeaderMetadata            Metadata `json:"header_metadata"`
	BodyMetadata              Metadata `json:"body_metadata"`
	BodyObserved              bool     `json:"body_observed"`
	Model                     string   `json:"model"`
	Stream                    bool     `json:"stream"`
	Store                     *bool    `json:"store"`
	PreviousResponseIDPresent bool     `json:"previous_response_id_present"`
	SessionHeaderPresent      bool     `json:"session_header_present"`
	RequestIDHeaderPresent    bool     `json:"request_id_header_present"`
	CacheKeyPresent           bool     `json:"cache_key_present"`
}

func metadata(raw string, present bool) Metadata {
	result := Metadata{Present: present, IDsPresent: []string{}}
	if !present || len(raw) > 16384 {
		return result
	}
	var value map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &value) != nil || value == nil {
		return result
	}
	result.ValidObject = true
	for _, key := range []string{"installation_id", "session_id", "thread_id", "turn_id", "window_id"} {
		if _, ok := value[key]; ok {
			result.IDsPresent = append(result.IDsPresent, key)
		}
	}
	return result
}
func InspectRequest(h http.Header, body []byte) Request {
	originator := h.Get("originator")
	switch originator {
	case "":
		originator = "absent"
	case "pi", "codex-tui", "codex_cli_rs":
	default:
		originator = "other"
	}
	family := "other"
	ua := h.Get("User-Agent")
	switch {
	case ua == "":
		family = "absent"
	case len(ua) >= 3 && ua[:3] == "pi/":
		family = "pi"
	case len(ua) >= 5 && ua[:5] == "codex":
		family = "codex"
	}
	_, headerPresent := h[http.CanonicalHeaderKey("x-codex-turn-metadata")]
	result := Request{Originator: originator, UserAgentFamily: family, VersionPresent: h.Get("version") != "",
		HeaderMetadata: metadata(h.Get("x-codex-turn-metadata"), headerPresent), BodyMetadata: metadata("", false),
		SessionHeaderPresent: h.Get("session-id") != "" || h.Get("session_id") != "", RequestIDHeaderPresent: h.Get("x-client-request-id") != ""}
	var value struct {
		Model              string                     `json:"model"`
		Stream             bool                       `json:"stream"`
		Store              *bool                      `json:"store"`
		PreviousResponseID string                     `json:"previous_response_id"`
		CacheKey           string                     `json:"prompt_cache_key"`
		ClientMetadata     map[string]json.RawMessage `json:"client_metadata"`
	}
	if len(body) == 0 || json.Unmarshal(body, &value) != nil {
		return result
	}
	result.BodyObserved = true
	result.Stream = value.Stream
	result.Store = value.Store
	if validModel(value.Model) {
		result.Model = value.Model
	}
	result.PreviousResponseIDPresent = value.PreviousResponseID != ""
	result.CacheKeyPresent = value.CacheKey != ""
	if raw, ok := value.ClientMetadata["x-codex-turn-metadata"]; ok {
		var text string
		_ = json.Unmarshal(raw, &text)
		result.BodyMetadata = metadata(text, true)
	}
	return result
}
