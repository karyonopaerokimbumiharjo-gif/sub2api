// Package executiontrace keeps bounded, metadata-only diagnostics for GPT-6J.
// It is intentionally ephemeral and never stores request or response bodies.
package executiontrace

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

const (
	DefaultCapacity     = 2048
	DefaultTTL          = 6 * time.Hour
	DefaultListLimit    = 100
	MaxListLimit        = 200
	maxEventsPerRequest = 32
)

type Event struct {
	EventsDropped      int     `json:"events_dropped,omitempty"`
	ToolResultsSeen    int     `json:"tool_results_seen,omitempty"`
	ToolResultsOmitted int     `json:"tool_results_omitted,omitempty"`
	HistorySample      bool    `json:"history_sample,omitempty"`
	Time               int64   `json:"time"`
	RequestID          string  `json:"request_id"`
	Stage              string  `json:"stage"`
	AccountID          int64   `json:"account_id,omitempty"`
	Model              string  `json:"model,omitempty"`
	ActualModel        string  `json:"actual_model,omitempty"`
	ResponseID         string  `json:"response_id,omitempty"`
	Tool               string  `json:"tool,omitempty"`
	CallID             string  `json:"call_id,omitempty"`
	Reason             string  `json:"reason,omitempty"`
	Status             int     `json:"status,omitempty"`
	DurationMS         int64   `json:"duration_ms,omitempty"`
	Confidence         float64 `json:"confidence,omitempty"`
	Probability        float64 `json:"probability,omitempty"`
}

type Store struct {
	mu       sync.Mutex
	events   []Event
	capacity int
	ttl      time.Duration
	now      func() time.Time
}

var Default = NewStore(DefaultCapacity, DefaultTTL)

func NewStore(capacity int, ttl time.Duration) *Store {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Store{capacity: capacity, ttl: ttl, now: time.Now}
}

func (s *Store) Append(event Event) {
	if s == nil {
		return
	}
	event = sanitize(event)
	if event.RequestID == "" || event.Stage == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	count := 0
	for i := len(s.events) - 1; i >= 0; i-- {
		if s.events[i].RequestID == event.RequestID {
			count++
		}
	}
	if count >= maxEventsPerRequest {
		// Retain request identity and terminal outcomes; evict an intermediate
		// event instead. Carry its omission count forward so loss stays visible.
		replace := -1
		for i := range s.events {
			old := s.events[i]
			if old.RequestID == event.RequestID && old.Stage != "request" && old.Stage != "request_failed" && old.Stage != "request_end" {
				replace = i
				break
			}
		}
		if replace < 0 {
			return
		}
		event.EventsDropped += 1 + s.events[replace].EventsDropped
		s.events = append(s.events[:replace], s.events[replace+1:]...)
	}
	event.Time = s.now().UnixMilli()
	if len(s.events) == s.capacity {
		copy(s.events, s.events[1:])
		s.events[len(s.events)-1] = event
		return
	}
	s.events = append(s.events, event)
}

// List returns a newest-first copy. An invalid filter matches nothing.
func (s *Store) List(requestID string, limit int) []Event {
	if s == nil {
		return []Event{}
	}
	requestID = strings.TrimSpace(requestID)
	if requestID != "" && safeToken(requestID, 128) == "" {
		return []Event{}
	}
	if limit <= 0 {
		limit = DefaultListLimit
	}
	if limit > MaxListLimit {
		limit = MaxListLimit
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked()
	out := make([]Event, 0, limit)
	for i := len(s.events) - 1; i >= 0 && len(out) < limit; i-- {
		if requestID == "" || s.events[i].RequestID == requestID {
			out = append(out, s.events[i])
		}
	}
	return out
}

func (s *Store) pruneLocked() {
	cutoff := s.now().Add(-s.ttl).UnixMilli()
	first := 0
	for first < len(s.events) && s.events[first].Time < cutoff {
		first++
	}
	if first > 0 {
		s.events = append([]Event(nil), s.events[first:]...)
	}
}

var stages = map[string]bool{
	"request": true, "client_tool_result": true, "guard_result": true,
	"gpt_handoff": true, "jev_decision": true, "tool_call": true,
	"gpt_response": true, "request_failed": true, "request_end": true,
}

var reasons = map[string]bool{
	"allowed": true, "prompt_guard_blocked": true, "prompt_guard_unavailable": true,
	"prompt_guard_review_required": true, "prompt_guard_invalid_response": true,
	"prompt_audit_config_conflict": true, "prompt_audit_config_unavailable": true,
	"prompt_audit_encryption_key_required": true, "prompt_guard_requires_audit_enabled": true,
	"content_policy_violation": true, "gpt6j_guard_unavailable": true,
	"invalid_request_error": true, "upstream_error": true,
	"upstream_failed": true, "request_rejected": true, "request_failed": true,
	"model_mismatch": true, "client_disconnected": true,
}

func sanitize(event Event) Event {
	if event.Stage == "请求失败" {
		event.Stage = "request_failed"
	}
	if !stages[event.Stage] {
		event.Stage = ""
	}
	event.RequestID = safeToken(event.RequestID, 128)
	event.Model = safeToken(event.Model, 96)
	event.ActualModel = safeToken(event.ActualModel, 96)
	event.ResponseID = safeToken(event.ResponseID, 128)
	if event.ResponseID != "" && !strings.HasPrefix(event.ResponseID, "resp_") {
		event.ResponseID = ""
	}
	// Tool names and call IDs may be supplied by clients. Keep only known item
	// types and a digest of the call ID, never the original value.
	if event.Tool != "function_call_output" && event.Tool != "custom_tool_call_output" && event.Tool != "chat_tool_result" {
		event.Tool = ""
	}
	if event.CallID != "" {
		sum := sha256.Sum256([]byte(event.CallID))
		event.CallID = hex.EncodeToString(sum[:8])
	}
	if !reasons[event.Reason] {
		if event.Reason != "" {
			event.Reason = "request_failed"
		}
	}
	if event.AccountID < 0 {
		event.AccountID = 0
	}
	if event.Status < 100 || event.Status > 599 {
		event.Status = 0
	}
	if event.DurationMS < 0 {
		event.DurationMS = 0
	}
	if event.Confidence < 0 || event.Confidence > 1 {
		event.Confidence = 0
	}
	if event.Probability < 0 || event.Probability > 1 {
		event.Probability = 0
	}
	return event
}

func safeToken(value string, max int) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > max {
		return ""
	}
	for _, r := range value {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' || r == ':' || r == '/' {
			continue
		}
		return ""
	}
	return value
}
