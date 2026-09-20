// Package responseaudit passively observes Responses streams without changing bytes.
package responseaudit

import (
	"encoding/json"
	"io"
	"mime"
	"sort"
	"strings"
	"sync"
)

const DefaultFrameLimit = 256 * 1024

type Result struct {
	TerminalStatus    string   `json:"terminal_status"`
	StreamInterrupted bool     `json:"stream_interrupted"`
	Models            []string `json:"response_models"`
	DroppedFrames     int      `json:"dropped_frames"`
	ModelOverflow     bool     `json:"model_overflow"`
}

func (r Result) MarshalJSON() ([]byte, error) {
	type plain Result
	var status *string
	if r.TerminalStatus != "" {
		value := r.TerminalStatus
		status = &value
	}
	return json.Marshal(struct {
		plain
		TerminalStatus *string `json:"terminal_status"`
	}{plain: plain(r), TerminalStatus: status})
}

type Observer struct {
	sse, plainJSON                 bool
	limit                          int
	buffer                         []byte
	lineContent, afterCR, overflow bool
	terminals                      map[string]bool
	models                         map[string]bool
	conflict, modelOverflow        bool
	dropped                        int
	finished                       bool
	result                         Result
}

func New(contentType string, limit int) *Observer {
	if limit <= 0 {
		limit = DefaultFrameLimit
	}
	media, _, _ := mime.ParseMediaType(contentType)
	return &Observer{sse: media == "text/event-stream", plainJSON: media == "application/json", limit: limit,
		terminals: make(map[string]bool), models: make(map[string]bool)}
}
func (o *Observer) append(b byte) {
	if o.overflow {
		return
	}
	if len(o.buffer) >= o.limit {
		o.overflow = true
		o.buffer = o.buffer[:0]
		return
	}
	o.buffer = append(o.buffer, b)
}
func (o *Observer) Feed(p []byte) {
	if o.finished || (!o.sse && !o.plainJSON) {
		return
	}
	for _, b := range p {
		if !o.sse {
			o.append(b)
			continue
		}
		if o.afterCR && b == '\n' {
			o.afterCR = false
			continue
		}
		o.afterCR = b == '\r'
		if b == '\r' || b == '\n' {
			if !o.lineContent {
				if o.overflow {
					o.dropped++
				} else {
					o.frame(string(o.buffer))
				}
				o.buffer = o.buffer[:0]
				o.overflow = false
			} else {
				o.append('\n')
			}
			o.lineContent = false
		} else {
			o.lineContent = true
			o.append(b)
		}
	}
}
func terminal(t string) string {
	switch t {
	case "response.completed":
		return "completed"
	case "response.incomplete":
		return "incomplete"
	case "response.failed":
		return "failed"
	}
	return ""
}
func validModel(s string) bool {
	if len(s) == 0 || len(s) > 80 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}
func (o *Observer) model(s string) {
	if !validModel(s) {
		return
	}
	if len(o.models) < 16 || o.models[s] {
		o.models[s] = true
	} else {
		o.modelOverflow = true
	}
}
func (o *Observer) frame(raw string) {
	var data []string
	name := ""
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, ":") {
			continue
		}
		key, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch key {
		case "data":
			data = append(data, value)
		case "event":
			name = value
		}
	}
	var event struct {
		Type     string `json:"type"`
		Response struct {
			Model  string  `json:"model"`
			Status *string `json:"status"`
		} `json:"response"`
	}
	if json.Unmarshal([]byte(strings.Join(data, "\n")), &event) != nil {
		return
	}
	t := terminal(event.Type)
	if t != "" || terminal(name) != "" {
		if name != "" && name != "message" && name != event.Type {
			o.conflict = true
		}
		if t != "" {
			o.terminals[t] = true
			if event.Response.Status != nil && *event.Response.Status != t {
				o.conflict = true
			}
		}
	}
	switch event.Type {
	case "response.created", "response.in_progress", "response.completed", "response.incomplete", "response.failed":
		o.model(event.Response.Model)
	}
}
func (o *Observer) Finish(interrupted bool) Result {
	if o.finished {
		return o.result
	}
	o.finished = true
	if o.plainJSON && !interrupted && !o.overflow {
		var response struct {
			Object string `json:"object"`
			Status string `json:"status"`
			Model  string `json:"model"`
		}
		if json.Unmarshal(o.buffer, &response) == nil && response.Object == "response" {
			switch response.Status {
			case "completed", "incomplete", "failed":
				o.terminals[response.Status] = true
			}
			o.model(response.Model)
		}
	}
	if o.overflow {
		o.dropped++
	}
	result := Result{StreamInterrupted: interrupted, DroppedFrames: o.dropped, ModelOverflow: o.modelOverflow, Models: []string{}}
	switch {
	case o.conflict || len(o.terminals) > 1:
		result.TerminalStatus = "conflicting"
	case len(o.terminals) == 1:
		for s := range o.terminals {
			result.TerminalStatus = s
		}
	case !interrupted:
		result.TerminalStatus = "missing_terminal"
	}
	for model := range o.models {
		result.Models = append(result.Models, model)
	}
	sort.Strings(result.Models)
	o.buffer = nil
	o.result = result
	return result
}

// Wrap observes the bytes already read by the caller; it never pre-reads/drains.
// Close before EOF records interruption, even after a terminal was observed.
func Wrap(source io.ReadCloser, contentType string, done func(Result)) io.ReadCloser {
	return &observedBody{source: source, observer: New(contentType, DefaultFrameLimit), done: done}
}

type observedBody struct {
	source    io.ReadCloser
	observer  *Observer
	mu        sync.Mutex
	done      func(Result)
	reported  bool
	closeOnce sync.Once
	closeErr  error
}

func (b *observedBody) record(p []byte, finish, interrupted bool) {
	b.mu.Lock()
	if b.reported {
		b.mu.Unlock()
		return
	}
	b.observer.Feed(p)
	if !finish {
		b.mu.Unlock()
		return
	}
	b.reported = true
	result := b.observer.Finish(interrupted)
	callback := b.done
	b.mu.Unlock()
	if callback != nil {
		callback(result)
	}
}
func (b *observedBody) Read(p []byte) (int, error) {
	n, err := b.source.Read(p)
	b.record(p[:n], err != nil, err != nil && err != io.EOF)
	return n, err
}
func (b *observedBody) Close() error {
	b.closeOnce.Do(func() { b.closeErr = b.source.Close(); b.record(nil, true, true) })
	return b.closeErr
}
