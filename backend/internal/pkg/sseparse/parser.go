// Package sseparse decodes bounded SSE frames independently of transport writes.
package sseparse

import (
	"bytes"
	"encoding/json"
	"strings"
)

const MaxFrameBytes = 1 << 20

type Event struct {
	Type string
	Data []byte
}

type Parser struct {
	line         []byte
	data         []byte
	kind         string
	skip         bool
	cr           bool
	lineNonempty bool
	Truncated    bool
}

// Feed accepts arbitrary fragments, including CRLF split across writes. An
// oversized frame is discarded through its blank line, never parsed partially.
func (p *Parser) Feed(raw []byte, emit func(Event)) {
	for _, b := range raw {
		if p.cr {
			p.cr = false
			if b == '\n' {
				continue
			}
		}
		if b == '\r' || b == '\n' {
			p.consumeLine(emit)
			p.cr = b == '\r'
			continue
		}
		p.lineNonempty = true
		if len(p.line)+len(p.data)+len(p.kind) >= MaxFrameBytes {
			p.skip, p.Truncated = true, true
		}
		if !p.skip {
			p.line = append(p.line, b)
		}
	}
}

func (p *Parser) consumeLine(emit func(Event)) {
	line := p.line
	nonempty := p.lineNonempty
	p.lineNonempty = false
	p.line = nil
	if !nonempty {
		if !p.skip && len(p.data) > 0 {
			emit(Event{Type: p.kind, Data: bytes.TrimSuffix(p.data, []byte{'\n'})})
		}
		p.data, p.kind, p.skip = nil, "", false
		return
	}
	if p.skip || line[0] == ':' {
		return
	}
	field, value, _ := bytes.Cut(line, []byte{':'})
	value = bytes.TrimPrefix(value, []byte{' '})
	switch string(field) {
	case "event":
		p.kind = string(value)
	case "data":
		p.data = append(append(p.data, value...), '\n')
	}
}

// Terminal only examines protocol fields, never generated text or arguments.
// Conflicting event/data types are invalid and cannot terminate the capture.
func (e Event) Terminal() string {
	if strings.TrimSpace(string(e.Data)) == "[DONE]" && (e.Type == "" || e.Type == "message") {
		return "completed"
	}
	var envelope struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(e.Data, &envelope) != nil {
		return ""
	}
	if e.Type != "" && e.Type != "message" && e.Type != envelope.Type {
		return ""
	}
	switch envelope.Type {
	case "response.completed", "message_stop":
		return "completed"
	case "response.failed", "error":
		return "failed"
	case "response.incomplete":
		return "incomplete"
	default:
		return ""
	}
}
