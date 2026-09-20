package responseaudit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func frame(status string) string {
	return fmt.Sprintf("data: {\"type\":\"response.%s\",\"response\":{\"status\":\"%s\",\"model\":\"gpt-6-astra\"}}\n\n", status, status)
}
func TestFrameBoundaries(t *testing.T) {
	for _, newline := range []string{"\n", "\r\n", "\r"} {
		data := []byte(strings.ReplaceAll(frame("completed"), "\n", newline))
		for step := 1; step < len(data); step++ {
			o := New("text/event-stream", 0)
			for i := 0; i < len(data); i += step {
				o.Feed(data[i:min(i+step, len(data))])
			}
			if got := o.Finish(false); got.TerminalStatus != "completed" || got.StreamInterrupted {
				t.Fatalf("step %d: %+v", step, got)
			}
		}
	}
	o := New("text/event-stream", 0)
	o.Feed([]byte("event: response.completed\ndata: {\"type\":\ndata: \"response.completed\"}\n\n"))
	if o.Finish(false).TerminalStatus != "completed" {
		t.Fatal("multiline frame")
	}
}
func TestTerminalCases(t *testing.T) {
	cases := []struct {
		name, body, want string
		interrupt        bool
	}{
		{"empty", "", "missing_terminal", false},
		{"done", "data: [DONE]\n\n", "missing_terminal", false},
		{"missing blank", strings.TrimSuffix(frame("completed"), "\n"), "missing_terminal", false},
		{"event without data", "event: response.completed\n\n", "missing_terminal", false},
		{"malformed", "data: {bad}\n\n", "missing_terminal", false},
		{"string", "data: \"response.completed\"\n\n", "missing_terminal", false},
		{"duplicate", frame("completed") + frame("completed"), "completed", false},
		{"conflict", frame("completed") + frame("failed"), "conflicting", false},
		{"event mismatch", "event: response.failed\n" + frame("completed"), "conflicting", false},
		{"status mismatch", "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"incomplete\"}}\n\n", "conflicting", false},
		{"interrupted", "", "", true},
		{"complete then interrupted", frame("completed"), "completed", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := New("text/event-stream", 0)
			o.Feed([]byte(tc.body))
			r := o.Finish(tc.interrupt)
			if r.TerminalStatus != tc.want || r.StreamInterrupted != tc.interrupt {
				t.Fatalf("%+v", r)
			}
		})
	}
}
func TestOversizeRecoveryAndJSON(t *testing.T) {
	o := New("text/event-stream", 256)
	for i := 0; i < 1000; i++ {
		o.Feed(bytes.Repeat([]byte("a"), 1024))
	}
	if len(o.buffer) > 256 || cap(o.buffer) > 512 {
		t.Fatal("unbounded memory")
	}
	o.Feed([]byte("\n\n" + frame("completed")))
	r := o.Finish(false)
	if r.TerminalStatus != "completed" || r.DroppedFrames != 1 {
		t.Fatalf("%+v", r)
	}
	for _, tc := range []struct{ body, want string }{
		{`{"object":"response","status":"completed"}`, "completed"},
		{`{"response":{"status":"completed"}}`, "missing_terminal"},
		{`[{"object":"response","status":"completed"}]`, "missing_terminal"},
		{`{"object":"response","status":"COMPLETED"}`, "missing_terminal"},
	} {
		o := New("application/json", 0)
		o.Feed([]byte(tc.body))
		if o.Finish(false).TerminalStatus != tc.want {
			t.Fatal(tc)
		}
	}
}

type errorReader struct {
	data []byte
	err  error
}

func (r *errorReader) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, r.err
	}
	return n, nil
}
func (r *errorReader) Close() error { return nil }
func TestReadCloserTransparencyAndFinalization(t *testing.T) {
	data := []byte(": comment\r\n\r\n" + frame("completed"))
	for _, end := range []error{io.EOF, io.ErrUnexpectedEOF} {
		count := 0
		var result Result
		body := Wrap(&errorReader{data: bytes.Clone(data), err: end}, "text/event-stream", func(r Result) { count++; result = r })
		got, err := io.ReadAll(body)
		if !bytes.Equal(data, got) {
			t.Fatal("changed bytes")
		}
		if end != io.EOF && !errors.Is(err, end) {
			t.Fatal(err)
		}
		_ = body.Close()
		_ = body.Close()
		if count != 1 || result.TerminalStatus != "completed" || result.StreamInterrupted != (end != io.EOF) {
			t.Fatalf("%d %+v", count, result)
		}
	}
	var result Result
	body := Wrap(io.NopCloser(strings.NewReader(frame("completed"))), "text/event-stream", func(r Result) { result = r })
	p := make([]byte, len(frame("completed")))
	_, _ = body.Read(p)
	_ = body.Close()
	if result.TerminalStatus != "completed" || !result.StreamInterrupted {
		t.Fatalf("%+v", result)
	}
}
func TestParallelRequestsRemainIndependent(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			status := []string{"completed", "failed", "incomplete"}[i%3]
			body := Wrap(io.NopCloser(strings.NewReader(frame(status))), "text/event-stream", func(r Result) {
				if r.TerminalStatus != status {
					t.Errorf("%+v", r)
				}
			})
			_, _ = io.Copy(io.Discard, body)
			_ = body.Close()
		}(i)
	}
	wg.Wait()
}
func TestRequestEvidenceDoesNotLeakAndChecksBothLocations(t *testing.T) {
	h := http.Header{"Authorization": []string{"Bearer secret"}, "X-Codex-Turn-Metadata": []string{`{"thread_id":"secret-a"}`}}
	r := InspectRequest(h, []byte(`{"model":"gpt-6-astra","client_metadata":{"x-codex-turn-metadata":"{\"session_id\":\"secret-b\"}"},"input":"private"}`))
	if !r.BodyObserved || len(r.HeaderMetadata.IDsPresent) != 1 || len(r.BodyMetadata.IDsPresent) != 1 {
		t.Fatalf("%+v", r)
	}
	if strings.Contains(fmt.Sprintf("%+v", r), "secret") || strings.Contains(fmt.Sprintf("%+v", r), "private") {
		t.Fatal("leaked value")
	}
}

func TestInterruptedWithoutTerminalSerializesNull(t *testing.T) {
	result := New("text/event-stream", 0).Finish(true)
	encoded, err := json.Marshal(result)
	if err != nil || !strings.Contains(string(encoded), `"terminal_status":null`) {
		t.Fatalf("%s %v", encoded, err)
	}
}
