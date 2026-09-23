package handler

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"net/http"
)

// Child model output is buffered until its exact model and terminal status are
// verified. No child headers, cookies or intermediate answer leak to the client.
type jBufferWriter struct {
	header  http.Header
	body    bytes.Buffer
	status  int
	written bool
	closed  chan bool
}

func newJBufferWriter() *jBufferWriter {
	return &jBufferWriter{header: make(http.Header), status: 200, closed: make(chan bool)}
}
func (w *jBufferWriter) Header() http.Header { return w.header }
func (w *jBufferWriter) WriteHeader(code int) {
	if !w.written {
		w.status = code
	}
}
func (w *jBufferWriter) WriteHeaderNow() { w.written = true }
func (w *jBufferWriter) Write(raw []byte) (int, error) {
	w.written = true
	if w.body.Len()+len(raw) > 16<<20 {
		return 0, errors.New("j_child_output_too_large")
	}
	return w.body.Write(raw)
}
func (w *jBufferWriter) WriteString(raw string) (int, error) { return w.Write([]byte(raw)) }
func (w *jBufferWriter) Status() int                         { return w.status }
func (w *jBufferWriter) Size() int {
	if !w.written {
		return -1
	}
	return w.body.Len()
}
func (w *jBufferWriter) Written() bool { return w.written }
func (w *jBufferWriter) Flush()        { w.WriteHeaderNow() }
func (w *jBufferWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, errors.New("j_child_hijack_not_supported")
}
func (w *jBufferWriter) CloseNotify() <-chan bool { return w.closed }
func (w *jBufferWriter) Pusher() http.Pusher      { return nil }
