package service

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

var errGPT6JResponseModel = errors.New("GPT-6J upstream response did not confirm gpt-6-astra")

const gpt6JResponseLimit = 16 << 20

type gpt6JResponseGuard struct {
	verified bool
	terminal bool
}

func (g *gpt6JResponseGuard) event(data []byte) error {
	if !gjson.ValidBytes(data) {
		return errGPT6JResponseModel
	}
	typ := gjson.GetBytes(data, "type").String()
	model := gjson.GetBytes(data, "response.model").String()
	if model == "" {
		model = gjson.GetBytes(data, "model").String()
	}
	if model != "" {
		if model != "gpt-6-astra" {
			return errGPT6JResponseModel
		}
		g.verified = true
	}
	if typ == "error" || typ == "response.failed" || typ == "response.incomplete" {
		g.terminal = true
		return nil
	}
	// Require evidence before any output, and recheck the terminal response
	// before a caller can report completion or rewrite its public model label.
	if !g.verified || (typ == "response.completed" && model == "") {
		return errGPT6JResponseModel
	}
	if typ == "response.completed" {
		g.terminal = true
	}
	return nil
}

func guardGPT6JHTTPResponse(c *gin.Context, resp *http.Response) error {
	if c == nil || !c.GetBool(OpenAIGPT6JContextKey) || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}
	// Compact responses carry encrypted context rather than a generation model.
	if c.Request != nil && strings.HasSuffix(c.Request.URL.Path, "/compact") {
		return nil
	}
	if isEventStreamResponse(resp.Header) {
		body := &gpt6JStreamBody{source: resp.Body, reader: bufio.NewReader(resp.Body)}
		// Validate the first data event before downstream headers or text are sent.
		for !body.guard.verified && !body.guard.terminal {
			frame, err := body.frame()
			if err != nil {
				return err
			}
			body.pending = append(body.pending, frame...)
			if len(body.pending) > gpt6JResponseLimit {
				return errGPT6JResponseModel
			}
		}
		resp.Body = body
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, gpt6JResponseLimit+1))
	if err != nil {
		return err
	}
	if len(data) > gpt6JResponseLimit || !gjson.ValidBytes(data) || gjson.GetBytes(data, "model").String() != "gpt-6-astra" {
		return errGPT6JResponseModel
	}
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(data))
	return nil
}

type gpt6JStreamBody struct {
	source  io.ReadCloser
	reader  *bufio.Reader
	guard   gpt6JResponseGuard
	pending []byte
	stopped error
}

func (b *gpt6JStreamBody) Close() error { return b.source.Close() }

func (b *gpt6JStreamBody) frame() ([]byte, error) {
	var wire, data []byte
	for {
		line, err := b.reader.ReadSlice('\n')
		wire = append(wire, line...)
		if len(wire) > gpt6JResponseLimit {
			return nil, errGPT6JResponseModel
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			if err == io.EOF && len(wire) == 0 && b.guard.terminal {
				return nil, io.EOF
			}
			if err == io.EOF {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		if bytes.Equal(line, []byte("\n")) || bytes.Equal(line, []byte("\r\n")) {
			break
		}
	}
	for _, line := range bytes.Split(wire, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if bytes.HasPrefix(line, []byte("data:")) {
			if len(data) > 0 {
				data = append(data, '\n')
			}
			data = append(data, bytes.TrimPrefix(line[5:], []byte(" "))...)
		}
	}
	if len(data) == 0 {
		return wire, nil
	}
	if bytes.Equal(data, []byte("[DONE]")) {
		if !b.guard.terminal {
			return nil, io.ErrUnexpectedEOF
		}
		return wire, nil
	}
	if err := b.guard.event(data); err != nil {
		return nil, err
	}
	return wire, nil
}

func (b *gpt6JStreamBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(b.pending) == 0 && b.stopped == nil {
		b.pending, b.stopped = b.frame()
	}
	if len(b.pending) == 0 {
		return 0, b.stopped
	}
	n := copy(p, b.pending)
	b.pending = b.pending[n:]
	return n, nil
}
