package repository

import (
	"compress/gzip"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/responseaudit"
	"github.com/klauspost/compress/zstd"
)

// auditResponsesHTTP runs at the final HTTP boundary, after existing decompression
// and before business parsing/model rewriting. It never reads response bytes ahead.
func auditResponsesHTTP(req *http.Request, resp *http.Response, accountID int64) {
	if req == nil || req.URL == nil || resp == nil || resp.Body == nil {
		return
	}
	path := strings.TrimRight(req.URL.Path, "/")
	if req.Method != http.MethodPost || !strings.HasSuffix(path, "/responses") {
		return
	}
	actual := req
	if resp.Request != nil {
		actual = resp.Request
	}
	request := responseaudit.InspectRequest(actual.Header, auditRequestBody(actual))
	status := resp.StatusCode
	stateLength := len(resp.Header.Get("x-codex-turn-state"))
	resp.Body = responseaudit.Wrap(resp.Body, resp.Header.Get("content-type"), func(result responseaudit.Result) {
		// No URL/query, credentials, original IDs, state token, prompts or response text.
		slog.Info("responses_upstream_audit", "account_id", accountID, "http_status", status,
			"request", request, "observation", result, "turn_state_present", stateLength > 0, "turn_state_length", stateLength)
	})
}

func auditRequestBody(req *http.Request) []byte {
	const limit = 4 * 1024 * 1024
	if req.GetBody == nil {
		return nil
	}
	body, err := req.GetBody()
	if err != nil {
		return nil
	}
	defer body.Close()
	var reader io.Reader = body
	switch strings.ToLower(req.Header.Get("content-encoding")) {
	case "", "identity":
	case "gzip":
		decoded, e := gzip.NewReader(body)
		if e != nil {
			return nil
		}
		defer decoded.Close()
		reader = decoded
	case "zstd":
		decoded, e := zstd.NewReader(body, zstd.WithDecoderMaxMemory(8*1024*1024), zstd.WithDecoderConcurrency(1))
		if e != nil {
			return nil
		}
		defer decoded.Close()
		reader = decoded
	default:
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil || len(data) > limit {
		return nil
	}
	return data
}
