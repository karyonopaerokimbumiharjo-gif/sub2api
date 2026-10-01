package handler

import (
	"strings"
	"unsafe"

	"github.com/tidwall/gjson"
)

// A screenshot is billed as vision input, not as its base64 transport text.
// Keep a conservative per-image budget for admission; billing still uses the
// upstream's actual token count. This also covers remote image URLs.
const inflightVisionInputTokens = 3072

// semanticInflightInputTokens retains the existing bytes/4 approximation for
// text, tool schemas, arguments and results, while separating binary media and
// opaque reasoning state. It never changes the forwarded request.
func semanticInflightInputTokens(body []byte) int {
	if !gjson.ValidBytes(body) {
		return len(body) / 4
	}
	textBytes, mediaTokens := 0, 0
	var visit func(gjson.Result, string, int)
	visit = func(value gjson.Result, key string, depth int) {
		if depth > 64 {
			textBytes += len(value.Raw)
			return
		}
		if key == "encrypted_content" {
			return
		}
		if value.IsObject() {
			kind := value.Get("type").String()
			switch kind {
			case "input_image", "image_url", "image", "image_generation_call", "computer_screenshot":
				mediaTokens += inflightVisionInputTokens
				return
			case "input_audio", "audio", "input_file", "file", "document":
				for _, path := range []string{"data", "file_data", "source.data", "input_audio.data", "audio.data"} {
					if data := value.Get(path); data.Type == gjson.String {
						mediaTokens += inflightEncodedFileTokens(data.String())
					}
				}
				return
			}
			// Gemini's inline media part does not have a type discriminator.
			for _, field := range []string{"inlineData", "inline_data"} {
				if media := value.Get(field); media.IsObject() {
					mime := media.Get("mimeType").String()
					if mime == "" {
						mime = media.Get("mime_type").String()
					}
					if strings.HasPrefix(mime, "image/") {
						mediaTokens += inflightVisionInputTokens
					} else {
						mediaTokens += inflightEncodedFileTokens(media.Get("data").String())
					}
					return
				}
			}
			value.ForEach(func(name, child gjson.Result) bool {
				textBytes += len(name.String()) // Tool/property names remain real input.
				visit(child, name.String(), depth+1)
				return true
			})
			return
		}
		if value.IsArray() {
			value.ForEach(func(_, child gjson.Result) bool {
				visit(child, key, depth+1)
				return true
			})
			return
		}
		if value.Type == gjson.String {
			text := value.String()
			// Tool results can serialize multimodal content as a JSON string.
			if (key == "output" || key == "arguments") && gjson.Valid(text) {
				visit(gjson.Parse(text), "", depth+1)
			} else {
				textBytes += len(text)
			}
			return
		}
		textBytes += len(value.Raw)
	}
	// Match the gateway's existing immutable payload-view pattern: no gjson
	// result escapes this call, and the request body is never mutated here.
	// ParseBytes would copy the complete screenshot payload just to inspect it.
	visit(gjson.Parse(unsafe.String(unsafe.SliceData(body), len(body))), "", 0)
	return (textBytes+3)/4 + mediaTokens
}

// Files/audio can contain arbitrary amounts of input. Account for decoded size
// conservatively without decoding or retaining a second copy of the payload.
func inflightEncodedFileTokens(data string) int {
	if strings.HasPrefix(data, "data:") {
		if comma := strings.IndexByte(data, ','); comma >= 0 {
			data = data[comma+1:]
		}
	}
	return (len(data)*3/4 + 3) / 4
}
