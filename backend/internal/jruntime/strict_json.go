package jruntime

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

func validateJSON(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return errors.New("json_depth_limit")
		}
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		delim, composite := tok.(json.Delim)
		if !composite {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				if !ok {
					return errors.New("invalid_json_key")
				}
				key = strings.ToLower(key)
				if seen[key] {
					return errors.New("duplicate_json_key")
				}
				seen[key] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid_json_delimiter")
		}
		_, err = dec.Token()
		return err
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing_json")
	}
	return nil
}
