// Package fuzzer implements the fuzz testing engine for katashiro-proxy.
// It provides payload position management, payload generation, attack type
// iteration, and orchestration of fuzz campaigns against recorded HTTP sessions.
package fuzzer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Position defines a location in an HTTP request where payloads are injected.
type Position struct {
	// ID is the unique identifier for this position (e.g., "pos-0").
	ID string `json:"id"`
	// Location specifies where in the request to inject: header, path, query,
	// body_regex, body_json, cookie.
	Location string `json:"location"`
	// Name is the header name, query parameter key, or cookie name.
	// Required for header, query, and cookie locations.
	Name string `json:"name,omitempty"`
	// JSONPath is the JSON path for body_json location (e.g., "$.password").
	JSONPath string `json:"json_path,omitempty"`
	// Mode is the operation mode: replace (default), add, or remove.
	Mode string `json:"mode,omitempty"`
	// Match is an optional regex pattern for replace mode.
	// If it contains a capture group, only the group is replaced.
	Match string `json:"match,omitempty"`
	// PayloadSet is the name of the payload set to use for this position.
	// Not required for remove mode.
	PayloadSet string `json:"payload_set,omitempty"`
}

// validLocations lists all supported position locations.
var validLocations = map[string]bool{
	"header":     true,
	"path":       true,
	"query":      true,
	"body_regex": true,
	"body_json":  true,
	"cookie":     true,
}

// validModes lists all supported position operation modes.
var validModes = map[string]bool{
	"replace": true,
	"add":     true,
	"remove":  true,
}

// maxMatchPatternLen is the maximum allowed length for match regex patterns.
const maxMatchPatternLen = 1024

// Validate checks that a Position is well-formed.
func (p *Position) Validate() error {
	if p.ID == "" {
		return fmt.Errorf("position id is required")
	}
	if !validLocations[p.Location] {
		return fmt.Errorf("invalid location %q: must be one of header, path, query, body_regex, body_json, cookie", p.Location)
	}

	mode := p.Mode
	if mode == "" {
		mode = "replace"
	}
	if !validModes[mode] {
		return fmt.Errorf("invalid mode %q: must be one of replace, add, remove", p.Mode)
	}

	switch p.Location {
	case "header", "query", "cookie":
		if p.Name == "" {
			return fmt.Errorf("name is required for %s location", p.Location)
		}
	case "body_json":
		if p.JSONPath == "" {
			return fmt.Errorf("json_path is required for body_json location")
		}
	}

	if mode != "remove" && p.PayloadSet == "" {
		return fmt.Errorf("payload_set is required for %s mode", mode)
	}

	if p.Match != "" {
		if len(p.Match) > maxMatchPatternLen {
			return fmt.Errorf("match pattern too long: %d > %d", len(p.Match), maxMatchPatternLen)
		}
		if _, err := regexp.Compile(p.Match); err != nil {
			return fmt.Errorf("invalid match pattern %q: %w", p.Match, err)
		}
	}

	return nil
}

// effectiveMode returns the position's mode, defaulting to "replace".
func (p *Position) effectiveMode() string {
	if p.Mode == "" {
		return "replace"
	}
	return p.Mode
}

// RequestData holds the mutable parts of an HTTP request that positions operate on.
type RequestData struct {
	// Method is the HTTP request method.
	Method string
	// URL is the parsed request URL.
	URL *url.URL
	// Headers are the request headers (canonical form).
	Headers map[string][]string
	// Body is the request body bytes.
	Body []byte
}

// Clone creates a deep copy of RequestData.
func (r *RequestData) Clone() *RequestData {
	clone := &RequestData{
		Method: r.Method,
		Body:   append([]byte(nil), r.Body...),
	}
	if r.URL != nil {
		u := *r.URL
		if r.URL.User != nil {
			u.User = url.UserPassword(r.URL.User.Username(), "")
			if p, ok := r.URL.User.Password(); ok {
				u.User = url.UserPassword(r.URL.User.Username(), p)
			}
		}
		q := r.URL.Query()
		u.RawQuery = q.Encode()
		clone.URL = &u
	}
	clone.Headers = make(map[string][]string)
	for k, v := range r.Headers {
		clone.Headers[k] = append([]string(nil), v...)
	}
	return clone
}

// ApplyPosition applies a single position with the given payload to the request data.
// For remove mode, payload is ignored.
func ApplyPosition(data *RequestData, pos Position, payload string) error {
	mode := pos.effectiveMode()
	switch mode {
	case "replace":
		return applyReplace(data, pos, payload)
	case "add":
		return applyAdd(data, pos, payload)
	case "remove":
		return applyRemove(data, pos)
	default:
		return fmt.Errorf("unsupported mode %q", mode)
	}
}

func applyReplace(data *RequestData, pos Position, payload string) error {
	switch pos.Location {
	case "header":
		return replaceHeader(data, pos, payload)
	case "query":
		return replaceQuery(data, pos, payload)
	case "path":
		return replacePath(data, pos, payload)
	case "body_regex":
		return replaceBodyRegex(data, pos, payload)
	case "body_json":
		return replaceBodyJSON(data, pos, payload)
	case "cookie":
		return replaceCookie(data, pos, payload)
	default:
		return fmt.Errorf("unsupported location %q for replace", pos.Location)
	}
}

func applyAdd(data *RequestData, pos Position, payload string) error {
	switch pos.Location {
	case "header":
		canonical := http.CanonicalHeaderKey(pos.Name)
		data.Headers[canonical] = append(data.Headers[canonical], payload)
		return nil
	case "query":
		if data.URL == nil {
			return fmt.Errorf("URL is nil, cannot add query parameter")
		}
		q := data.URL.Query()
		q.Add(pos.Name, payload)
		data.URL.RawQuery = q.Encode()
		return nil
	case "cookie":
		canonical := http.CanonicalHeaderKey("Cookie")
		existing := ""
		if v, ok := data.Headers[canonical]; ok && len(v) > 0 {
			existing = v[0]
		}
		newCookie := pos.Name + "=" + payload
		if existing != "" {
			existing += "; " + newCookie
		} else {
			existing = newCookie
		}
		data.Headers[canonical] = []string{existing}
		return nil
	default:
		return fmt.Errorf("add mode is not supported for %s location", pos.Location)
	}
}

func applyRemove(data *RequestData, pos Position) error {
	switch pos.Location {
	case "header":
		delete(data.Headers, http.CanonicalHeaderKey(pos.Name))
		return nil
	case "query":
		if data.URL == nil {
			return fmt.Errorf("URL is nil, cannot remove query parameter")
		}
		q := data.URL.Query()
		q.Del(pos.Name)
		data.URL.RawQuery = q.Encode()
		return nil
	case "cookie":
		return removeCookie(data, pos.Name)
	default:
		return fmt.Errorf("remove mode is not supported for %s location", pos.Location)
	}
}

func replaceHeader(data *RequestData, pos Position, payload string) error {
	canonical := http.CanonicalHeaderKey(pos.Name)
	values, ok := data.Headers[canonical]
	if !ok || len(values) == 0 {
		// If header doesn't exist, set it with the payload.
		data.Headers[canonical] = []string{payload}
		return nil
	}

	if pos.Match != "" {
		re, err := regexp.Compile(pos.Match)
		if err != nil {
			return fmt.Errorf("compile match pattern: %w", err)
		}
		for i, v := range values {
			values[i] = replaceWithCapture(re, v, payload)
		}
	} else {
		data.Headers[canonical] = []string{payload}
	}
	return nil
}

func replaceQuery(data *RequestData, pos Position, payload string) error {
	if data.URL == nil {
		return fmt.Errorf("URL is nil, cannot replace query parameter")
	}
	q := data.URL.Query()
	if pos.Match != "" {
		re, err := regexp.Compile(pos.Match)
		if err != nil {
			return fmt.Errorf("compile match pattern: %w", err)
		}
		vals := q[pos.Name]
		for i, v := range vals {
			vals[i] = replaceWithCapture(re, v, payload)
		}
		q[pos.Name] = vals
	} else {
		q.Set(pos.Name, payload)
	}
	data.URL.RawQuery = q.Encode()
	return nil
}

func replacePath(data *RequestData, pos Position, payload string) error {
	if data.URL == nil {
		return fmt.Errorf("URL is nil, cannot replace path")
	}
	if pos.Match != "" {
		re, err := regexp.Compile(pos.Match)
		if err != nil {
			return fmt.Errorf("compile match pattern: %w", err)
		}
		data.URL.Path = replaceWithCapture(re, data.URL.Path, payload)
	} else {
		data.URL.Path = payload
	}
	return nil
}

func replaceBodyRegex(data *RequestData, pos Position, payload string) error {
	pattern := pos.Match
	if pattern == "" {
		// For body_regex without match, replace entire body.
		data.Body = []byte(payload)
		return nil
	}
	if len(pattern) > maxMatchPatternLen {
		return fmt.Errorf("match pattern too long: %d > %d", len(pattern), maxMatchPatternLen)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("compile match pattern: %w", err)
	}
	data.Body = []byte(replaceWithCapture(re, string(data.Body), payload))
	return nil
}

func replaceBodyJSON(data *RequestData, pos Position, payload string) error {
	if pos.JSONPath == "" {
		return fmt.Errorf("json_path is required for body_json location")
	}

	keys, err := parseSimpleJSONPath(pos.JSONPath)
	if err != nil {
		return fmt.Errorf("parse json_path: %w", err)
	}

	var root any
	if err := json.Unmarshal(data.Body, &root); err != nil {
		return fmt.Errorf("body is not valid JSON: %w", err)
	}

	if err := setJSONValue(root, keys, payload); err != nil {
		return fmt.Errorf("set json value: %w", err)
	}

	result, err := json.Marshal(root)
	if err != nil {
		return fmt.Errorf("marshal patched JSON: %w", err)
	}
	data.Body = result
	return nil
}

func replaceCookie(data *RequestData, pos Position, payload string) error {
	canonical := http.CanonicalHeaderKey("Cookie")
	values, ok := data.Headers[canonical]
	if !ok || len(values) == 0 {
		data.Headers[canonical] = []string{pos.Name + "=" + payload}
		return nil
	}

	cookieStr := values[0]
	parts := strings.Split(cookieStr, ";")
	found := false
	for i, part := range parts {
		trimmed := strings.TrimSpace(part)
		eqIdx := strings.Index(trimmed, "=")
		if eqIdx < 0 {
			continue
		}
		name := trimmed[:eqIdx]
		if strings.TrimSpace(name) == pos.Name {
			if pos.Match != "" {
				re, err := regexp.Compile(pos.Match)
				if err != nil {
					return fmt.Errorf("compile match pattern: %w", err)
				}
				oldVal := trimmed[eqIdx+1:]
				newVal := replaceWithCapture(re, oldVal, payload)
				parts[i] = " " + name + "=" + newVal
				if i == 0 {
					parts[i] = name + "=" + newVal
				}
			} else {
				parts[i] = " " + pos.Name + "=" + payload
				if i == 0 {
					parts[i] = pos.Name + "=" + payload
				}
			}
			found = true
			break
		}
	}

	if !found {
		parts = append(parts, " "+pos.Name+"="+payload)
	}
	data.Headers[canonical] = []string{strings.Join(parts, ";")}
	return nil
}

func removeCookie(data *RequestData, name string) error {
	canonical := http.CanonicalHeaderKey("Cookie")
	values, ok := data.Headers[canonical]
	if !ok || len(values) == 0 {
		return nil
	}

	cookieStr := values[0]
	parts := strings.Split(cookieStr, ";")
	var result []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		eqIdx := strings.Index(trimmed, "=")
		if eqIdx < 0 {
			result = append(result, part)
			continue
		}
		cookieName := strings.TrimSpace(trimmed[:eqIdx])
		if cookieName != name {
			result = append(result, part)
		}
	}

	if len(result) == 0 {
		delete(data.Headers, canonical)
	} else {
		data.Headers[canonical] = []string{strings.TrimSpace(strings.Join(result, ";"))}
	}
	return nil
}

// replaceWithCapture replaces text matched by a regex with payload.
// If the regex has capture groups, only the first capture group is replaced.
// Otherwise, the entire match is replaced.
func replaceWithCapture(re *regexp.Regexp, input, payload string) string {
	if re.NumSubexp() == 0 {
		// No capture groups: replace entire match.
		return re.ReplaceAllLiteralString(input, payload)
	}

	// Has capture groups: replace only the first capture group.
	return re.ReplaceAllStringFunc(input, func(match string) string {
		loc := re.FindStringSubmatchIndex(match)
		if loc == nil || len(loc) < 4 {
			return match
		}
		// loc[2], loc[3] are the start/end of the first capture group.
		groupStart := loc[2]
		groupEnd := loc[3]
		if groupStart < 0 || groupEnd < 0 {
			return match
		}
		return match[:groupStart] + payload + match[groupEnd:]
	})
}

// parseSimpleJSONPath parses a simplified JSON path expression.
// Supports: $.key1.key2, key1.key2 ($ prefix is optional).
func parseSimpleJSONPath(path string) ([]string, error) {
	if path == "" {
		return nil, fmt.Errorf("empty json_path")
	}
	path = strings.TrimPrefix(path, "$.")
	path = strings.TrimPrefix(path, "$")
	if path == "" {
		return nil, fmt.Errorf("json_path must reference at least one key")
	}
	keys := strings.Split(path, ".")
	for i, k := range keys {
		if k == "" {
			return nil, fmt.Errorf("json_path has empty key at position %d", i)
		}
	}
	return keys, nil
}

// setJSONValue sets a string value at the given key path in a JSON structure.
func setJSONValue(root any, keys []string, value string) error {
	if len(keys) == 0 {
		return fmt.Errorf("empty key path")
	}

	current := root
	for i := 0; i < len(keys)-1; i++ {
		m, ok := current.(map[string]any)
		if !ok {
			return fmt.Errorf("key %q: expected object, got %T", keys[i], current)
		}
		next, exists := m[keys[i]]
		if !exists {
			return fmt.Errorf("key %q not found", keys[i])
		}
		current = next
	}

	lastKey := keys[len(keys)-1]
	m, ok := current.(map[string]any)
	if !ok {
		return fmt.Errorf("key %q: expected object, got %T", lastKey, current)
	}
	m[lastKey] = value
	return nil
}
