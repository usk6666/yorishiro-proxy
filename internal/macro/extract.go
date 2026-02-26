package macro

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ExtractValues applies extraction rules to a request/response pair and stores
// results in the KV Store. Returns an error if a required extraction fails.
func ExtractValues(rules []ExtractionRule, req *SendRequest, resp *SendResponse, kvStore map[string]string) error {
	for _, rule := range rules {
		value, err := extractSingle(rule, req, resp)
		if err != nil {
			if rule.Required {
				return fmt.Errorf("required extraction %q failed: %w", rule.Name, err)
			}
			if rule.Default != "" {
				kvStore[rule.Name] = rule.Default
			}
			continue
		}
		kvStore[rule.Name] = value
	}
	return nil
}

// extractSingle extracts a single value according to the given rule.
func extractSingle(rule ExtractionRule, req *SendRequest, resp *SendResponse) (string, error) {
	switch rule.Source {
	case ExtractionSourceHeader:
		return extractHeader(rule, req, resp)
	case ExtractionSourceBody:
		return extractBody(rule, req, resp)
	case ExtractionSourceBodyJSON:
		return extractBodyJSON(rule, req, resp)
	case ExtractionSourceStatus:
		return extractStatus(rule, resp)
	case ExtractionSourceURL:
		return extractURL(rule, req, resp)
	default:
		return "", fmt.Errorf("unsupported extraction source %q", rule.Source)
	}
}

// selectData returns the appropriate data based on the extraction rule's From field.
func selectHeaders(rule ExtractionRule, req *SendRequest, resp *SendResponse) map[string][]string {
	if rule.From == ExtractionFromRequest {
		if req == nil {
			return nil
		}
		return req.Headers
	}
	if resp == nil {
		return nil
	}
	return resp.Headers
}

func selectBody(rule ExtractionRule, req *SendRequest, resp *SendResponse) []byte {
	if rule.From == ExtractionFromRequest {
		if req == nil {
			return nil
		}
		return req.Body
	}
	if resp == nil {
		return nil
	}
	return resp.Body
}

func extractHeader(rule ExtractionRule, req *SendRequest, resp *SendResponse) (string, error) {
	if rule.HeaderName == "" {
		return "", fmt.Errorf("header_name is required for header extraction")
	}

	headers := selectHeaders(rule, req, resp)
	if headers == nil {
		return "", fmt.Errorf("no headers available")
	}

	// Look up the header (case-insensitive via canonical form).
	values := findHeader(headers, rule.HeaderName)
	if len(values) == 0 {
		return "", fmt.Errorf("header %q not found", rule.HeaderName)
	}

	// Concatenate all values for matching.
	combined := strings.Join(values, ", ")

	if rule.Regex == "" {
		return combined, nil
	}

	return matchRegex(combined, rule.Regex, rule.Group)
}

func extractBody(rule ExtractionRule, req *SendRequest, resp *SendResponse) (string, error) {
	body := selectBody(rule, req, resp)
	if len(body) == 0 {
		return "", fmt.Errorf("empty body")
	}

	if rule.Regex == "" {
		return string(body), nil
	}

	return matchRegex(string(body), rule.Regex, rule.Group)
}

func extractBodyJSON(rule ExtractionRule, req *SendRequest, resp *SendResponse) (string, error) {
	body := selectBody(rule, req, resp)
	if len(body) == 0 {
		return "", fmt.Errorf("empty body")
	}

	if rule.JSONPath == "" {
		return "", fmt.Errorf("json_path is required for body_json extraction")
	}

	return evaluateJSONPath(body, rule.JSONPath)
}

func extractStatus(rule ExtractionRule, resp *SendResponse) (string, error) {
	if resp == nil {
		return "", fmt.Errorf("no response available")
	}
	return strconv.Itoa(resp.StatusCode), nil
}

func extractURL(rule ExtractionRule, req *SendRequest, resp *SendResponse) (string, error) {
	var urlStr string
	if rule.From == ExtractionFromRequest {
		if req == nil {
			return "", fmt.Errorf("no request available")
		}
		urlStr = req.URL
	} else {
		if resp == nil {
			return "", fmt.Errorf("no response available")
		}
		urlStr = resp.URL
		if urlStr == "" {
			// Fallback: try Location header.
			locations := findHeader(resp.Headers, "Location")
			if len(locations) > 0 {
				urlStr = locations[0]
			}
		}
	}

	if urlStr == "" {
		return "", fmt.Errorf("no URL available")
	}

	if rule.Regex == "" {
		return urlStr, nil
	}

	return matchRegex(urlStr, rule.Regex, rule.Group)
}

// matchRegex applies a regex pattern and returns the specified capture group.
func matchRegex(input, pattern string, group int) (string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", fmt.Errorf("invalid regex %q: %w", pattern, err)
	}

	matches := re.FindStringSubmatch(input)
	if matches == nil {
		return "", fmt.Errorf("regex %q did not match", pattern)
	}

	if group < 0 || group >= len(matches) {
		return "", fmt.Errorf("regex group %d out of range (matched %d groups)", group, len(matches)-1)
	}

	return matches[group], nil
}

// findHeader does a case-insensitive header lookup across potentially
// non-canonical header maps.
func findHeader(headers map[string][]string, name string) []string {
	lowerName := strings.ToLower(name)
	for k, v := range headers {
		if strings.ToLower(k) == lowerName {
			return v
		}
	}
	return nil
}

// evaluateJSONPath implements a minimal JSON Path evaluator supporting
// dot-notation paths like "$.foo.bar" and "$.foo[0].bar".
// It does not implement the full JSON Path specification.
func evaluateJSONPath(data []byte, path string) (string, error) {
	if !strings.HasPrefix(path, "$") {
		return "", fmt.Errorf("json_path must start with $")
	}

	var root interface{}
	if err := json.Unmarshal(data, &root); err != nil {
		return "", fmt.Errorf("invalid JSON: %w", err)
	}

	// Remove leading "$" and optional "." after it.
	remainder := path[1:]
	if strings.HasPrefix(remainder, ".") {
		remainder = remainder[1:]
	}

	if remainder == "" {
		return jsonValueToString(root)
	}

	current := root
	segments := splitJSONPathSegments(remainder)

	for _, seg := range segments {
		var err error
		current, err = resolveJSONSegment(current, seg)
		if err != nil {
			return "", fmt.Errorf("json_path %q: %w", path, err)
		}
	}

	return jsonValueToString(current)
}

// splitJSONPathSegments splits a JSON path into segments.
// Handles both dot notation (foo.bar) and bracket notation (foo[0]).
func splitJSONPathSegments(path string) []string {
	var segments []string
	var current strings.Builder

	for i := 0; i < len(path); i++ {
		switch path[i] {
		case '.':
			if current.Len() > 0 {
				segments = append(segments, current.String())
				current.Reset()
			}
		case '[':
			if current.Len() > 0 {
				segments = append(segments, current.String())
				current.Reset()
			}
			// Find closing bracket.
			end := strings.IndexByte(path[i:], ']')
			if end == -1 {
				current.WriteByte(path[i])
				continue
			}
			segments = append(segments, path[i:i+end+1])
			i += end
		default:
			current.WriteByte(path[i])
		}
	}

	if current.Len() > 0 {
		segments = append(segments, current.String())
	}

	return segments
}

// resolveJSONSegment resolves a single segment against a JSON value.
func resolveJSONSegment(current interface{}, segment string) (interface{}, error) {
	// Array index: [N]
	if strings.HasPrefix(segment, "[") && strings.HasSuffix(segment, "]") {
		idxStr := segment[1 : len(segment)-1]
		idx, err := strconv.Atoi(idxStr)
		if err != nil {
			return nil, fmt.Errorf("invalid array index %q", idxStr)
		}
		arr, ok := current.([]interface{})
		if !ok {
			return nil, fmt.Errorf("expected array, got %T", current)
		}
		if idx < 0 || idx >= len(arr) {
			return nil, fmt.Errorf("array index %d out of bounds (length %d)", idx, len(arr))
		}
		return arr[idx], nil
	}

	// Object key.
	obj, ok := current.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("expected object, got %T", current)
	}
	val, exists := obj[segment]
	if !exists {
		return nil, fmt.Errorf("key %q not found", segment)
	}
	return val, nil
}

// jsonValueToString converts a JSON value to its string representation.
func jsonValueToString(v interface{}) (string, error) {
	switch val := v.(type) {
	case string:
		return val, nil
	case float64:
		// Format without trailing zeros for integers.
		if val == float64(int64(val)) {
			return strconv.FormatInt(int64(val), 10), nil
		}
		return strconv.FormatFloat(val, 'f', -1, 64), nil
	case bool:
		return strconv.FormatBool(val), nil
	case nil:
		return "", fmt.Errorf("null value")
	default:
		// For objects/arrays, marshal back to JSON string.
		b, err := json.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("marshal json value: %w", err)
		}
		return string(b), nil
	}
}
