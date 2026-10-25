package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/encoding"
)

// BodyPatch represents a single body modification operation.
// Either json_path+value or regex+replace must be specified (mutually exclusive).
type BodyPatch struct {
	// JSONPath is a dot-notation JSON path (e.g., "$.user.name") for JSON body patching.
	JSONPath string `json:"json_path,omitempty"`
	// Value is the replacement value when using JSONPath patching.
	Value any `json:"value,omitempty"`
	// Regex is a regular expression pattern for text-based body patching.
	Regex string `json:"regex,omitempty"`
	// Replace is the replacement string when using regex patching.
	// Supports capture group references ($1, $2, etc.).
	Replace string `json:"replace,omitempty"`
	// Encoding is an optional chain of codec names to apply to the patch value
	// before applying. For json_path patches, encoding is applied to string values only.
	// For regex patches, encoding is applied to the replace string.
	Encoding []string `json:"encoding,omitempty"`
	// ValueJSON is raw JSON text spliced verbatim (byte-exact, including any
	// leading/trailing whitespace) as the replacement value when using
	// JSONPath patching. Mutually exclusive with Value and Encoding; use it
	// when Value would lose information in the MCP JSON layer (big integers,
	// object key order, specific escapes).
	ValueJSON string `json:"value_json,omitempty" jsonschema:"raw JSON text spliced verbatim as the json_path replacement value, e.g. a big integer 12345678901234567890 passed as a string; exclusive with value and encoding"`
}

// validateBodyPatch checks that a BodyPatch has exactly one patch mode specified.
func validateBodyPatch(bp BodyPatch) error {
	hasJSON := bp.JSONPath != ""
	hasRegex := bp.Regex != ""
	if hasJSON && hasRegex {
		return fmt.Errorf("body_patch cannot have both json_path and regex")
	}
	if !hasJSON && !hasRegex {
		return fmt.Errorf("body_patch must specify either json_path or regex")
	}
	// Note: bp.Value == nil is valid (represents JSON null).
	// We cannot distinguish between "value not set" and "value set to null"
	// with the any type, so we do not reject nil values.

	if bp.ValueJSON != "" {
		if !hasJSON {
			return fmt.Errorf("body_patch value_json requires json_path (not valid with regex)")
		}
		if bp.Value != nil {
			return fmt.Errorf("body_patch cannot have both value and value_json")
		}
		if len(bp.Encoding) > 0 {
			return fmt.Errorf("body_patch value_json cannot be combined with encoding")
		}
		if !json.Valid([]byte(bp.ValueJSON)) {
			return fmt.Errorf("body_patch value_json is not valid JSON")
		}
	}

	// Validate encoding codec names if specified.
	if len(bp.Encoding) > 0 {
		if len(bp.Encoding) > maxEncodingChainLen {
			return fmt.Errorf("encoding chain length %d exceeds maximum of %d", len(bp.Encoding), maxEncodingChainLen)
		}
		reg := encoding.DefaultRegistry()
		for _, name := range bp.Encoding {
			if _, ok := reg.Get(name); !ok {
				return fmt.Errorf("unknown encoding codec %q; available codecs: %s", name, strings.Join(reg.List(), ", "))
			}
		}
	}

	return nil
}

// applyBodyPatches applies a sequence of BodyPatch operations to the given body bytes.
// Patches are applied in order. Returns the modified body.
func applyBodyPatches(body []byte, patches []BodyPatch) ([]byte, error) {
	for i, p := range patches {
		if err := validateBodyPatch(p); err != nil {
			return nil, fmt.Errorf("body_patches[%d]: %w", i, err)
		}

		// Apply encoding to patch values if specified.
		if len(p.Encoding) > 0 {
			var err error
			p, err = encodePatchValue(p)
			if err != nil {
				return nil, fmt.Errorf("body_patches[%d]: %w", i, err)
			}
		}

		var err error
		if p.JSONPath != "" {
			var replacement []byte
			if p.ValueJSON != "" {
				replacement = []byte(p.ValueJSON)
			} else if replacement, err = encodeJSONPatchValue(p.Value); err != nil {
				return nil, fmt.Errorf("body_patches[%d]: %w", i, err)
			}
			body, err = applyJSONPathPatch(body, p.JSONPath, replacement)
		} else {
			body, err = applyRegexPatch(body, p.Regex, p.Replace)
		}
		if err != nil {
			return nil, fmt.Errorf("body_patches[%d]: %w", i, err)
		}
	}
	return body, nil
}

// encodeJSONPatchValue encodes a json_path replacement value compactly with
// HTML escaping disabled, so "<", ">" and "&" are written as-is.
func encodeJSONPatchValue(value any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, fmt.Errorf("encode json_path value: %w", err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// applyJSONPathPatch replaces the value at path with the already-encoded
// JSON text replacement. Supports a simplified dot-notation path:
// $.key1.key2.key3 (array index notation is not supported).
//
// The edit is a byte splice: only the bytes of the target value change;
// key order, whitespace, escapes, number spelling, duplicate keys and any
// invalid UTF-8 elsewhere in the body are preserved exactly (MITM
// Principle 1). If an object on the path has duplicate keys, the last
// occurrence is followed / rewritten; earlier occurrences are left as is.
// The input slice is never modified; a new slice is returned.
func applyJSONPathPatch(body []byte, path string, replacement []byte) ([]byte, error) {
	// Parse the JSON path: $.foo.bar.baz -> ["foo", "bar", "baz"]
	keys, err := parseJSONPath(path)
	if err != nil {
		return nil, err
	}

	if !json.Valid(body) {
		// Re-run the standard decoder only to obtain a descriptive error.
		var discard json.RawMessage
		err := json.Unmarshal(body, &discard)
		return nil, fmt.Errorf("body is not valid JSON: %w", err)
	}

	start, end, err := locateJSONPath(body, keys)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(body)-(end-start)+len(replacement))
	out = append(out, body[:start]...)
	out = append(out, replacement...)
	out = append(out, body[end:]...)
	return out, nil
}

// errJSONScan is returned when the scanner runs past the end of the body or
// meets an unexpected byte. It cannot happen on json.Valid input, but the
// scanner is bounds-checked anyway because bodies are attacker-controlled.
var errJSONScan = errors.New("body is not valid JSON: unexpected structure")

// locateJSONPath returns the [start,end) byte span of the value addressed by
// keys in body. body must already have passed json.Valid.
func locateJSONPath(body []byte, keys []string) (int, int, error) {
	cur := skipJSONWhitespace(body, 0)
	for idx, key := range keys {
		if cur >= len(body) {
			return 0, 0, errJSONScan
		}
		if body[cur] != '{' {
			return 0, 0, fmt.Errorf("json_path key %q: expected object, got %s", key, jsonKindName(body[cur]))
		}
		valStart, valEnd, found, err := findJSONMember(body, cur, key)
		if err != nil {
			return 0, 0, err
		}
		if !found {
			return 0, 0, fmt.Errorf("json_path key %q not found", key)
		}
		if idx == len(keys)-1 {
			return valStart, valEnd, nil
		}
		cur = valStart
	}
	// Unreachable: parseJSONPath guarantees at least one key.
	return 0, 0, fmt.Errorf("empty key path")
}

// findJSONMember scans the object starting at body[objStart] == '{' and
// returns the value span of the LAST member whose decoded key equals key.
func findJSONMember(body []byte, objStart int, key string) (valStart, valEnd int, found bool, err error) {
	i := skipJSONWhitespace(body, objStart+1)
	if i < len(body) && body[i] == '}' {
		return 0, 0, false, nil
	}
	for {
		if i >= len(body) || body[i] != '"' {
			return 0, 0, false, errJSONScan
		}
		keyEnd, err := skipJSONString(body, i)
		if err != nil {
			return 0, 0, false, err
		}
		var decoded string
		if err := json.Unmarshal(body[i:keyEnd], &decoded); err != nil {
			return 0, 0, false, fmt.Errorf("decode object key: %w", err)
		}
		i = skipJSONWhitespace(body, keyEnd)
		if i >= len(body) || body[i] != ':' {
			return 0, 0, false, errJSONScan
		}
		vs := skipJSONWhitespace(body, i+1)
		ve, err := skipJSONValue(body, vs)
		if err != nil {
			return 0, 0, false, err
		}
		if decoded == key {
			valStart, valEnd, found = vs, ve, true
		}
		i = skipJSONWhitespace(body, ve)
		if i >= len(body) {
			return 0, 0, false, errJSONScan
		}
		switch body[i] {
		case ',':
			i = skipJSONWhitespace(body, i+1)
		case '}':
			return valStart, valEnd, found, nil
		default:
			return 0, 0, false, errJSONScan
		}
	}
}

// skipJSONWhitespace returns the index of the first non-whitespace byte at
// or after i (RFC 8259 insignificant whitespace).
func skipJSONWhitespace(body []byte, i int) int {
	for i < len(body) {
		switch body[i] {
		case ' ', '\t', '\n', '\r':
			i++
		default:
			return i
		}
	}
	return i
}

// skipJSONString returns the index just past the string starting at
// body[i] == '"', honouring backslash escapes.
func skipJSONString(body []byte, i int) (int, error) {
	for i++; i < len(body); i++ {
		switch body[i] {
		case '\\':
			i++
		case '"':
			return i + 1, nil
		}
	}
	return 0, errJSONScan
}

// skipJSONValue returns the index just past the value starting at body[i].
// Containers are skipped iteratively with a depth counter (no recursion).
func skipJSONValue(body []byte, i int) (int, error) {
	if i >= len(body) {
		return 0, errJSONScan
	}
	switch body[i] {
	case '"':
		return skipJSONString(body, i)
	case '{', '[':
		depth := 0
		for i < len(body) {
			switch body[i] {
			case '"':
				end, err := skipJSONString(body, i)
				if err != nil {
					return 0, err
				}
				i = end
				continue
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return i + 1, nil
				}
			}
			i++
		}
		return 0, errJSONScan
	default:
		// Number or literal (true / false / null): runs to the next
		// delimiter or whitespace.
		start := i
		for i < len(body) {
			switch body[i] {
			case ',', '}', ']', ' ', '\t', '\n', '\r':
				if i == start {
					return 0, errJSONScan
				}
				return i, nil
			}
			i++
		}
		return i, nil
	}
}

// jsonKindName names the JSON value kind that starts with byte c.
func jsonKindName(c byte) string {
	switch c {
	case '{':
		return "object"
	case '[':
		return "array"
	case '"':
		return "string"
	case 't', 'f':
		return "boolean"
	case 'n':
		return "null"
	default:
		return "number"
	}
}

// parseJSONPath parses a simplified JSON path expression.
// Supports: $.key1.key2, key1.key2 ($ prefix is optional).
func parseJSONPath(path string) ([]string, error) {
	if path == "" {
		return nil, fmt.Errorf("empty json_path")
	}
	// Strip the optional root indicator.
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

// maxEncodingChainLen is the maximum number of codecs allowed in an encoding chain
// to prevent excessive CPU consumption from very long chains.
const maxEncodingChainLen = 10

// maxRegexPatternLen is the maximum allowed length for regex patterns in body patches.
// This prevents resource exhaustion from very large patterns during compilation and matching.
const maxRegexPatternLen = 1024

// encodePatchValue applies the encoding chain to the patch value.
// For json_path patches, encoding is applied to string values only.
// For regex patches, encoding is applied to the replace string.
func encodePatchValue(p BodyPatch) (BodyPatch, error) {
	if p.JSONPath != "" {
		// Only encode string values for JSON path patches.
		if strVal, ok := p.Value.(string); ok {
			encoded, err := encoding.Encode(strVal, p.Encoding)
			if err != nil {
				return p, fmt.Errorf("encode json_path value: %w", err)
			}
			p.Value = encoded
		}
	} else {
		// Encode the replace string for regex patches.
		encoded, err := encoding.Encode(p.Replace, p.Encoding)
		if err != nil {
			return p, fmt.Errorf("encode regex replace: %w", err)
		}
		p.Replace = encoded
	}
	return p, nil
}

// applyRegexPatch applies a regex replacement to the body text.
func applyRegexPatch(body []byte, pattern, replace string) ([]byte, error) {
	if len(pattern) > maxRegexPatternLen {
		return nil, fmt.Errorf("regex pattern too long: %d > %d", len(pattern), maxRegexPatternLen)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex %q: %w", pattern, err)
	}
	result := re.ReplaceAll(body, []byte(replace))
	return result, nil
}
