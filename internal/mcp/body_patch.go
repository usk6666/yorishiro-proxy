package mcp

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
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
	return nil
}

// applyBodyPatches applies a sequence of BodyPatch operations to the given body bytes.
// Patches are applied in order. Returns the modified body.
func applyBodyPatches(body []byte, patches []BodyPatch) ([]byte, error) {
	for i, p := range patches {
		if err := validateBodyPatch(p); err != nil {
			return nil, fmt.Errorf("body_patches[%d]: %w", i, err)
		}
		var err error
		if p.JSONPath != "" {
			body, err = applyJSONPathPatch(body, p.JSONPath, p.Value)
		} else {
			body, err = applyRegexPatch(body, p.Regex, p.Replace)
		}
		if err != nil {
			return nil, fmt.Errorf("body_patches[%d]: %w", i, err)
		}
	}
	return body, nil
}

// applyJSONPathPatch applies a JSON path patch to the body.
// Supports a simplified dot-notation path: $.key1.key2.key3
// Array index notation is not supported.
func applyJSONPathPatch(body []byte, path string, value any) ([]byte, error) {
	// Parse the JSON path: $.foo.bar.baz -> ["foo", "bar", "baz"]
	keys, err := parseJSONPath(path)
	if err != nil {
		return nil, err
	}

	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, fmt.Errorf("body is not valid JSON: %w", err)
	}

	if err := setNestedValue(root, keys, value); err != nil {
		return nil, err
	}

	result, err := json.Marshal(root)
	if err != nil {
		return nil, fmt.Errorf("marshal patched JSON: %w", err)
	}
	return result, nil
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

// setNestedValue sets a value at the given key path in a JSON structure.
func setNestedValue(root any, keys []string, value any) error {
	if len(keys) == 0 {
		return fmt.Errorf("empty key path")
	}

	current := root
	for i := 0; i < len(keys)-1; i++ {
		m, ok := current.(map[string]any)
		if !ok {
			return fmt.Errorf("json_path key %q: expected object, got %T", keys[i], current)
		}
		next, exists := m[keys[i]]
		if !exists {
			return fmt.Errorf("json_path key %q not found", keys[i])
		}
		current = next
	}

	lastKey := keys[len(keys)-1]
	m, ok := current.(map[string]any)
	if !ok {
		return fmt.Errorf("json_path key %q: expected object, got %T", lastKey, current)
	}
	if _, exists := m[lastKey]; !exists {
		return fmt.Errorf("json_path key %q not found", lastKey)
	}
	m[lastKey] = value
	return nil
}

// maxRegexPatternLen is the maximum allowed length for regex patterns in body patches.
// This prevents resource exhaustion from very large patterns during compilation and matching.
const maxRegexPatternLen = 1024

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
