package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// positionalArgMapping defines the positional argument mapping for each tool.
// The slice elements are the parameter names, in order, for bare-word arguments.
var positionalArgMapping = map[string][]string{
	"query":       {"resource", "id"},
	"execute":     {"action"},
	"proxy_start": {},
	"proxy_stop":  {},
	"configure":   {},
}

// toolSchema holds the parsed properties from a tool's JSON Schema InputSchema.
type toolSchema struct {
	// properties maps parameter name → type string (e.g. "string", "number", "boolean", "array", "object").
	properties map[string]string
	// required is the set of required parameter names.
	required map[string]bool
	// enums maps parameter name → allowed values.
	enums map[string][]string
}

// parseToolSchema extracts parameter info from a tool's InputSchema (map[string]any from JSON).
// Returns nil if schema is nil or not a map.
func parseToolSchema(inputSchema any) *toolSchema {
	if inputSchema == nil {
		return nil
	}
	m, ok := inputSchema.(map[string]any)
	if !ok {
		return nil
	}

	ts := &toolSchema{
		properties: make(map[string]string),
		required:   make(map[string]bool),
		enums:      make(map[string][]string),
	}
	parseSchemaRequired(ts, m)
	parseSchemaProperties(ts, m)
	return ts
}

// parseSchemaRequired fills ts.required from the "required" array in a JSON Schema map.
func parseSchemaRequired(ts *toolSchema, m map[string]any) {
	req, ok := m["required"]
	if !ok {
		return
	}
	reqSlice, ok := req.([]any)
	if !ok {
		return
	}
	for _, r := range reqSlice {
		if s, ok := r.(string); ok {
			ts.required[s] = true
		}
	}
}

// parseSchemaProperties fills ts.properties and ts.enums from the "properties" object in a JSON Schema map.
func parseSchemaProperties(ts *toolSchema, m map[string]any) {
	props, ok := m["properties"]
	if !ok {
		return
	}
	propsMap, ok := props.(map[string]any)
	if !ok {
		return
	}
	for name, propVal := range propsMap {
		propMap, ok := propVal.(map[string]any)
		if !ok {
			continue
		}
		ts.properties[name] = schemaPropertyType(propMap)
		if enumVals := schemaPropertyEnums(propMap); enumVals != nil {
			ts.enums[name] = enumVals
		}
	}
}

// schemaPropertyType returns the "type" string from a JSON Schema property map, defaulting to "string".
func schemaPropertyType(propMap map[string]any) string {
	if t, ok := propMap["type"]; ok {
		if ts, ok := t.(string); ok {
			return ts
		}
	}
	return "string"
}

// schemaPropertyEnums returns enum values from a JSON Schema property map, or nil if not present.
func schemaPropertyEnums(propMap map[string]any) []string {
	enumVal, ok := propMap["enum"]
	if !ok {
		return nil
	}
	enumSlice, ok := enumVal.([]any)
	if !ok {
		return nil
	}
	vals := make([]string, 0, len(enumSlice))
	for _, v := range enumSlice {
		vals = append(vals, fmt.Sprintf("%v", v))
	}
	return vals
}

// buildToolParams builds the tool parameters map from:
//   - toolName: used for positional argument mapping
//   - args: raw CLI arguments (positional bare-words + --key=value / key=value flags)
//   - schema: optional tool schema for type inference (may be nil)
//   - stderr: writer for warnings (usually os.Stderr)
//
// Returns (params, error).
func buildToolParams(toolName string, args []string, schema *toolSchema, stderr io.Writer) (map[string]any, error) {
	if stderr == nil {
		stderr = os.Stderr
	}
	posMapping := positionalArgMapping[toolName]
	posIndex := 0
	result := make(map[string]any)

	for _, arg := range args {
		stripped, isFlagStyle := stripFlagPrefix(arg)
		if stripped == "" {
			continue
		}

		idx := strings.IndexByte(stripped, '=')
		switch {
		case idx < 0 && !isFlagStyle:
			posIndex = applyPositionalArg(result, posMapping, posIndex, stripped, schema, stderr)
		case idx < 0 && isFlagStyle:
			result[stripped] = true
		default:
			key := stripped[:idx]
			if key != "" {
				applyKeyValue(result, key, stripped[idx+1:], schema)
			}
		}
	}

	if err := validateToolParams(result, schema, stderr); err != nil {
		return nil, err
	}
	return result, nil
}

// stripFlagPrefix removes leading "--" or "-" from an arg and reports whether the arg was flag-style.
func stripFlagPrefix(arg string) (stripped string, isFlagStyle bool) {
	if strings.HasPrefix(arg, "--") {
		return arg[2:], true
	}
	if strings.HasPrefix(arg, "-") {
		return arg[1:], true
	}
	return arg, false
}

// applyPositionalArg assigns a bare-word argument to its positional parameter name if available.
// Returns the updated posIndex.
func applyPositionalArg(result map[string]any, posMapping []string, posIndex int, value string, schema *toolSchema, stderr io.Writer) int {
	if posIndex < len(posMapping) {
		paramName := posMapping[posIndex]
		result[paramName] = coerceValue(paramName, value, schema)
		return posIndex + 1
	}
	fmt.Fprintf(stderr, "warning: extra positional argument %q ignored\n", value)
	return posIndex
}

// applyKeyValue sets a key-value pair in the result map.
// If key contains a "." (dot-notation), it expands into a nested map.
// For example, "filter.method" with value "POST" produces result["filter"] = {"method": "POST"}.
// If result["filter"] already exists as map[string]any, the child key is merged into it.
// Type coercion uses the schema's parent key properties if no direct match for the dot-notation key.
func applyKeyValue(result map[string]any, key, value string, schema *toolSchema) {
	dotIdx := strings.IndexByte(key, '.')
	if dotIdx < 0 {
		result[key] = coerceValue(key, value, schema)
		return
	}
	parent := key[:dotIdx]
	child := key[dotIdx+1:]
	nested, ok := result[parent].(map[string]any)
	if !ok {
		nested = make(map[string]any)
	}
	// Attempt type coercion using the child key directly; if not in schema, treat as string.
	nested[child] = coerceValue(child, value, schema)
	result[parent] = nested
}

// validateToolParams warns on unknown parameters and errors on missing required ones.
// For nested map values (produced by dot-notation expansion), the parent key is validated
// as an "object" type and child keys are not individually checked against the schema.
func validateToolParams(result map[string]any, schema *toolSchema, stderr io.Writer) error {
	if schema == nil {
		return nil
	}
	for key, val := range result {
		if _, known := schema.properties[key]; !known {
			// If the value is a nested map, it was produced by dot-notation expansion (e.g. filter.method=POST).
			// Accept it as a potential "object" parameter without warning.
			if _, isNested := val.(map[string]any); isNested {
				continue
			}
			fmt.Fprintf(stderr, "warning: unknown parameter %q (not in tool schema)\n", key)
		}
	}
	for param := range schema.required {
		if _, provided := result[param]; !provided {
			return missingRequiredParamError(param, schema)
		}
	}
	return nil
}

// missingRequiredParamError returns an error for a missing required parameter,
// including enum candidates if available.
func missingRequiredParamError(param string, schema *toolSchema) error {
	candidates := ""
	if enumVals, hasEnum := schema.enums[param]; hasEnum {
		candidates = fmt.Sprintf(" (one of: %s)", strings.Join(enumVals, ", "))
	}
	return fmt.Errorf("missing required parameter %q%s", param, candidates)
}

// coerceValue converts a string value to the appropriate Go type based on the schema.
// If schema is nil or the key is not found in the schema, returns the string as-is.
func coerceValue(key, value string, schema *toolSchema) any {
	if schema == nil {
		return value
	}
	typ, ok := schema.properties[key]
	if !ok {
		return value
	}
	switch typ {
	case "number", "integer":
		return coerceNumeric(value)
	case "boolean":
		return coerceBoolean(value)
	case "array":
		return parseArrayValue(value)
	default:
		return value
	}
}

// coerceNumeric parses a string as int64, then float64, falling back to string.
func coerceNumeric(value string) any {
	if i, err := strconv.ParseInt(value, 10, 64); err == nil {
		return i
	}
	if f, err := strconv.ParseFloat(value, 64); err == nil {
		return f
	}
	return value
}

// coerceBoolean parses a string as a boolean, returning the string unchanged on unrecognized values.
func coerceBoolean(value string) any {
	switch strings.ToLower(value) {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	}
	return value
}

// parseArrayValue splits a comma-separated value into a string slice.
// Single-quoted segments preserve commas within them.
// e.g. "a,b,c" → ["a","b","c"]
// e.g. "'a,b','c,d'" → ["a,b","c,d"]
func parseArrayValue(value string) []string {
	if value == "" {
		return []string{}
	}

	var result []string
	var current strings.Builder
	inQuote := false

	for i := 0; i < len(value); i++ {
		ch := value[i]
		switch {
		case ch == '\'' && !inQuote:
			inQuote = true
		case ch == '\'' && inQuote:
			inQuote = false
		case ch == ',' && !inQuote:
			result = append(result, current.String())
			current.Reset()
		default:
			current.WriteByte(ch)
		}
	}
	result = append(result, current.String())
	return result
}
