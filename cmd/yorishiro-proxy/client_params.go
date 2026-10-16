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
//
// Typed tools (resend_http/ws/grpc/raw, fuzz_http/ws/grpc/raw, plugin_introspect)
// have no "action" concept — every parameter is named explicitly in the
// InputSchema — so most carry an empty positional slice. The remaining
// shared / cross-cutting tools keep "action" as the first positional for
// convenience, matching their pre-typed-split CLI ergonomics.
var positionalArgMapping = map[string][]string{
	"docs":              {"topic", "section"},
	"query":             {"resource", "id"},
	"intercept":         {"action"},
	"manage":            {"action"},
	"security":          {"action"},
	"macro":             {"action"},
	"proxy_start":       {},
	"proxy_stop":        {},
	"configure":         {},
	"resend_http":       {},
	"resend_ws":         {},
	"resend_grpc":       {},
	"resend_raw":        {},
	"fuzz_http":         {},
	"fuzz_ws":           {},
	"fuzz_grpc":         {},
	"fuzz_raw":          {},
	"plugin_introspect": {},
	"grpc_schema":       {"action"},
}

// toolSchema holds the parsed properties from a tool's JSON Schema InputSchema.
type toolSchema struct {
	// properties maps parameter name → type string (e.g. "string", "number", "boolean", "array", "object").
	// A nullable JSON Schema type array (e.g. ["null", "integer"]) is resolved to its
	// non-null member; see schemaPropertyType.
	properties map[string]string
	// nested maps a top-level parameter name → child name → resolved type string,
	// taken from that parameter's own "properties". It types dot-notation
	// children (e.g. params.older_than_days=7) against the parent's schema.
	nested map[string]map[string]string
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
		nested:     make(map[string]map[string]string),
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

// parseSchemaProperties fills ts.properties, ts.nested and ts.enums from the
// "properties" object in a JSON Schema map.
func parseSchemaProperties(ts *toolSchema, m map[string]any) {
	for name, propMap := range schemaPropertyMaps(m) {
		ts.properties[name] = schemaPropertyType(propMap)
		if enumVals := schemaPropertyEnums(propMap); enumVals != nil {
			ts.enums[name] = enumVals
		}
		children := schemaPropertyMaps(propMap)
		if len(children) == 0 {
			continue
		}
		childTypes := make(map[string]string, len(children))
		for child, childMap := range children {
			childTypes[child] = schemaPropertyType(childMap)
		}
		ts.nested[name] = childTypes
	}
}

// schemaPropertyMaps returns the property-name → property-schema entries of the
// "properties" object in a JSON Schema map, skipping entries that are not objects.
// Returns nil when there is no usable "properties" object.
func schemaPropertyMaps(m map[string]any) map[string]map[string]any {
	propsMap, ok := m["properties"].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]map[string]any, len(propsMap))
	for name, propVal := range propsMap {
		if propMap, ok := propVal.(map[string]any); ok {
			out[name] = propMap
		}
	}
	return out
}

// schemaPropertyType returns the type of a JSON Schema property map, defaulting to "string".
//
// "type" may be a string or, per JSON Schema 2020-12 §6.1.1, an array of type names.
// The MCP server's schema generator renders every optional (pointer / slice) field
// as ["null", X]. For an array the first string element that is not "null" is used,
// regardless of its position; an array with no such element resolves to "string".
func schemaPropertyType(propMap map[string]any) string {
	switch t := propMap["type"].(type) {
	case string:
		return t
	case []any:
		for _, elem := range t {
			if s, ok := elem.(string); ok && s != "null" {
				return s
			}
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
// A dot-notation child is typed against the parent property's own schema
// (schema.nested[parent][child]); a child the parent does not declare stays a string.
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
	nested[child] = coerceNestedValue(parent, child, value, schema)
	result[parent] = nested
}

// coerceNestedValue converts a dot-notation child value using the type the
// parent property's schema declares for that child. If schema is nil or the
// child is not declared, returns the string as-is.
func coerceNestedValue(parent, child, value string, schema *toolSchema) any {
	if schema == nil {
		return value
	}
	typ, ok := schema.nested[parent][child]
	if !ok {
		return value
	}
	return coerceTyped(typ, value)
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
	return coerceTyped(typ, value)
}

// coerceTyped converts a string value to the Go type matching a resolved JSON
// Schema type. A value that does not parse as that type is returned unchanged,
// so the server's schema validation reports it.
func coerceTyped(typ, value string) any {
	switch typ {
	case "integer":
		i, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			// Try float and truncate to int64. NaN, ±Inf and values outside
			// [-2^63, 2^63) have no int64 form (the conversion is
			// implementation-defined), so leave them for server validation.
			// The upper bound is exclusive because float64(math.MaxInt64)
			// rounds up to 2^63.
			f, ferr := strconv.ParseFloat(value, 64)
			if ferr != nil || !(f >= -9223372036854775808.0 && f < 9223372036854775808.0) {
				return value
			}
			return int64(f)
		}
		return i
	case "number":
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
// A doubled single quote (”) inside a quoted segment is an escaped literal single quote.
// e.g. "a,b,c" → ["a","b","c"]
// e.g. "'a,b','c,d'" → ["a,b","c,d"]
// e.g. "'it”s'" → ["it's"]
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
			// Check for doubled single quote ('') — escaped literal quote.
			if i+1 < len(value) && value[i+1] == '\'' {
				current.WriteByte('\'')
				i++ // skip the second quote
			} else {
				inQuote = false
			}
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
