package main

import (
	"encoding/json"
	"errors"
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
	// schemas maps a top-level parameter name → its raw JSON Schema map, kept
	// whole (properties / items / additionalProperties) so a dot-notation path
	// of any depth and array items can be typed; see schemaAt and coerceAt.
	schemas map[string]map[string]any
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
		schemas:    make(map[string]map[string]any),
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

// parseSchemaProperties fills ts.properties, ts.schemas and ts.enums from the
// "properties" object in a JSON Schema map.
func parseSchemaProperties(ts *toolSchema, m map[string]any) {
	for name, propMap := range schemaPropertyMaps(m) {
		ts.properties[name] = schemaPropertyType(propMap)
		ts.schemas[name] = propMap
		if enumVals := schemaPropertyEnums(propMap); enumVals != nil {
			ts.enums[name] = enumVals
		}
	}
}

// topSchema returns the JSON Schema map of a top-level parameter, or nil when
// the parameter is undeclared (or ts is nil). A schema built without raw
// sub-schemas falls back to a synthetic {"type": <resolved type>} map.
func (ts *toolSchema) topSchema(name string) map[string]any {
	if ts == nil {
		return nil
	}
	if s, ok := ts.schemas[name]; ok {
		return s
	}
	if typ, ok := ts.properties[name]; ok {
		return map[string]any{"type": typ}
	}
	return nil
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
			if err := applyKeyValue(result, stripped[:idx], stripped[idx+1:], schema); err != nil {
				return nil, err
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

// applyKeyValue sets one key=value argument in the result map.
//
// The key is a dot-separated path of any depth: "filter.method=POST" produces
// result["filter"] = {"method": "POST"}, merging into an existing map. Each
// segment is resolved against the schema (see resolveKeyPath) and the leaf
// value is converted to the type the schema declares there (see coerceAt).
//
// A key ending in ":" ("key:=<json>") parses the value as JSON at any path,
// regardless of the schema (and with no schema at all) — the only way to send
// null, or a JSON value where the schema has no usable type.
//
// It returns an error, naming the path, only when a value that must be JSON
// does not parse as the JSON kind required there.
func applyKeyValue(result map[string]any, key, value string, schema *toolSchema) error {
	explicitJSON := strings.HasSuffix(key, ":")
	key = strings.TrimSuffix(key, ":")
	if key == "" {
		return nil
	}
	path, leaf := resolveKeyPath(key, schema)

	var v any
	var err error
	if explicitJSON {
		if v, err = decodeJSONValue(value); err != nil {
			return fmt.Errorf("%s: invalid JSON after \":=\": %w", key, err)
		}
	} else if v, err = coerceAt(leaf, value); err != nil {
		return fmt.Errorf("%s: %w", key, err)
	}
	setPath(result, path, v)
	return nil
}

// resolveKeyPath splits a dotted key into result-map path segments and
// returns the JSON Schema that applies to the leaf (nil when unknown).
//
// Every "." separates a segment, with one exception: once the walk reaches a
// map whose values are not objects (e.g. "vars": additionalProperties
// string), the remaining segments form a single map key, so
// "post_macro.vars.user.id" yields path [post_macro vars user.id].
func resolveKeyPath(key string, schema *toolSchema) ([]string, map[string]any) {
	segs := strings.Split(key, ".")
	s := schema.topSchema(segs[0])
	path := []string{segs[0]}
	for i := 1; i < len(segs); i++ {
		var joinRest bool
		s, joinRest = schemaChild(s, segs[i])
		if joinRest {
			return append(path, strings.Join(segs[i:], ".")), s
		}
		path = append(path, segs[i])
	}
	return path, s
}

// schemaChild returns the sub-schema for one dot segment below s: the
// declared property of that name or, failing that, the additionalProperties
// sub-schema when s is a map (the segment is then a map key). joinRest
// reports that the map's values are not objects, so no further dot segment
// can descend into them. A segment below an array, or one s does not
// declare, resolves to nil and the value is left as a string.
func schemaChild(s map[string]any, seg string) (child map[string]any, joinRest bool) {
	if s == nil {
		return nil, false
	}
	if c, ok := schemaPropertyMaps(s)[seg]; ok {
		return c, false
	}
	if ap, ok := s["additionalProperties"].(map[string]any); ok {
		return ap, schemaPropertyType(ap) != "object"
	}
	return nil, false
}

// setPath stores v in result at path, creating (or replacing non-map values
// with) intermediate maps. A later value at the same path wins.
func setPath(result map[string]any, path []string, v any) {
	cur := result
	for _, seg := range path[:len(path)-1] {
		next, ok := cur[seg].(map[string]any)
		if !ok {
			next = make(map[string]any)
			cur[seg] = next
		}
		cur = next
	}
	cur[path[len(path)-1]] = v
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

// coerceValue converts a top-level parameter's string value to the Go type
// its schema declares. If schema is nil, the key is not declared, or the value
// does not fit a JSON-only type, the string is returned as-is.
func coerceValue(key, value string, schema *toolSchema) any {
	v, err := coerceAt(schema.topSchema(key), value)
	if err != nil {
		return value
	}
	return v
}

// coerceAt converts a CLI string value to the Go type the JSON Schema s
// declares (nil s: returned unchanged).
//
// JSON is parsed only where the schema makes every non-JSON value invalid
// anyway — an object, or an array of objects / arrays — so no value that a
// string-typed (or untyped) parameter accepts ever changes meaning. Arrays of
// scalars keep the comma-separated form; see coerceArray.
func coerceAt(s map[string]any, value string) (any, error) {
	if s == nil {
		return value, nil
	}
	switch typ := schemaPropertyType(s); typ {
	case "object":
		return decodeJSONKind(value, "object")
	case "array":
		return coerceArray(s, value)
	default:
		return coerceTyped(typ, value), nil
	}
}

// coerceArray converts an array value according to the schema's items type:
//   - string (or no items): comma-separated, see parseArrayValue → []string
//   - object / array: the value must be a JSON array → []any
//   - integer / number / boolean: comma-separated, or a JSON array when the
//     value starts with "[", each element converted to the item type → []any
//
// An empty value is an empty array.
func coerceArray(s map[string]any, value string) (any, error) {
	if value == "" {
		return []string{}, nil
	}
	itemType := "string"
	if items, ok := s["items"].(map[string]any); ok {
		itemType = schemaPropertyType(items)
	}
	switch itemType {
	case "string":
		return parseArrayValue(value), nil
	case "object", "array":
		return decodeJSONKind(value, "array")
	default:
		return coerceScalarArray(itemType, value), nil
	}
}

// coerceScalarArray converts an array of integer / number / boolean items.
// A value starting with "[" that parses as a JSON array is taken as JSON (its
// numbers converted to the item type); anything else falls back to the comma
// form with each element converted by coerceTyped. An element that does not
// convert is left as-is, so the server's validation reports it.
func coerceScalarArray(itemType, value string) []any {
	if strings.HasPrefix(value, "[") {
		if decoded, err := decodeJSONValue(value); err == nil {
			if arr, ok := decoded.([]any); ok {
				for i, e := range arr {
					if n, isNum := e.(json.Number); isNum && itemType != "boolean" {
						arr[i] = coerceTyped(itemType, n.String())
					}
				}
				return arr
			}
		}
	}
	parts := parseArrayValue(value)
	out := make([]any, len(parts))
	for i, p := range parts {
		out[i] = coerceTyped(itemType, p)
	}
	return out
}

// decodeJSONKind decodes value as JSON and requires the result to be a JSON
// object (kind "object") or array (kind "array").
func decodeJSONKind(value, kind string) (any, error) {
	v, err := decodeJSONValue(value)
	if err != nil {
		return nil, fmt.Errorf("expected a JSON %s: %w", kind, err)
	}
	switch v.(type) {
	case map[string]any:
		if kind == "object" {
			return v, nil
		}
	case []any:
		if kind == "array" {
			return v, nil
		}
	}
	return nil, fmt.Errorf("expected a JSON %s, got %s", kind, jsonKind(v))
}

// jsonKind names the JSON kind of a decoded value for error messages.
func jsonKind(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case map[string]any:
		return "an object"
	case []any:
		return "an array"
	case string:
		return "a string"
	case bool:
		return "a boolean"
	default:
		return "a number"
	}
}

// decodeJSONValue decodes exactly one JSON value. Numbers are kept as
// json.Number so they re-marshal verbatim. Errors carry the byte offset at
// which decoding failed.
func decodeJSONValue(value string) (any, error) {
	dec := json.NewDecoder(strings.NewReader(value))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		var se *json.SyntaxError
		if errors.As(err, &se) {
			return nil, fmt.Errorf("%w (at offset %d)", err, se.Offset)
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("unexpected end of JSON input (at offset %d)", len(value))
		}
		return nil, err
	}
	end := dec.InputOffset()
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("unexpected data after the JSON value (at offset %d)", end)
	}
	return v, nil
}

// coerceTyped converts a string value to the Go type matching a resolved
// scalar JSON Schema type. A value that does not parse as that type is
// returned unchanged, so the server's schema validation reports it.
func coerceTyped(typ, value string) any {
	switch typ {
	case "integer":
		return coerceInteger(value)
	case "number":
		return coerceNumeric(value)
	case "boolean":
		return coerceBoolean(value)
	default:
		return value
	}
}

// coerceInteger parses a string as int64, truncating an in-range float.
func coerceInteger(value string) any {
	i, err := strconv.ParseInt(value, 10, 64)
	if err == nil {
		return i
	}
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
