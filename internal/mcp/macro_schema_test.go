package mcp

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/macro"
)

// USK-1034: the macro tool schema is the only macro documentation an agent
// sees without reading an MCP resource. These tests guard the two failure
// modes that made the reported incident possible: the §var§ syntax being
// absent from the tool surface, and a jsonschema tag silently disappearing
// (renamed field, dropped tag) so a field degrades to "string, no
// description".

// macroToolSchema returns the macro tool's generated InputSchema as a
// decoded JSON object, exactly as an MCP client receives it from tools/list.
func macroToolSchema(t *testing.T) map[string]any {
	t.Helper()

	cs := setupResourceTestSession(t)
	result, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	var tool *gomcp.Tool
	for _, tl := range result.Tools {
		if tl.Name == "macro" {
			tool = tl
			break
		}
	}
	if tool == nil {
		t.Fatal("macro tool not found in tools/list")
	}
	if tool.InputSchema == nil {
		t.Fatal("macro tool has no InputSchema")
	}

	raw, err := json.Marshal(tool.InputSchema)
	if err != nil {
		t.Fatalf("marshal InputSchema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("unmarshal InputSchema: %v", err)
	}
	return schema
}

// macroToolDescription returns the macro tool's Description from tools/list.
func macroToolDescription(t *testing.T) string {
	t.Helper()

	cs := setupResourceTestSession(t)
	result, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	for _, tl := range result.Tools {
		if tl.Name == "macro" {
			return tl.Description
		}
	}
	t.Fatal("macro tool not found in tools/list")
	return ""
}

// navSchema walks a decoded JSON schema along the given path, failing the
// test if any segment is missing or is not an object.
func navSchema(t *testing.T, schema map[string]any, path ...string) map[string]any {
	t.Helper()

	cur := schema
	for i, seg := range path {
		next, ok := cur[seg]
		if !ok {
			t.Fatalf("schema path %q: segment %q not found", strings.Join(path[:i+1], "."), seg)
		}
		obj, ok := next.(map[string]any)
		if !ok {
			t.Fatalf("schema path %q: segment %q is %T, want object", strings.Join(path[:i+1], "."), seg, next)
		}
		cur = obj
	}
	return cur
}

// schemaDescription returns the description of the named property under the
// given properties object.
func schemaDescription(t *testing.T, props map[string]any, field string) string {
	t.Helper()

	raw, ok := props[field]
	if !ok {
		t.Fatalf("property %q not found (properties: %v)", field, sortedSchemaKeys(props))
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("property %q is %T, want object", field, raw)
	}
	desc, _ := obj["description"].(string)
	return desc
}

// sortedSchemaKeys returns the map keys in deterministic order.
func sortedSchemaKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// macroStepProperties returns the properties of a macro step object in the
// generated schema (params.steps.items).
func macroStepProperties(t *testing.T, schema map[string]any) map[string]any {
	t.Helper()
	return navSchema(t, schema, "properties", "params", "properties", "steps", "items", "properties")
}

// TestMacroToolSchema_OverrideFieldsDocumentTemplateSyntax asserts that all
// FOUR template expansion sites name the §var§ syntax in their generated
// description. override_method is included deliberately: it expands too
// (internal/macro/engine.go buildRequest), and the documentation previously
// claimed otherwise.
func TestMacroToolSchema_OverrideFieldsDocumentTemplateSyntax(t *testing.T) {
	props := macroStepProperties(t, macroToolSchema(t))

	for _, field := range []string{"override_method", "override_url", "override_headers", "override_body"} {
		t.Run(field, func(t *testing.T) {
			desc := schemaDescription(t, props, field)
			if desc == "" {
				t.Fatalf("%s has no description; the jsonschema tag was dropped", field)
			}
			if !strings.Contains(desc, macro.DelimOpen) {
				t.Errorf("%s description does not mention the %s template delimiter: %q",
					field, macro.DelimOpen, desc)
			}
		})
	}
}

// TestMacroToolSchema_VarsDocumentTemplateSyntax asserts that the two KV
// Store entry points explain how a step references their keys.
func TestMacroToolSchema_VarsDocumentTemplateSyntax(t *testing.T) {
	props := navSchema(t, macroToolSchema(t), "properties", "params", "properties")

	for _, field := range []string{"initial_vars", "vars"} {
		t.Run(field, func(t *testing.T) {
			desc := schemaDescription(t, props, field)
			if !strings.Contains(desc, macro.DelimOpen) {
				t.Errorf("%s description does not mention the %s template delimiter: %q",
					field, macro.DelimOpen, desc)
			}
		})
	}
}

// TestMacroToolSchema_EveryFieldDocumented asserts that every property of
// every macro input object carries a non-empty description. A newly added Go
// field without a jsonschema tag fails here.
func TestMacroToolSchema_EveryFieldDocumented(t *testing.T) {
	schema := macroToolSchema(t)

	objects := map[string]map[string]any{
		"params.steps[].when":    navSchema(t, schema, "properties", "params", "properties", "steps", "items", "properties", "when", "properties"),
		"params.steps[].extract": navSchema(t, schema, "properties", "params", "properties", "steps", "items", "properties", "extract", "items", "properties"),
		"params.steps[]":         macroStepProperties(t, schema),
		"params":                 navSchema(t, schema, "properties", "params", "properties"),
		"(root)":                 navSchema(t, schema, "properties"),
	}

	for _, objName := range sortedObjectNames(objects) {
		props := objects[objName]
		for _, field := range sortedSchemaKeys(props) {
			if desc := schemaDescription(t, props, field); strings.TrimSpace(desc) == "" {
				t.Errorf("%s.%s has no description in the generated schema", objName, field)
			}
		}
	}
}

// sortedObjectNames returns the object names in deterministic order.
func sortedObjectNames(m map[string]map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TestMacroToolSchema_StepDefaultsMatchEngine asserts the documented defaults
// and limits agree with the macro engine constants. jsonschema tags cannot
// express default/minimum structurally (a "WORD=" prefix panics AddTool), so
// they are prose — and prose drifts silently without this test.
func TestMacroToolSchema_StepDefaultsMatchEngine(t *testing.T) {
	schema := macroToolSchema(t)
	props := macroStepProperties(t, schema)

	tests := []struct {
		field string
		want  []string
	}{
		{"on_error", []string{string(macro.OnErrorAbort), string(macro.OnErrorSkip), string(macro.OnErrorRetry)}},
		{"retry_count", []string{"3", "10"}}, // DefaultRetryCount / MaxRetryCount
		{"retry_delay_ms", []string{"1000"}}, // DefaultRetryDelayMs
		{"timeout_ms", []string{"60000"}},    // DefaultStepTimeoutMs
	}
	for _, tc := range tests {
		t.Run(tc.field, func(t *testing.T) {
			desc := schemaDescription(t, props, tc.field)
			for _, want := range tc.want {
				if !strings.Contains(desc, want) {
					t.Errorf("%s description %q does not mention %q", tc.field, desc, want)
				}
			}
		})
	}

	if macro.DefaultRetryCount != 3 || macro.MaxRetryCount != 10 ||
		macro.DefaultRetryDelayMs != 1000 || macro.DefaultStepTimeoutMs != 60000 {
		t.Errorf("macro engine defaults changed; update the macroStepInput jsonschema tags: "+
			"retry=%d/%d delay=%d timeout=%d",
			macro.DefaultRetryCount, macro.MaxRetryCount, macro.DefaultRetryDelayMs, macro.DefaultStepTimeoutMs)
	}

	// params.macro_timeout_ms documents DefaultMacroTimeoutMs; params.steps
	// documents MaxSteps.
	paramsProps := navSchema(t, schema, "properties", "params", "properties")
	if desc := schemaDescription(t, paramsProps, "macro_timeout_ms"); !strings.Contains(desc, "300000") {
		t.Errorf("macro_timeout_ms description %q does not mention the default 300000", desc)
	}
	if macro.DefaultMacroTimeoutMs != 300000 {
		t.Errorf("DefaultMacroTimeoutMs = %d; update the macro_timeout_ms jsonschema tag", macro.DefaultMacroTimeoutMs)
	}
	if desc := schemaDescription(t, paramsProps, "steps"); !strings.Contains(desc, "50") {
		t.Errorf("steps description %q does not mention the maximum 50", desc)
	}
	if macro.MaxSteps != 50 {
		t.Errorf("MaxSteps = %d; update the steps jsonschema tag", macro.MaxSteps)
	}

	// The ReDoS caps (CWE-1333) documented on extract[].regex and on the two
	// guard regex fields are security-relevant limits: drift here misleads an
	// agent about how much input is actually scanned.
	extractProps := navSchema(t, props, "extract", "items", "properties")
	whenProps := navSchema(t, props, "when", "properties")
	for _, tc := range []struct {
		name  string
		props map[string]any
		field string
		want  []string
	}{
		{"extract.regex", extractProps, "regex", []string{"1024", "1 MiB"}},
		{"when.header_match", whenProps, "header_match", []string{"1024"}},
		{"when.body_match", whenProps, "body_match", []string{"1024", "1 MiB"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			desc := schemaDescription(t, tc.props, tc.field)
			for _, want := range tc.want {
				if !strings.Contains(desc, want) {
					t.Errorf("%s description %q does not mention %q", tc.name, desc, want)
				}
			}
		})
	}
	if macro.MaxRegexPatternLen != 1024 || macro.MaxRegexInputSize != 1<<20 || macro.MaxStepBodySize != 1<<20 {
		t.Errorf("macro regex/body caps changed; update the regex, header_match and body_match "+
			"jsonschema tags: pattern=%d input=%d body=%d",
			macro.MaxRegexPatternLen, macro.MaxRegexInputSize, macro.MaxStepBodySize)
	}
}

// TestMacroToolDescription_DocumentsTemplateSyntax asserts the tool
// Description carries both the positive example (§var§) and the
// counter-example ({{var}}) the reported incident needed.
func TestMacroToolDescription_DocumentsTemplateSyntax(t *testing.T) {
	desc := macroToolDescription(t)

	for _, want := range []string{
		macro.DelimOpen,   // the supported syntax
		"{{",              // the counter-example an agent is likely to try
		"override_method", // all four expansion sites are named
		"override_url",
		"override_headers",
		"override_body",
		"initial_vars",
		"url_encode", // the encoder chain exists
	} {
		if !strings.Contains(desc, want) {
			t.Errorf("macro tool Description does not contain %q: %q", want, desc)
		}
	}
}

// quotedValues returns the values quoted with q (`"` or "`") in text, sorted.
func quotedValues(text, q string) []string {
	re := regexp.MustCompile(regexp.QuoteMeta(q) + `([a-z_]+)` + regexp.QuoteMeta(q))
	var out []string
	for _, m := range re.FindAllStringSubmatch(text, -1) {
		out = append(out, m[1])
	}
	sort.Strings(out)
	return out
}

// TestHelpMacroResource_EnumsMatchGoConstants asserts that the value lists
// help_macro.md gives for the enum-like macro fields — which the generated
// InputSchema cannot express — agree with the macro package constants.
// (Until USK-1153 this guarded a hand-written yorishiro://schema/macro
// resource; the help resource is now the only place these lists live.)
func TestHelpMacroResource_EnumsMatchGoConstants(t *testing.T) {
	cs := setupResourceTestSession(t)
	result, err := cs.ReadResource(context.Background(), &gomcp.ReadResourceParams{
		URI: "yorishiro://help/macro",
	})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	text := result.Contents[0].Text

	// match returns the first submatch of pattern in the help text.
	match := func(t *testing.T, pattern string) string {
		t.Helper()
		m := regexp.MustCompile(pattern).FindStringSubmatch(text)
		if m == nil {
			t.Fatalf("help/macro has no text matching %q", pattern)
		}
		return m[1]
	}

	tests := []struct {
		name    string
		pattern string // the first submatch holds the documented value list
		quote   string
		want    []string
	}{
		{
			name:    "action",
			pattern: "(?m)^The action to execute\\. One of: (.*)$",
			quote:   "`",
			want:    availableMacroActions,
		},
		{
			name:    "on_error",
			pattern: `(?m)^\s*- \*\*on_error\*\* \(string, optional\): (.*)$`,
			quote:   `"`,
			want:    []string{string(macro.OnErrorAbort), string(macro.OnErrorSkip), string(macro.OnErrorRetry)},
		},
		{
			name:    "extract.from",
			pattern: "`from` \\(([^)]*)\\)",
			quote:   `"`,
			want:    []string{string(macro.ExtractionFromRequest), string(macro.ExtractionFromResponse)},
		},
		{
			name:    "extract.source",
			pattern: "`source` \\(([^)]*)\\)",
			quote:   `"`,
			want: []string{
				string(macro.ExtractionSourceHeader),
				string(macro.ExtractionSourceBody),
				string(macro.ExtractionSourceBodyJSON),
				string(macro.ExtractionSourceStatus),
				string(macro.ExtractionSourceURL),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := quotedValues(match(t, tc.pattern), tc.quote)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("help/macro %s values = %v, want %v", tc.name, got, want)
			}
		})
	}
}

// TestHelpMacroResource_DocumentsExpansionSites asserts the help resource
// stays in sync with the macro engine: every encoder in macro.ListEncoders()
// is named, and override_method is documented as a template expansion site
// (help_macro.md previously claimed otherwise).
func TestHelpMacroResource_DocumentsExpansionSites(t *testing.T) {
	cs := setupResourceTestSession(t)
	result, err := cs.ReadResource(context.Background(), &gomcp.ReadResourceParams{
		URI: "yorishiro://help/macro",
	})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	text := result.Contents[0].Text

	for _, enc := range macro.ListEncoders() {
		if !strings.Contains(text, "`"+enc+"`") {
			t.Errorf("help/macro does not document encoder %q", enc)
		}
	}

	if !strings.Contains(text, "**override_method** (string, optional): Override HTTP method. Supports `"+
		macro.DelimOpen+"variable"+macro.DelimClose+"` templates") {
		t.Error("help/macro does not document template support on override_method")
	}
}
