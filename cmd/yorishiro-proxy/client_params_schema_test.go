package main

// client_params_schema_test.go — USK-1140.
//
// The MCP server derives every tool's InputSchema with jsonschema-go, which
// renders an optional (pointer / slice) field as a JSON Schema type ARRAY,
// e.g. `"type": ["null", "integer"]`. The CLI client must resolve such a
// union to its non-null member so `client proxy_start max_connections=2048`
// sends the integer 2048 instead of the string "2048". The same resolution
// applies to dot-notation children (`params.older_than_days=7`), which must
// be typed against the PARENT property's own schema rather than against the
// tool's top-level properties.
//
// These tests drive the real seam: an in-process mcp.Server, the real
// tools/list → fetchToolSchema → buildToolParams path, and session.CallTool,
// so the server's own input-schema validation is the oracle.

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/mcp"
)

// newInMemoryToolSession boots an in-process MCP server with empty
// components and returns a connected client session. Teardown closes the
// session, cancels the server context and waits for Run to return.
func newInMemoryToolSession(t *testing.T) (context.Context, *gomcp.ClientSession) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	srv := mcp.NewServer(nil, nil, nil, nil, nil, nil, nil)
	serverTransport, clientTransport := gomcp.NewInMemoryTransports()

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = srv.Run(ctx, serverTransport)
	}()

	client := gomcp.NewClient(&gomcp.Implementation{Name: "usk1140-test", Version: "test"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		cancel()
		<-runDone
		t.Fatalf("connect in-memory MCP client: %v", err)
	}

	t.Cleanup(func() {
		_ = session.Close()
		cancel()
		select {
		case <-runDone:
		case <-time.After(10 * time.Second):
			t.Error("in-memory MCP server did not stop within 10s")
		}
	})
	return ctx, session
}

// callToolViaCLIPath runs the CLI's own parameter path — fetchToolSchema
// (real tools/list) → buildToolParams — and then calls the tool. It returns
// the params that were sent and the CallTool transport/validation error
// (nil when the server accepted the arguments, even if the tool itself
// reported a tool-level IsError).
func callToolViaCLIPath(t *testing.T, ctx context.Context, session *gomcp.ClientSession, tool string, args ...string) (map[string]any, *gomcp.CallToolResult, error) {
	t.Helper()

	schema := fetchToolSchema(ctx, session, tool)
	if schema == nil {
		t.Fatalf("fetchToolSchema(%q) returned nil", tool)
	}
	params, err := buildToolParams(tool, args, schema, io.Discard)
	if err != nil {
		t.Fatalf("buildToolParams(%q, %q): %v", tool, args, err)
	}
	res, err := session.CallTool(ctx, &gomcp.CallToolParams{Name: tool, Arguments: params})
	return params, res, err
}

// toolResultText concatenates the text content of a CallToolResult.
func toolResultText(res *gomcp.CallToolResult) string {
	if res == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*gomcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// TestClientTool_NullableInteger_AcceptedByServer is the reported bug:
// an optional integer parameter must be sent as a JSON integer.
func TestClientTool_NullableInteger_AcceptedByServer(t *testing.T) {
	ctx, session := newInMemoryToolSession(t)

	params, res, err := callToolViaCLIPath(t, ctx, session, "configure", "max_connections=2048")

	if got := params["max_connections"]; got != int64(2048) {
		t.Errorf("params[max_connections] = %#v (%T), want int64(2048)", got, got)
	}
	if err != nil {
		t.Fatalf("CallTool(configure max_connections=2048) rejected by server schema: %v", err)
	}
	// With no proxy manager the tool fails at tool level — which proves the
	// arguments passed input validation and reached the handler.
	if !res.IsError || !strings.Contains(toolResultText(res), "proxy manager is not initialized") {
		t.Errorf("CallTool result = IsError:%v %q, want tool-level %q", res.IsError, toolResultText(res), "proxy manager is not initialized")
	}
}

// TestClientTool_NonNumericNullableInteger_StillRejected guards that the fix
// only converts values that parse: an unparseable value is still sent as a
// string and rejected by the server's schema, not silently zeroed.
func TestClientTool_NonNumericNullableInteger_StillRejected(t *testing.T) {
	ctx, session := newInMemoryToolSession(t)

	params, _, err := callToolViaCLIPath(t, ctx, session, "configure", "max_connections=lots")

	if got := params["max_connections"]; got != "lots" {
		t.Errorf("params[max_connections] = %#v (%T), want the raw string %q", got, got, "lots")
	}
	if err == nil {
		t.Fatal("CallTool(configure max_connections=lots) succeeded, want a server schema error")
	}
	for _, want := range []string{"/properties/max_connections", `has type "string"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("CallTool error = %q, want it to contain %q", err, want)
		}
	}
}

// TestBuildToolParams_LiveSchemaNullableTypes checks coercion against the
// server's real InputSchemas for every nullable kind the CLI coerces.
func TestBuildToolParams_LiveSchemaNullableTypes(t *testing.T) {
	ctx, session := newInMemoryToolSession(t)

	tests := []struct {
		name string
		tool string
		args []string
		key  string
		want any
	}{
		{"nullable integer", "proxy_start", []string{"max_connections=2048"}, "max_connections", int64(2048)},
		{"nullable boolean true", "query", []string{"resource=flows", "include_bodies=true"}, "include_bodies", true},
		{"nullable boolean false", "resend_ws", []string{"opcode=text", "fin=false"}, "fin", false},
		{"nullable string-item array", "query", []string{"resource=flows", "fields=id,method"}, "fields", []string{"id", "method"}},
		{"nullable string-item array grpc", "resend_grpc", []string{`messages=[{"payload":"x"}]`, "accept_encoding=gzip,identity"}, "accept_encoding", []string{"gzip", "identity"}},
		{"nullable string stays literal", "configure", []string{"tls_fingerprint=123"}, "tls_fingerprint", "123"},
		{"unparseable integer stays raw", "configure", []string{"max_connections=lots"}, "max_connections", "lots"},
		// USK-1152 no-regression guards: top-level string-item arrays keep the
		// comma / single-quote convention and stay []string.
		{"string-item array keeps quoted comma", "query", []string{"resource=flows", "fields='a,b',c"}, "fields", []string{"a,b", "c"}},
		{"string-item array keeps doubled quote", "query", []string{"resource=flows", "fields='it''s'"}, "fields", []string{"it's"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			schema := fetchToolSchema(ctx, session, tt.tool)
			if schema == nil {
				t.Fatalf("fetchToolSchema(%q) returned nil", tt.tool)
			}
			params, err := buildToolParams(tt.tool, tt.args, schema, io.Discard)
			if err != nil {
				t.Fatalf("buildToolParams(%q, %q): %v", tt.tool, tt.args, err)
			}
			if got := params[tt.key]; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("%s %q: params[%q] = %#v (%T), want %#v (%T)", tt.tool, tt.args, tt.key, got, got, tt.want, tt.want)
			}
		})
	}
}

// TestParseToolSchema_NullableUnionTypes pins the type-array resolver.
// The `["null", X]` rows mirror what jsonschema-go emits for *T / []T fields
// (and the live tools/list dump). The remaining rows are synthetic edge
// cases: other orderings, degenerate arrays and non-string elements.
func TestParseToolSchema_NullableUnionTypes(t *testing.T) {
	tests := []struct {
		name    string
		typeVal any
		omit    bool
		want    string
	}{
		{name: "null|integer", typeVal: []any{"null", "integer"}, want: "integer"},
		{name: "null|number", typeVal: []any{"null", "number"}, want: "number"},
		{name: "null|boolean", typeVal: []any{"null", "boolean"}, want: "boolean"},
		{name: "null|string", typeVal: []any{"null", "string"}, want: "string"},
		{name: "null|array", typeVal: []any{"null", "array"}, want: "array"},
		{name: "null|object", typeVal: []any{"null", "object"}, want: "object"},
		{name: "integer|null (null last)", typeVal: []any{"integer", "null"}, want: "integer"},
		{name: "only null", typeVal: []any{"null"}, want: "string"},
		{name: "empty array", typeVal: []any{}, want: "string"},
		{name: "non-string element skipped", typeVal: []any{1, "integer"}, want: "integer"},
		{name: "multi-type union takes first non-null", typeVal: []any{"string", "integer"}, want: "string"},
		{name: "type missing", omit: true, want: "string"},
		{name: "scalar integer", typeVal: "integer", want: "integer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prop := map[string]any{}
			if !tt.omit {
				prop["type"] = tt.typeVal
			}
			got := parseToolSchema(map[string]any{
				"type":       "object",
				"properties": map[string]any{"p": prop},
			})
			if got == nil {
				t.Fatal("parseToolSchema returned nil")
			}
			if got.properties["p"] != tt.want {
				t.Errorf("type %#v resolved to %q, want %q", tt.typeVal, got.properties["p"], tt.want)
			}
		})
	}
}

// TestClientTool_DotNotationChildren_TypedByParentSchema covers the second
// defect of the same class: dot-notation children were typed against the
// tool's TOP-LEVEL properties, so every nested value was sent as a string.
// The argument lists are the CLI's own --help examples.
func TestClientTool_DotNotationChildren_TypedByParentSchema(t *testing.T) {
	ctx, session := newInMemoryToolSession(t)

	tests := []struct {
		name   string
		tool   string
		args   []string
		parent string
		want   map[string]any
	}{
		{
			name:   "security nullable number",
			tool:   "security",
			args:   []string{"action=set_rate_limits", "params.max_requests_per_second=100"},
			parent: "params",
			want:   map[string]any{"max_requests_per_second": int64(100)},
		},
		{
			name:   "manage nullable integer and boolean",
			tool:   "manage",
			args:   []string{"action=delete_flows", "params.older_than_days=7", "params.confirm=true"},
			parent: "params",
			want:   map[string]any{"older_than_days": int64(7), "confirm": true},
		},
		{
			name:   "query filter integer",
			tool:   "query",
			args:   []string{"resource=flows", "filter.status_code=200"},
			parent: "filter",
			want:   map[string]any{"status_code": int64(200)},
		},
		{
			name:   "configure nested array",
			tool:   "configure",
			args:   []string{"tls_passthrough.add=a.com,b.com"},
			parent: "tls_passthrough",
			want:   map[string]any{"add": []string{"a.com", "b.com"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, res, err := callToolViaCLIPath(t, ctx, session, tt.tool, tt.args...)

			nested, ok := params[tt.parent].(map[string]any)
			if !ok {
				t.Fatalf("params[%q] = %#v (%T), want map[string]any", tt.parent, params[tt.parent], params[tt.parent])
			}
			for child, want := range tt.want {
				if got := nested[child]; !reflect.DeepEqual(got, want) {
					t.Errorf("%s.%s = %#v (%T), want %#v (%T)", tt.parent, child, got, got, want, want)
				}
			}
			if err != nil {
				t.Fatalf("CallTool(%s %q) rejected by server schema: %v", tt.tool, tt.args, err)
			}
			if res != nil && res.IsError && strings.Contains(toolResultText(res), "invalid params") {
				t.Errorf("CallTool(%s %q) tool result reports invalid params: %q", tt.tool, tt.args, toolResultText(res))
			}
		})
	}
}

// --- USK-1152: typed array items, N-level dot paths, JSON values ---
//
// Every fixture below is a REAL registered tool schema reached through
// tools/list; the server's own input validation is the oracle wherever the
// test calls the tool.

// buildViaLiveSchema runs fetchToolSchema → buildToolParams without calling
// the tool, for assertions on CLI-side results and errors.
func buildViaLiveSchema(t *testing.T, ctx context.Context, session *gomcp.ClientSession, tool string, args ...string) (map[string]any, error) {
	t.Helper()
	schema := fetchToolSchema(ctx, session, tool)
	if schema == nil {
		t.Fatalf("fetchToolSchema(%q) returned nil", tool)
	}
	return buildToolParams(tool, args, schema, io.Discard)
}

// childMap walks params along keys, failing the test if any step is not a map.
func childMap(t *testing.T, params map[string]any, keys ...string) map[string]any {
	t.Helper()
	cur := params
	for _, k := range keys {
		next, ok := cur[k].(map[string]any)
		if !ok {
			t.Fatalf("params path %q: %q = %#v (%T), want map[string]any", strings.Join(keys, "."), k, cur[k], cur[k])
		}
		cur = next
	}
	return cur
}

const usk1152Positions = `[{"path":"raw_query","payloads":["test1","test2","test3"]}]`

// TestClientTool_NestedIntegerArray_TypedByItems is the reported bug (T1/T2):
// an array whose items are integers must be sent as integers, both from the
// comma form and from the JSON-array form.
func TestClientTool_NestedIntegerArray_TypedByItems(t *testing.T) {
	ctx, session := newInMemoryToolSession(t)

	for _, form := range []string{"200,302", "[200,302]"} {
		t.Run(form, func(t *testing.T) {
			params, _, err := callToolViaCLIPath(t, ctx, session, "fuzz_http",
				"flow_id=x", "post_macro.name=m", "post_macro.status_codes="+form, "positions="+usk1152Positions)

			got := childMap(t, params, "post_macro")["status_codes"]
			want := []any{int64(200), int64(302)}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("post_macro.status_codes = %#v (%T), want %#v", got, got, want)
			}
			if err != nil {
				t.Fatalf("CallTool(fuzz_http post_macro.status_codes=%s) rejected by server schema: %v", form, err)
			}
		})
	}
}

// TestClientTool_NestedIntegerArray_UnparseableElementStaysRaw (T3) guards
// that an element that does not parse is sent as-is so the server rejects it.
func TestClientTool_NestedIntegerArray_UnparseableElementStaysRaw(t *testing.T) {
	ctx, session := newInMemoryToolSession(t)

	params, _, err := callToolViaCLIPath(t, ctx, session, "fuzz_http",
		"flow_id=x", "post_macro.name=m", "post_macro.status_codes=200,abc", "positions="+usk1152Positions)

	got := childMap(t, params, "post_macro")["status_codes"]
	want := []any{int64(200), "abc"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("post_macro.status_codes = %#v (%T), want %#v", got, got, want)
	}
	if err == nil {
		t.Fatal("CallTool(fuzz_http post_macro.status_codes=200,abc) succeeded, want a server schema error")
	}
	if !strings.Contains(err.Error(), "status_codes") {
		t.Errorf("CallTool error = %q, want it to name status_codes", err)
	}
}

// TestClientTool_JSONObjectArrays_Accepted covers T4-T7: array-of-object
// parameters take a JSON value, decoded verbatim and in order.
func TestClientTool_JSONObjectArrays_Accepted(t *testing.T) {
	ctx, session := newInMemoryToolSession(t)

	t.Run("fuzz_http positions", func(t *testing.T) {
		params, _, err := callToolViaCLIPath(t, ctx, session, "fuzz_http", "flow_id=x", "positions="+usk1152Positions)
		want := []any{map[string]any{"path": "raw_query", "payloads": []any{"test1", "test2", "test3"}}}
		if got := params["positions"]; !reflect.DeepEqual(got, want) {
			t.Errorf("positions = %#v (%T), want %#v", got, got, want)
		}
		if err != nil {
			t.Fatalf("CallTool(fuzz_http positions=<json>) rejected by server schema: %v", err)
		}
	})

	t.Run("fuzz_http SQLi payload verbatim", func(t *testing.T) {
		// What the shell hands over for positions='[...["'\'' OR '\''1'\''='\''1"]...]'.
		const sqli = `' OR '1'='1`
		params, _, err := callToolViaCLIPath(t, ctx, session, "fuzz_http", "flow_id=x",
			`positions=[{"path":"raw_query","payloads":["`+sqli+`"]}]`)
		positions, ok := params["positions"].([]any)
		if !ok || len(positions) != 1 {
			t.Fatalf("positions = %#v (%T), want a 1-element []any", params["positions"], params["positions"])
		}
		pos, _ := positions[0].(map[string]any)
		payloads, _ := pos["payloads"].([]any)
		if len(payloads) != 1 || payloads[0] != sqli {
			t.Errorf("positions[0].payloads = %#v, want [%q]", pos["payloads"], sqli)
		}
		if err != nil {
			t.Fatalf("CallTool(fuzz_http SQLi positions) rejected by server schema: %v", err)
		}
	})

	t.Run("resend_http headers", func(t *testing.T) {
		params, _, err := callToolViaCLIPath(t, ctx, session, "resend_http", "flow_id=x",
			`headers=[{"name":"Authorization","value":"Bearer X"},{"name":"X-A","value":"1"}]`)
		want := []any{
			map[string]any{"name": "Authorization", "value": "Bearer X"},
			map[string]any{"name": "X-A", "value": "1"},
		}
		if got := params["headers"]; !reflect.DeepEqual(got, want) {
			t.Errorf("headers = %#v (%T), want %#v", got, got, want)
		}
		if err != nil {
			t.Fatalf("CallTool(resend_http headers=<json>) rejected by server schema: %v", err)
		}
	})

	t.Run("security params.allows echoed", func(t *testing.T) {
		params, res, err := callToolViaCLIPath(t, ctx, session, "security", "action=set_target_scope",
			`params.allows=[{"hostname":"a.com","ports":[443]}]`)
		allows, ok := childMap(t, params, "params")["allows"].([]any)
		if !ok || len(allows) != 1 {
			t.Fatalf("params.allows = %#v, want a 1-element []any", childMap(t, params, "params")["allows"])
		}
		if err != nil {
			t.Fatalf("CallTool(security set_target_scope params.allows=<json>) rejected by server schema: %v", err)
		}
		if text := toolResultText(res); res.IsError || !strings.Contains(text, `"ports":[443]`) {
			t.Errorf("security result = IsError:%v %q, want it to echo %q", res.IsError, text, `"ports":[443]`)
		}
	})
}

// TestClientTool_NLevelDotPaths covers T8/T9: dot notation descends every
// level, a map of objects consumes one segment as its key, and a map of
// scalars keeps the remaining dotted segments as one key.
func TestClientTool_NLevelDotPaths(t *testing.T) {
	ctx, session := newInMemoryToolSession(t)

	t.Run("configure protocol_overrides map of objects", func(t *testing.T) {
		params, _, err := callToolViaCLIPath(t, ctx, session, "configure",
			"intercept_queue.protocol_overrides.http.timeout_ms=5000")
		http := childMap(t, params, "intercept_queue", "protocol_overrides", "http")
		if got := http["timeout_ms"]; got != int64(5000) {
			t.Errorf("intercept_queue.protocol_overrides.http.timeout_ms = %#v (%T), want int64(5000)", got, got)
		}
		if err != nil {
			t.Fatalf("CallTool(configure protocol_overrides) rejected by server schema: %v", err)
		}
	})

	t.Run("fuzz_http post_macro.vars scalar map keeps dotted key", func(t *testing.T) {
		params, _, err := callToolViaCLIPath(t, ctx, session, "fuzz_http", "flow_id=x",
			"post_macro.name=m", "post_macro.vars.user.id=admin", "positions="+usk1152Positions)
		vars := childMap(t, params, "post_macro", "vars")
		if want := (map[string]any{"user.id": "admin"}); !reflect.DeepEqual(vars, want) {
			t.Errorf("post_macro.vars = %#v, want %#v", vars, want)
		}
		if err != nil {
			t.Fatalf("CallTool(fuzz_http post_macro.vars.user.id) rejected by server schema: %v", err)
		}
	})
}

// TestBuildToolParams_MalformedJSONAtJSONOnlyPath (T10) — a JSON-only path
// with malformed JSON is a CLI error naming the path, not a silent string.
func TestBuildToolParams_MalformedJSONAtJSONOnlyPath(t *testing.T) {
	ctx, session := newInMemoryToolSession(t)

	tests := []struct {
		name string
		tool string
		args []string
		path string
	}{
		{"top-level positions", "fuzz_http", []string{"flow_id=x", `positions=[{"path":`}, "positions"},
		{"nested params.allows", "security", []string{"action=set_target_scope", `params.allows=[{"hostname":}]`}, "params.allows"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := buildViaLiveSchema(t, ctx, session, tt.tool, tt.args...)
			if err == nil {
				t.Fatalf("buildToolParams(%s %q) = %#v, nil error; want an error naming %q", tt.tool, tt.args, params, tt.path)
			}
			if !strings.Contains(err.Error(), tt.path) {
				t.Errorf("buildToolParams error = %q, want it to name %q", err, tt.path)
			}
		})
	}
}

// TestBuildToolParams_JSONNotAutoParsedForStrings (T11/T12) guards the
// schema-driven rule: a value that merely LOOKS like JSON stays a string
// wherever the schema says string (or array of strings).
func TestBuildToolParams_JSONNotAutoParsedForStrings(t *testing.T) {
	ctx, session := newInMemoryToolSession(t)

	tests := []struct {
		name string
		tool string
		args []string
		path []string
		want any
	}{
		{"resend_http body", "resend_http", []string{"flow_id=x", `body={"x":1}`}, []string{"body"}, `{"x":1}`},
		{"intercept nested http.body", "intercept", []string{"action=modify_and_forward", "params.id=1", `http.body={"a":1}`}, []string{"http", "body"}, `{"a":1}`},
		{"query filter.url_pattern", "query", []string{"resource=flows", "filter.url_pattern=[a-z]+"}, []string{"filter", "url_pattern"}, "[a-z]+"},
		{"configure tls_passthrough.add bracketed host", "configure", []string{"tls_passthrough.add=[::1],example.com"}, []string{"tls_passthrough", "add"}, []string{"[::1]", "example.com"}},
		// Valid JSON at an array<string> path must still be one literal item:
		// the comma form never JSON-decodes string items (only `key:=` does).
		{"configure tls_passthrough.add valid JSON stays literal", "configure", []string{`tls_passthrough.add=["a"]`}, []string{"tls_passthrough", "add"}, []string{`["a"]`}},
		{"query fields valid JSON stays literal", "query", []string{"resource=flows", `fields=["id"]`}, []string{"fields"}, []string{`["id"]`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := buildViaLiveSchema(t, ctx, session, tt.tool, tt.args...)
			if err != nil {
				t.Fatalf("buildToolParams(%s %q): %v", tt.tool, tt.args, err)
			}
			parent := childMap(t, params, tt.path[:len(tt.path)-1]...)
			leaf := tt.path[len(tt.path)-1]
			if got := parent[leaf]; !reflect.DeepEqual(got, tt.want) {
				t.Errorf("%s = %#v (%T), want %#v (%T)", strings.Join(tt.path, "."), got, got, tt.want, tt.want)
			}
		})
	}
}

// TestClientTool_USK1152_NoRegression (T14) — already-correct behaviour that
// the rewrite must keep: a nested scalar integer, and an empty array value.
func TestClientTool_USK1152_NoRegression(t *testing.T) {
	ctx, session := newInMemoryToolSession(t)

	t.Run("post_macro.n integer", func(t *testing.T) {
		params, _, err := callToolViaCLIPath(t, ctx, session, "fuzz_http", "flow_id=x",
			"post_macro.name=m", "post_macro.n=3", "positions="+usk1152Positions)
		if got := childMap(t, params, "post_macro")["n"]; got != int64(3) {
			t.Errorf("post_macro.n = %#v (%T), want int64(3)", got, got)
		}
		if err != nil {
			t.Fatalf("CallTool(fuzz_http post_macro.n=3) rejected by server schema: %v", err)
		}
	})

	t.Run("resend_http empty headers", func(t *testing.T) {
		params, _, err := callToolViaCLIPath(t, ctx, session, "resend_http", "flow_id=x", "headers=")
		got := params["headers"]
		if v := reflect.ValueOf(got); got == nil || v.Kind() != reflect.Slice || v.Len() != 0 {
			t.Errorf("headers = %#v (%T), want an empty slice", got, got)
		}
		if err != nil {
			t.Fatalf("CallTool(resend_http headers=) rejected by server schema: %v", err)
		}
	})
}

// TestBuildToolParams_ExplicitJSONAssignment covers T15: `key:=<json>` parses
// the value as JSON at any path regardless of the schema (and with no schema).
func TestBuildToolParams_ExplicitJSONAssignment(t *testing.T) {
	ctx, session := newInMemoryToolSession(t)

	t.Run("null clears a protocol override", func(t *testing.T) {
		params, err := buildViaLiveSchema(t, ctx, session, "configure", "intercept_queue.protocol_overrides.http:=null")
		if err != nil {
			t.Fatalf("buildToolParams: %v", err)
		}
		overrides := childMap(t, params, "intercept_queue", "protocol_overrides")
		got, present := overrides["http"]
		if !present || got != nil {
			t.Errorf("protocol_overrides = %#v, want key \"http\" with a nil value", overrides)
		}
	})

	t.Run("object form of untyped upstream_proxy", func(t *testing.T) {
		params, err := buildViaLiveSchema(t, ctx, session, "proxy_start", `upstream_proxy:={"url":"http://127.0.0.1:1"}`)
		if err != nil {
			t.Fatalf("buildToolParams: %v", err)
		}
		want := map[string]any{"url": "http://127.0.0.1:1"}
		if got := params["upstream_proxy"]; !reflect.DeepEqual(got, want) {
			t.Errorf("upstream_proxy = %#v (%T), want %#v", got, got, want)
		}
	})

	t.Run("JSON-literal string array", func(t *testing.T) {
		params, err := buildViaLiveSchema(t, ctx, session, "query", "resource=flows", `fields:=["a,b"]`)
		if err != nil {
			t.Fatalf("buildToolParams: %v", err)
		}
		if got, want := params["fields"], []any{"a,b"}; !reflect.DeepEqual(got, want) {
			t.Errorf("fields = %#v (%T), want %#v", got, got, want)
		}
	})

	t.Run("malformed JSON names the path", func(t *testing.T) {
		params, err := buildViaLiveSchema(t, ctx, session, "proxy_start", `upstream_proxy:={"url":`)
		if err == nil {
			t.Fatalf("buildToolParams = %#v, nil error; want an error naming upstream_proxy", params)
		}
		if !strings.Contains(err.Error(), "upstream_proxy") {
			t.Errorf("buildToolParams error = %q, want it to name upstream_proxy", err)
		}
	})

	t.Run("works with nil schema", func(t *testing.T) {
		params, err := buildToolParams("fuzz_http", []string{`a.b:=[1,"x"]`}, nil, io.Discard)
		if err != nil {
			t.Fatalf("buildToolParams: %v", err)
		}
		got := childMap(t, params, "a")["b"]
		arr, ok := got.([]any)
		if !ok || len(arr) != 2 || arr[1] != "x" || fmt.Sprint(arr[0]) != "1" {
			t.Errorf("a.b = %#v (%T), want [1 \"x\"]", got, got)
		}
	})
}
