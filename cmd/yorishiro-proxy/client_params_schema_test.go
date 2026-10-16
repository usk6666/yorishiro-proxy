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
		{"nullable string-item array grpc", "resend_grpc", []string{"accept_encoding=gzip,identity"}, "accept_encoding", []string{"gzip", "identity"}},
		{"nullable string stays literal", "configure", []string{"tls_fingerprint=123"}, "tls_fingerprint", "123"},
		{"unparseable integer stays raw", "configure", []string{"max_connections=lots"}, "max_connections", "lots"},
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
