package mcp

import (
	"context"
	"embed"
	"fmt"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

//go:embed resources/*.md
var resourcesFS embed.FS

// resourceDef defines a single MCP resource to register.
type resourceDef struct {
	uri         string
	name        string
	description string
	mimeType    string
	filename    string // path within the embedded FS (e.g. "resources/help_query.md")

	// topic is the docs-tool topic name for this resource — the value an
	// agent passes as docs(topic=...).
	//
	// Explicit rather than derived from name, so the topic namespace is
	// never a side effect of a file naming rule.
	topic string
}

// helpResources lists all help resources. Every entry is both an MCP
// resource (yorishiro://help/<topic>) and a docs-tool topic; the slice order
// is the order topics appear in the docs() index, so getting-started leads
// and the cross-cutting concept topics trail the per-tool references.
var helpResources = []resourceDef{
	{
		uri:         "yorishiro://help/getting-started",
		name:        "help_getting-started",
		topic:       "getting-started",
		description: "End-to-end first session: MCP setup, proxy_start, CA certificate install, first capture, inspect, replay.",
		mimeType:    "text/markdown",
		filename:    "resources/help_getting-started.md",
	},
	{
		uri:         "yorishiro://help/proxy_start",
		name:        "help_proxy_start",
		topic:       "proxy_start",
		description: "Full parameter documentation and usage examples for the proxy_start tool.",
		mimeType:    "text/markdown",
		filename:    "resources/help_proxy_start.md",
	},
	{
		uri:         "yorishiro://help/proxy_stop",
		name:        "help_proxy_stop",
		topic:       "proxy_stop",
		description: "Documentation for the proxy_stop tool.",
		mimeType:    "text/markdown",
		filename:    "resources/help_proxy_stop.md",
	},
	{
		uri:         "yorishiro://help/query",
		name:        "help_query",
		topic:       "query",
		description: "Resource list, filter syntax, and usage examples for the query tool.",
		mimeType:    "text/markdown",
		filename:    "resources/help_query.md",
	},
	{
		uri:         "yorishiro://help/manage",
		name:        "help_manage",
		topic:       "manage",
		description: "Action list, parameter syntax, and usage examples for the manage tool (delete_flows, export_flows, import_flows, regenerate_ca_cert).",
		mimeType:    "text/markdown",
		filename:    "resources/help_manage.md",
	},
	{
		uri:         "yorishiro://help/macro",
		name:        "help_macro",
		topic:       "macro",
		description: "Action list, parameter syntax, and usage examples for the macro tool (define_macro, run_macro, delete_macro).",
		mimeType:    "text/markdown",
		filename:    "resources/help_macro.md",
	},
	{
		uri:         "yorishiro://help/intercept",
		name:        "help_intercept",
		topic:       "intercept",
		description: "Action list, parameter syntax, and usage examples for the intercept tool (release, modify_and_forward, drop).",
		mimeType:    "text/markdown",
		filename:    "resources/help_intercept.md",
	},
	{
		uri:         "yorishiro://help/configure",
		name:        "help_configure",
		topic:       "configure",
		description: "Operation types, merge/replace syntax, and usage examples for the configure tool.",
		mimeType:    "text/markdown",
		filename:    "resources/help_configure.md",
	},
	{
		uri:         "yorishiro://help/examples",
		name:        "help_examples",
		topic:       "examples",
		description: "Common vulnerability assessment workflow examples using yorishiro-proxy.",
		mimeType:    "text/markdown",
		filename:    "resources/help_examples.md",
	},
	{
		uri:         "yorishiro://help/security",
		name:        "help_security",
		topic:       "security",
		description: "Two-layer target scope architecture, action syntax, and usage examples for the security tool.",
		mimeType:    "text/markdown",
		filename:    "resources/help_security.md",
	},
	{
		uri:         "yorishiro://help/resend_http",
		name:        "help_resend_http",
		topic:       "resend_http",
		description: "Parameter documentation and examples for the resend_http tool (HTTPMessage-typed HTTP resend).",
		mimeType:    "text/markdown",
		filename:    "resources/help_resend_http.md",
	},
	{
		uri:         "yorishiro://help/resend_ws",
		name:        "help_resend_ws",
		topic:       "resend_ws",
		description: "Parameter documentation and examples for the resend_ws tool (WSMessage-typed WebSocket frame resend).",
		mimeType:    "text/markdown",
		filename:    "resources/help_resend_ws.md",
	},
	{
		uri:         "yorishiro://help/resend_grpc",
		name:        "help_resend_grpc",
		topic:       "resend_grpc",
		description: "Parameter documentation and examples for the resend_grpc tool (GRPCStart/Data/End-typed gRPC RPC resend).",
		mimeType:    "text/markdown",
		filename:    "resources/help_resend_grpc.md",
	},
	{
		uri:         "yorishiro://help/resend_raw",
		name:        "help_resend_raw",
		topic:       "resend_raw",
		description: "Parameter documentation and examples for the resend_raw tool (RawMessage-typed byte payload resend).",
		mimeType:    "text/markdown",
		filename:    "resources/help_resend_raw.md",
	},
	{
		uri:         "yorishiro://help/fuzz_http",
		name:        "help_fuzz_http",
		topic:       "fuzz_http",
		description: "Parameter documentation, position path syntax, and examples for the fuzz_http tool.",
		mimeType:    "text/markdown",
		filename:    "resources/help_fuzz_http.md",
	},
	{
		uri:         "yorishiro://help/fuzz_ws",
		name:        "help_fuzz_ws",
		topic:       "fuzz_ws",
		description: "Parameter documentation, position path syntax, and examples for the fuzz_ws tool.",
		mimeType:    "text/markdown",
		filename:    "resources/help_fuzz_ws.md",
	},
	{
		uri:         "yorishiro://help/fuzz_grpc",
		name:        "help_fuzz_grpc",
		topic:       "fuzz_grpc",
		description: "Parameter documentation, position path syntax, and examples for the fuzz_grpc tool.",
		mimeType:    "text/markdown",
		filename:    "resources/help_fuzz_grpc.md",
	},
	{
		uri:         "yorishiro://help/fuzz_raw",
		name:        "help_fuzz_raw",
		topic:       "fuzz_raw",
		description: "Parameter documentation, position path syntax, and examples for the fuzz_raw tool (HTTP request smuggling fuzzer).",
		mimeType:    "text/markdown",
		filename:    "resources/help_fuzz_raw.md",
	},
	{
		uri:         "yorishiro://help/plugin_introspect",
		name:        "help_plugin_introspect",
		topic:       "plugin_introspect",
		description: "Documentation and example output for the plugin_introspect tool.",
		mimeType:    "text/markdown",
		filename:    "resources/help_plugin_introspect.md",
	},
	{
		uri:         "yorishiro://help/grpc_schema",
		name:        "help_grpc_schema",
		topic:       "grpc_schema",
		description: "Action list, parameter syntax, descriptor-set requirements, and usage examples for the grpc_schema tool (register, list, unregister, clear).",
		mimeType:    "text/markdown",
		filename:    "resources/help_grpc_schema.md",
	},
	{
		uri:         "yorishiro://help/template-syntax",
		name:        "help_template-syntax",
		topic:       "template-syntax",
		description: "Where the §var§ KV Store template syntax is expanded, and which tool parameters accept it.",
		mimeType:    "text/markdown",
		filename:    "resources/help_template-syntax.md",
	},
	{
		uri:         "yorishiro://help/docs",
		name:        "help_docs",
		topic:       "docs",
		description: "How the docs tool itself works: the topic index, section slicing, and the error paths.",
		mimeType:    "text/markdown",
		filename:    "resources/help_docs.md",
	},
}

// There are deliberately no hand-written JSON Schema resources: the only
// tool input schema an agent can obtain is the InputSchema tools/list
// returns, which is what the go-sdk validates calls against. The former
// yorishiro://schema/* copies drifted from it (USK-1153).

// registerResources registers all help MCP resources on the server.
func (s *Server) registerResources() {
	for _, rd := range helpResources {
		s.server.AddResource(
			&gomcp.Resource{
				URI:         rd.uri,
				Name:        rd.name,
				Description: rd.description,
				MIMEType:    rd.mimeType,
			},
			makeResourceHandler(rd.uri, rd.mimeType, rd.filename),
		)
	}

}

// makeResourceHandler returns a ResourceHandler that reads the given file from the
// embedded filesystem and returns it as the resource content.
func makeResourceHandler(uri, mimeType, filename string) gomcp.ResourceHandler {
	return func(_ context.Context, _ *gomcp.ReadResourceRequest) (*gomcp.ReadResourceResult, error) {
		data, err := resourcesFS.ReadFile(filename)
		if err != nil {
			return nil, fmt.Errorf("read embedded resource %s: %w", filename, err)
		}
		return &gomcp.ReadResourceResult{
			Contents: []*gomcp.ResourceContents{
				{
					URI:      uri,
					MIMEType: mimeType,
					Text:     string(data),
				},
			},
		}, nil
	}
}
