package mcp

import (
	"context"
	"embed"
	"fmt"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

//go:embed resources/*.md resources/*.json
var resourcesFS embed.FS

// resourceDef defines a single MCP resource to register.
type resourceDef struct {
	uri         string
	name        string
	description string
	mimeType    string
	filename    string // path within the embedded FS (e.g. "resources/help_query.md")
}

// helpResources lists all help resources.
var helpResources = []resourceDef{
	{
		uri:         "yorishiro://help/proxy_start",
		name:        "help_proxy_start",
		description: "Full parameter documentation and usage examples for the proxy_start tool.",
		mimeType:    "text/markdown",
		filename:    "resources/help_proxy_start.md",
	},
	{
		uri:         "yorishiro://help/proxy_stop",
		name:        "help_proxy_stop",
		description: "Documentation for the proxy_stop tool.",
		mimeType:    "text/markdown",
		filename:    "resources/help_proxy_stop.md",
	},
	{
		uri:         "yorishiro://help/query",
		name:        "help_query",
		description: "Resource list, filter syntax, and usage examples for the query tool.",
		mimeType:    "text/markdown",
		filename:    "resources/help_query.md",
	},
	{
		uri:         "yorishiro://help/resend",
		name:        "help_resend",
		description: "Action list, parameter syntax, and usage examples for the resend tool (resend, resend_raw, tcp_replay).",
		mimeType:    "text/markdown",
		filename:    "resources/help_resend.md",
	},
	{
		uri:         "yorishiro://help/manage",
		name:        "help_manage",
		description: "Action list, parameter syntax, and usage examples for the manage tool (delete_flows, export_flows, import_flows, regenerate_ca_cert).",
		mimeType:    "text/markdown",
		filename:    "resources/help_manage.md",
	},
	{
		uri:         "yorishiro://help/fuzz",
		name:        "help_fuzz",
		description: "Action list, parameter syntax, and usage examples for the fuzz tool (fuzz, fuzz_pause, fuzz_resume, fuzz_cancel).",
		mimeType:    "text/markdown",
		filename:    "resources/help_fuzz.md",
	},
	{
		uri:         "yorishiro://help/macro",
		name:        "help_macro",
		description: "Action list, parameter syntax, and usage examples for the macro tool (define_macro, run_macro, delete_macro).",
		mimeType:    "text/markdown",
		filename:    "resources/help_macro.md",
	},
	{
		uri:         "yorishiro://help/intercept",
		name:        "help_intercept",
		description: "Action list, parameter syntax, and usage examples for the intercept tool (release, modify_and_forward, drop).",
		mimeType:    "text/markdown",
		filename:    "resources/help_intercept.md",
	},
	{
		uri:         "yorishiro://help/configure",
		name:        "help_configure",
		description: "Operation types, merge/replace syntax, and usage examples for the configure tool.",
		mimeType:    "text/markdown",
		filename:    "resources/help_configure.md",
	},
	{
		uri:         "yorishiro://help/examples",
		name:        "help_examples",
		description: "Common vulnerability assessment workflow examples using yorishiro-proxy.",
		mimeType:    "text/markdown",
		filename:    "resources/help_examples.md",
	},
	{
		uri:         "yorishiro://help/security",
		name:        "help_security",
		description: "Two-layer target scope architecture, action syntax, and usage examples for the security tool.",
		mimeType:    "text/markdown",
		filename:    "resources/help_security.md",
	},
}

// schemaResources lists all JSON Schema resources.
var schemaResources = []resourceDef{
	{
		uri:         "yorishiro://schema/proxy_start",
		name:        "schema_proxy_start",
		description: "JSON Schema for the proxy_start tool input.",
		mimeType:    "application/json",
		filename:    "resources/schema_proxy_start.json",
	},
	{
		uri:         "yorishiro://schema/query",
		name:        "schema_query",
		description: "JSON Schema for the query tool input.",
		mimeType:    "application/json",
		filename:    "resources/schema_query.json",
	},
	{
		uri:         "yorishiro://schema/resend",
		name:        "schema_resend",
		description: "JSON Schema for the resend tool input.",
		mimeType:    "application/json",
		filename:    "resources/schema_resend.json",
	},
	{
		uri:         "yorishiro://schema/manage",
		name:        "schema_manage",
		description: "JSON Schema for the manage tool input.",
		mimeType:    "application/json",
		filename:    "resources/schema_manage.json",
	},
	{
		uri:         "yorishiro://schema/fuzz",
		name:        "schema_fuzz",
		description: "JSON Schema for the fuzz tool input.",
		mimeType:    "application/json",
		filename:    "resources/schema_fuzz.json",
	},
	{
		uri:         "yorishiro://schema/macro",
		name:        "schema_macro",
		description: "JSON Schema for the macro tool input.",
		mimeType:    "application/json",
		filename:    "resources/schema_macro.json",
	},
	{
		uri:         "yorishiro://schema/intercept",
		name:        "schema_intercept",
		description: "JSON Schema for the intercept tool input.",
		mimeType:    "application/json",
		filename:    "resources/schema_intercept.json",
	},
	{
		uri:         "yorishiro://schema/configure",
		name:        "schema_configure",
		description: "JSON Schema for the configure tool input.",
		mimeType:    "application/json",
		filename:    "resources/schema_configure.json",
	},
}

// registerResources registers all help and schema MCP resources on the server.
func (s *Server) registerResources() {
	allResources := make([]resourceDef, 0, len(helpResources)+len(schemaResources))
	allResources = append(allResources, helpResources...)
	allResources = append(allResources, schemaResources...)

	for _, rd := range allResources {
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
