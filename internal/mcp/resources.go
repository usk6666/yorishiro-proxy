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
		uri:         "katashiro://help/proxy_start",
		name:        "help_proxy_start",
		description: "Full parameter documentation and usage examples for the proxy_start tool.",
		mimeType:    "text/markdown",
		filename:    "resources/help_proxy_start.md",
	},
	{
		uri:         "katashiro://help/proxy_stop",
		name:        "help_proxy_stop",
		description: "Documentation for the proxy_stop tool.",
		mimeType:    "text/markdown",
		filename:    "resources/help_proxy_stop.md",
	},
	{
		uri:         "katashiro://help/query",
		name:        "help_query",
		description: "Resource list, filter syntax, and usage examples for the query tool.",
		mimeType:    "text/markdown",
		filename:    "resources/help_query.md",
	},
	{
		uri:         "katashiro://help/execute",
		name:        "help_execute",
		description: "Action list, parameter syntax, and usage examples for the execute tool.",
		mimeType:    "text/markdown",
		filename:    "resources/help_execute.md",
	},
	{
		uri:         "katashiro://help/configure",
		name:        "help_configure",
		description: "Operation types, merge/replace syntax, and usage examples for the configure tool.",
		mimeType:    "text/markdown",
		filename:    "resources/help_configure.md",
	},
	{
		uri:         "katashiro://help/examples",
		name:        "help_examples",
		description: "Common vulnerability assessment workflow examples using katashiro-proxy.",
		mimeType:    "text/markdown",
		filename:    "resources/help_examples.md",
	},
}

// schemaResources lists all JSON Schema resources.
var schemaResources = []resourceDef{
	{
		uri:         "katashiro://schema/proxy_start",
		name:        "schema_proxy_start",
		description: "JSON Schema for the proxy_start tool input.",
		mimeType:    "application/json",
		filename:    "resources/schema_proxy_start.json",
	},
	{
		uri:         "katashiro://schema/query",
		name:        "schema_query",
		description: "JSON Schema for the query tool input.",
		mimeType:    "application/json",
		filename:    "resources/schema_query.json",
	},
	{
		uri:         "katashiro://schema/execute",
		name:        "schema_execute",
		description: "JSON Schema for the execute tool input.",
		mimeType:    "application/json",
		filename:    "resources/schema_execute.json",
	},
	{
		uri:         "katashiro://schema/configure",
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
