package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// setupResourceTestSession creates an MCP client session for resource tests.
func setupResourceTestSession(t *testing.T) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	ca := newTestCA(t)
	s := NewServer(ctx, ca, nil, nil)
	ct, st := gomcp.NewInMemoryTransports()

	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)

	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs
}

func TestListResources_AllRegistered(t *testing.T) {
	cs := setupResourceTestSession(t)

	result, err := cs.ListResources(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}

	// Build a set of all registered URIs.
	gotURIs := make(map[string]bool, len(result.Resources))
	for _, r := range result.Resources {
		gotURIs[r.URI] = true
	}

	// Verify all expected help resources are present.
	expectedHelpURIs := []string{
		"yorishiro://help/proxy_start",
		"yorishiro://help/proxy_stop",
		"yorishiro://help/query",
		"yorishiro://help/execute",
		"yorishiro://help/configure",
		"yorishiro://help/examples",
		"yorishiro://help/security",
	}
	for _, uri := range expectedHelpURIs {
		if !gotURIs[uri] {
			t.Errorf("missing help resource: %s", uri)
		}
	}

	// Verify all expected schema resources are present.
	expectedSchemaURIs := []string{
		"yorishiro://schema/proxy_start",
		"yorishiro://schema/query",
		"yorishiro://schema/execute",
		"yorishiro://schema/configure",
	}
	for _, uri := range expectedSchemaURIs {
		if !gotURIs[uri] {
			t.Errorf("missing schema resource: %s", uri)
		}
	}

	// Total expected count = 6 help + 4 schema = 10.
	expectedCount := len(expectedHelpURIs) + len(expectedSchemaURIs)
	if len(result.Resources) != expectedCount {
		t.Errorf("resource count = %d, want %d", len(result.Resources), expectedCount)
	}
}

func TestReadResource_HelpResources(t *testing.T) {
	cs := setupResourceTestSession(t)

	tests := []struct {
		name            string
		uri             string
		wantMIMEType    string
		wantContains    string // substring that must appear in content
		wantNotContains string // substring that must NOT appear (empty = skip check)
	}{
		{
			name:         "help/proxy_start",
			uri:          "yorishiro://help/proxy_start",
			wantMIMEType: "text/markdown",
			wantContains: "proxy_start",
		},
		{
			name:         "help/proxy_stop",
			uri:          "yorishiro://help/proxy_stop",
			wantMIMEType: "text/markdown",
			wantContains: "proxy_stop",
		},
		{
			name:         "help/query",
			uri:          "yorishiro://help/query",
			wantMIMEType: "text/markdown",
			wantContains: "sessions",
		},
		{
			name:         "help/execute",
			uri:          "yorishiro://help/execute",
			wantMIMEType: "text/markdown",
			wantContains: "replay",
		},
		{
			name:         "help/configure",
			uri:          "yorishiro://help/configure",
			wantMIMEType: "text/markdown",
			wantContains: "merge",
		},
		{
			name:         "help/examples",
			uri:          "yorishiro://help/examples",
			wantMIMEType: "text/markdown",
			wantContains: "Workflow",
		},
		{
			name:         "help/security",
			uri:          "yorishiro://help/security",
			wantMIMEType: "text/markdown",
			wantContains: "Two-Layer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := cs.ReadResource(context.Background(), &gomcp.ReadResourceParams{
				URI: tt.uri,
			})
			if err != nil {
				t.Fatalf("ReadResource(%s): %v", tt.uri, err)
			}

			if len(result.Contents) == 0 {
				t.Fatal("result has no contents")
			}

			content := result.Contents[0]
			if content.URI != tt.uri {
				t.Errorf("content URI = %q, want %q", content.URI, tt.uri)
			}
			if content.MIMEType != tt.wantMIMEType {
				t.Errorf("content MIMEType = %q, want %q", content.MIMEType, tt.wantMIMEType)
			}
			if content.Text == "" {
				t.Error("content text is empty")
			}
			if !strings.Contains(content.Text, tt.wantContains) {
				t.Errorf("content text does not contain %q", tt.wantContains)
			}
			if tt.wantNotContains != "" && strings.Contains(content.Text, tt.wantNotContains) {
				t.Errorf("content text should not contain %q", tt.wantNotContains)
			}
		})
	}
}

func TestReadResource_SchemaResources(t *testing.T) {
	cs := setupResourceTestSession(t)

	tests := []struct {
		name         string
		uri          string
		wantMIMEType string
		wantTitle    string // expected title field in JSON
	}{
		{
			name:         "schema/proxy_start",
			uri:          "yorishiro://schema/proxy_start",
			wantMIMEType: "application/json",
			wantTitle:    "proxy_start input",
		},
		{
			name:         "schema/query",
			uri:          "yorishiro://schema/query",
			wantMIMEType: "application/json",
			wantTitle:    "query input",
		},
		{
			name:         "schema/execute",
			uri:          "yorishiro://schema/execute",
			wantMIMEType: "application/json",
			wantTitle:    "execute input",
		},
		{
			name:         "schema/configure",
			uri:          "yorishiro://schema/configure",
			wantMIMEType: "application/json",
			wantTitle:    "configure input",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := cs.ReadResource(context.Background(), &gomcp.ReadResourceParams{
				URI: tt.uri,
			})
			if err != nil {
				t.Fatalf("ReadResource(%s): %v", tt.uri, err)
			}

			if len(result.Contents) == 0 {
				t.Fatal("result has no contents")
			}

			content := result.Contents[0]
			if content.URI != tt.uri {
				t.Errorf("content URI = %q, want %q", content.URI, tt.uri)
			}
			if content.MIMEType != tt.wantMIMEType {
				t.Errorf("content MIMEType = %q, want %q", content.MIMEType, tt.wantMIMEType)
			}

			// Verify the JSON is valid.
			var parsed map[string]any
			if err := json.Unmarshal([]byte(content.Text), &parsed); err != nil {
				t.Fatalf("content is not valid JSON: %v", err)
			}

			// Verify the title field.
			title, ok := parsed["title"].(string)
			if !ok {
				t.Fatal("schema missing title field")
			}
			if title != tt.wantTitle {
				t.Errorf("schema title = %q, want %q", title, tt.wantTitle)
			}

			// Verify it declares itself as a JSON Schema.
			schema, ok := parsed["$schema"].(string)
			if !ok || schema == "" {
				t.Error("schema missing $schema field")
			}

			// Verify the type is "object".
			typ, ok := parsed["type"].(string)
			if !ok || typ != "object" {
				t.Errorf("schema type = %q, want %q", typ, "object")
			}
		})
	}
}

func TestReadResource_ContentAccuracy(t *testing.T) {
	cs := setupResourceTestSession(t)

	// Verify help/query mentions all available resources.
	result, err := cs.ReadResource(context.Background(), &gomcp.ReadResourceParams{
		URI: "yorishiro://help/query",
	})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}

	text := result.Contents[0].Text
	for _, resource := range availableResources {
		if !strings.Contains(text, resource) {
			t.Errorf("help/query does not mention resource %q", resource)
		}
	}

	// Verify help/execute mentions all available actions.
	result, err = cs.ReadResource(context.Background(), &gomcp.ReadResourceParams{
		URI: "yorishiro://help/execute",
	})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}

	text = result.Contents[0].Text
	for _, action := range availableActions {
		if !strings.Contains(text, action) {
			t.Errorf("help/execute does not mention action %q", action)
		}
	}
}

func TestReadResource_SchemaFieldConsistency(t *testing.T) {
	cs := setupResourceTestSession(t)

	// Verify schema/query lists the correct resource enum values.
	result, err := cs.ReadResource(context.Background(), &gomcp.ReadResourceParams{
		URI: "yorishiro://schema/query",
	})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}

	var schema struct {
		Properties struct {
			Resource struct {
				Enum []string `json:"enum"`
			} `json:"resource"`
		} `json:"properties"`
	}
	if err := json.Unmarshal([]byte(result.Contents[0].Text), &schema); err != nil {
		t.Fatalf("unmarshal schema: %v", err)
	}

	gotResources := make(map[string]bool)
	for _, r := range schema.Properties.Resource.Enum {
		gotResources[r] = true
	}
	for _, r := range availableResources {
		if !gotResources[r] {
			t.Errorf("schema/query enum missing resource %q", r)
		}
	}

	// Verify schema/execute lists the correct action enum values.
	result, err = cs.ReadResource(context.Background(), &gomcp.ReadResourceParams{
		URI: "yorishiro://schema/execute",
	})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}

	var execSchema struct {
		Properties struct {
			Action struct {
				Enum []string `json:"enum"`
			} `json:"action"`
		} `json:"properties"`
	}
	if err := json.Unmarshal([]byte(result.Contents[0].Text), &execSchema); err != nil {
		t.Fatalf("unmarshal schema: %v", err)
	}

	gotActions := make(map[string]bool)
	for _, a := range execSchema.Properties.Action.Enum {
		gotActions[a] = true
	}
	for _, a := range availableActions {
		if !gotActions[a] {
			t.Errorf("schema/execute enum missing action %q", a)
		}
	}
}

func TestResourceMetadata(t *testing.T) {
	cs := setupResourceTestSession(t)

	result, err := cs.ListResources(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}

	for _, r := range result.Resources {
		t.Run(r.Name, func(t *testing.T) {
			if r.URI == "" {
				t.Error("resource URI is empty")
			}
			if r.Name == "" {
				t.Error("resource name is empty")
			}
			if r.Description == "" {
				t.Error("resource description is empty")
			}
			if r.MIMEType == "" {
				t.Error("resource MIME type is empty")
			}

			// Verify URI scheme.
			if !strings.HasPrefix(r.URI, "yorishiro://") {
				t.Errorf("URI %q does not start with yorishiro://", r.URI)
			}

			// Verify MIME type is valid.
			validMIME := r.MIMEType == "text/markdown" || r.MIMEType == "application/json"
			if !validMIME {
				t.Errorf("unexpected MIME type: %s", r.MIMEType)
			}

			// Help resources should be markdown, schema resources should be JSON.
			if strings.Contains(r.URI, "/help/") && r.MIMEType != "text/markdown" {
				t.Errorf("help resource has MIME type %s, want text/markdown", r.MIMEType)
			}
			if strings.Contains(r.URI, "/schema/") && r.MIMEType != "application/json" {
				t.Errorf("schema resource has MIME type %s, want application/json", r.MIMEType)
			}
		})
	}
}

func TestMakeResourceHandler_ReturnsContent(t *testing.T) {
	// Unit test the handler factory function directly.
	handler := makeResourceHandler("yorishiro://test/resource", "text/plain", "resources/help_proxy_stop.md")

	result, err := handler(context.Background(), &gomcp.ReadResourceRequest{})
	if err != nil {
		t.Fatalf("handler returned error: %v", err)
	}

	if len(result.Contents) != 1 {
		t.Fatalf("expected 1 content, got %d", len(result.Contents))
	}

	c := result.Contents[0]
	if c.URI != "yorishiro://test/resource" {
		t.Errorf("URI = %q, want %q", c.URI, "yorishiro://test/resource")
	}
	if c.MIMEType != "text/plain" {
		t.Errorf("MIMEType = %q, want %q", c.MIMEType, "text/plain")
	}
	if c.Text == "" {
		t.Error("text is empty")
	}
}

func TestMakeResourceHandler_InvalidFilename(t *testing.T) {
	// Verify that a handler for a nonexistent file returns an error.
	handler := makeResourceHandler("yorishiro://test/nonexistent", "text/plain", "resources/nonexistent.md")

	_, err := handler(context.Background(), &gomcp.ReadResourceRequest{})
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
	if !strings.Contains(err.Error(), "read embedded resource") {
		t.Errorf("error = %q, want it to contain 'read embedded resource'", err.Error())
	}
}

func TestResourceDefinitions_NoDuplicates(t *testing.T) {
	// Verify no duplicate URIs or names across all resource definitions.
	allDefs := make([]resourceDef, 0, len(helpResources)+len(schemaResources))
	allDefs = append(allDefs, helpResources...)
	allDefs = append(allDefs, schemaResources...)

	uris := make(map[string]bool)
	names := make(map[string]bool)

	for _, rd := range allDefs {
		if uris[rd.uri] {
			t.Errorf("duplicate URI: %s", rd.uri)
		}
		uris[rd.uri] = true

		if names[rd.name] {
			t.Errorf("duplicate name: %s", rd.name)
		}
		names[rd.name] = true
	}
}

func TestResourceDefinitions_AllFilesExist(t *testing.T) {
	// Verify that all referenced embedded files actually exist.
	allDefs := make([]resourceDef, 0, len(helpResources)+len(schemaResources))
	allDefs = append(allDefs, helpResources...)
	allDefs = append(allDefs, schemaResources...)

	for _, rd := range allDefs {
		t.Run(rd.name, func(t *testing.T) {
			data, err := resourcesFS.ReadFile(rd.filename)
			if err != nil {
				t.Fatalf("cannot read embedded file %s: %v", rd.filename, err)
			}
			if len(data) == 0 {
				t.Errorf("embedded file %s is empty", rd.filename)
			}
		})
	}
}

func TestSchemaResources_ValidJSON(t *testing.T) {
	// Verify all schema files are valid JSON independently of the MCP server.
	for _, rd := range schemaResources {
		t.Run(rd.name, func(t *testing.T) {
			data, err := resourcesFS.ReadFile(rd.filename)
			if err != nil {
				t.Fatalf("read file: %v", err)
			}

			var parsed map[string]any
			if err := json.Unmarshal(data, &parsed); err != nil {
				t.Fatalf("invalid JSON in %s: %v", rd.filename, err)
			}

			// Must have $schema, title, type.
			for _, key := range []string{"$schema", "title", "type"} {
				if _, ok := parsed[key]; !ok {
					t.Errorf("schema %s missing required field %q", rd.filename, key)
				}
			}
		})
	}
}

func TestHelpResources_NonEmpty(t *testing.T) {
	// Verify all help files start with a markdown heading.
	for _, rd := range helpResources {
		t.Run(rd.name, func(t *testing.T) {
			data, err := resourcesFS.ReadFile(rd.filename)
			if err != nil {
				t.Fatalf("read file: %v", err)
			}

			text := string(data)
			if !strings.HasPrefix(text, "# ") {
				t.Errorf("help file %s does not start with a markdown heading", rd.filename)
			}
		})
	}
}
