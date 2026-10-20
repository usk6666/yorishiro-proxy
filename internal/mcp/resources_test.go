package mcp

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// setupResourceTestSession creates an MCP client session for resource tests.
func setupResourceTestSession(t *testing.T) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	ca := newTestCA(t)
	s := newServer(ctx, ca, nil, nil)
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
		"yorishiro://help/getting-started",
		"yorishiro://help/template-syntax",
		"yorishiro://help/docs",
		"yorishiro://help/proxy_start",
		"yorishiro://help/proxy_stop",
		"yorishiro://help/query",
		"yorishiro://help/manage",
		"yorishiro://help/macro",
		"yorishiro://help/intercept",
		"yorishiro://help/configure",
		"yorishiro://help/examples",
		"yorishiro://help/security",
		"yorishiro://help/resend_http",
		"yorishiro://help/resend_ws",
		"yorishiro://help/resend_grpc",
		"yorishiro://help/resend_raw",
		"yorishiro://help/fuzz_http",
		"yorishiro://help/fuzz_ws",
		"yorishiro://help/fuzz_grpc",
		"yorishiro://help/fuzz_raw",
		"yorishiro://help/plugin_introspect",
		"yorishiro://help/grpc_schema",
	}
	for _, uri := range expectedHelpURIs {
		if !gotURIs[uri] {
			t.Errorf("missing help resource: %s", uri)
		}
	}

	// Help resources are the only resources (no yorishiro://schema/*).
	if len(result.Resources) != len(expectedHelpURIs) {
		t.Errorf("resource count = %d, want %d", len(result.Resources), len(expectedHelpURIs))
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
			wantContains: "flows",
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
			validMIME := r.MIMEType == "text/markdown" || r.MIMEType == "text/plain"
			if !validMIME {
				t.Errorf("unexpected MIME type: %s", r.MIMEType)
			}

			// Help resources should be markdown, info resources should be plain text.
			if strings.Contains(r.URI, "/help/") && r.MIMEType != "text/markdown" {
				t.Errorf("help resource has MIME type %s, want text/markdown", r.MIMEType)
			}
			if strings.Contains(r.URI, "/info/") && r.MIMEType != "text/plain" {
				t.Errorf("info resource has MIME type %s, want text/plain", r.MIMEType)
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
	allDefs := helpResources

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
	allDefs := helpResources

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

// TestResourceDefinitions_EveryEmbeddedFileIsRegistered is the reverse
// direction of TestResourceDefinitions_AllFilesExist: that test proves every
// registry entry resolves to a file, this one proves every embedded file is
// reachable through the registry.
//
// Without it, dropping a new resources/*.md into the tree and forgetting the
// helpResources entry compiles, passes every existing test, and silently
// ships a document no agent can reach — which is the class of failure
// USK-1036 exists to close.
func TestResourceDefinitions_EveryEmbeddedFileIsRegistered(t *testing.T) {
	entries, err := resourcesFS.ReadDir("resources")
	if err != nil {
		t.Fatalf("read embedded resources dir: %v", err)
	}

	helpByFile := make(map[string]resourceDef, len(helpResources))
	for _, rd := range helpResources {
		if prev, dup := helpByFile[rd.filename]; dup {
			t.Errorf("file %s is registered twice (%s and %s)", rd.filename, prev.name, rd.name)
		}
		helpByFile[rd.filename] = rd
	}
	seenMD := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := "resources/" + e.Name()
		switch {
		case strings.HasSuffix(e.Name(), ".md"):
			seenMD++
			rd, ok := helpByFile[name]
			if !ok {
				t.Errorf("embedded file %s has no helpResources entry; add one (uri, name, topic, description, mimeType, filename)", name)
				continue
			}
			if rd.topic == "" {
				t.Errorf("help resource %s has an empty topic; it would be unreachable via the docs tool", rd.name)
			}
		default:
			t.Errorf("unexpected embedded resource %s: only *.md is registered", name)
		}
	}

	if seenMD != len(helpResources) {
		t.Errorf("embedded *.md count = %d, helpResources = %d", seenMD, len(helpResources))
	}
}

// TestResourceDefinitions_TopicFieldPopulation asserts the topic namespace
// invariant: every help resource is a docs topic, and its URI and filename
// agree with the topic.
func TestResourceDefinitions_TopicFieldPopulation(t *testing.T) {
	seen := make(map[string]string, len(helpResources))
	for _, rd := range helpResources {
		if rd.topic == "" {
			t.Errorf("help resource %s has no topic", rd.name)
			continue
		}
		if prev, dup := seen[rd.topic]; dup {
			t.Errorf("topic %q is claimed by both %s and %s", rd.topic, prev, rd.name)
		}
		seen[rd.topic] = rd.name

		// The URI path segment and the topic must agree, so an agent that
		// saw yorishiro://help/X can call docs(topic="X") and vice versa.
		if want := "yorishiro://help/" + rd.topic; rd.uri != want {
			t.Errorf("resource %s: uri = %q, want %q to match topic %q", rd.name, rd.uri, want, rd.topic)
		}
		if want := "resources/help_" + rd.topic + ".md"; rd.filename != want {
			t.Errorf("resource %s: filename = %q, want %q to match topic %q", rd.name, rd.filename, want, rd.topic)
		}
	}
}

// TestHelpResources_ValidUTF8NoControlBytes guards the delivery path.
//
// help_fuzz_ws.md shipped a raw NUL byte inside a JSON example for months
// (file(1) classified it as "data", and grep treated it as binary, which hid
// a stale cross-link in the same file). The docs tool makes these documents
// the primary reference surface for every agent, so a control byte is no
// longer a cosmetic defect.
//
// Tab, LF and CR are the only control characters markdown legitimately needs.
func TestHelpResources_ValidUTF8NoControlBytes(t *testing.T) {
	entries, err := resourcesFS.ReadDir("resources")
	if err != nil {
		t.Fatalf("read embedded resources dir: %v", err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := "resources/" + e.Name()
		t.Run(e.Name(), func(t *testing.T) {
			data, err := resourcesFS.ReadFile(name)
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			if !utf8.Valid(data) {
				t.Fatalf("%s is not valid UTF-8", name)
			}
			for i, b := range data {
				if b == '\t' || b == '\n' || b == '\r' {
					continue
				}
				if b < 0x20 || b == 0x7f {
					t.Fatalf("%s: control byte 0x%02x at offset %d", name, b, i)
				}
			}
		})
	}
}

// TestHelpResources_HeadingDepthWithinOutline is a corpus invariant, not a
// unit test: it constrains what may be written into resources/*.md.
//
// extractDocsSection can address any heading from H2 down, but only H2 appears
// in the docs() index and only H2–H4 in the unknown-section outline
// (docsOutlineMaxLevel). A deeper heading would therefore be addressable via
// section= while appearing on no discovery surface at all — an agent could
// only reach it by guessing the exact text, which is precisely the failure
// class the docs tool exists to remove (USK-1036).
//
// help_docs.md states the H2–H4 range to agents as a contract; this test is
// what keeps that statement true. To introduce H5, raise docsOutlineMaxLevel
// and update that sentence — do not delete this test.
func TestHelpResources_HeadingDepthWithinOutline(t *testing.T) {
	for _, rd := range helpResources {
		if rd.topic == "" {
			continue
		}
		t.Run(rd.topic, func(t *testing.T) {
			data, err := resourcesFS.ReadFile(rd.filename)
			if err != nil {
				t.Fatalf("read %s: %v", rd.filename, err)
			}
			for _, h := range scanDocsHeadings(strings.Split(string(data), "\n")) {
				if h.level > docsOutlineMaxLevel {
					t.Errorf("%s:%d: H%d heading %q exceeds docsOutlineMaxLevel (%d); "+
						"it is addressable via section= but listed in neither the docs() index nor the unknown-section outline",
						rd.filename, h.start+1, h.level, h.text, docsOutlineMaxLevel)
				}
			}
		})
	}
}
