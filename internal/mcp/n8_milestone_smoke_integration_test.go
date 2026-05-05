//go:build e2e

package mcp

// n8_milestone_smoke_integration_test.go — RFC-001 N8 (USK-681)
// milestone-cross-cutting smoke test.
//
// USK-681 closes the N8 milestone. Each prior N8 issue (USK-664…USK-685)
// already shipped a per-feature `_integration_test.go` that exercises the
// individual MCP tool. This file holds the *only* assertion that doesn't
// belong to any one of those: that the full set of N8-introduced typed
// MCP tools coexists on a single MCP server and that legacy single-string
// tools (resend, fuzz, intercept, plugin) remain registered alongside
// them — i.e. that no per-issue PR knocked a sibling registration off
// `Server.registerTools`.
//
// Scope is intentionally narrow. Per-tool semantics are owned by the
// existing files:
//   - resend_http_integration_test.go (USK-672)
//   - resend_ws_integration_test.go   (USK-673)
//   - resend_grpc_integration_test.go (USK-674)
//   - resend_raw_integration_test.go  (USK-675)
//   - intercept_typed_integration_test.go (USK-676)
//   - fuzz_http_integration_test.go   (USK-677)
//   - fuzz_ws_integration_test.go     (USK-678)
//   - fuzz_grpc_integration_test.go   (USK-679)
//   - fuzz_raw_integration_test.go    (USK-680)
//   - plugin_introspect_integration_test.go (USK-665/666 surface)
//   - query_multiproto_test.go (USK-667 family filter)

import (
	"context"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestN8Milestone_TypedToolSurfaceCoexists verifies that all N8-introduced
// typed MCP tools and the shared cross-cutting tools are registered on a
// default-constructed MCP server.
//
// The legacy single-string tools (`resend`, `fuzz`, `plugin`) were removed
// by USK-693 / USK-695 — only the typed siblings remain.
func TestN8Milestone_TypedToolSurfaceCoexists(t *testing.T) {
	cs := setupTestSession(t, newTestCA(t))

	res, err := cs.ListTools(context.Background(), &gomcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	got := make(map[string]bool, len(res.Tools))
	for _, tool := range res.Tools {
		got[tool.Name] = true
	}

	// N8-introduced typed tools (the 8 protocol-split + plugin_introspect
	// + intercept Protocol-typed extension; intercept keeps its name
	// because USK-676 chose tagged-union over per-protocol fan-out).
	n8Typed := []string{
		"resend_http",
		"resend_ws",
		"resend_grpc",
		"resend_raw",
		"fuzz_http",
		"fuzz_ws",
		"fuzz_grpc",
		"fuzz_raw",
		"plugin_introspect",
	}
	for _, name := range n8Typed {
		if !got[name] {
			t.Errorf("N8 typed tool %q missing from server registrations", name)
		}
	}

	// Shared / cross-cutting tools that must remain registered.
	shared := []string{
		"intercept",
		"query",
		"macro",
	}
	for _, name := range shared {
		if !got[name] {
			t.Errorf("shared tool %q missing — PR may have dropped a registration", name)
		}
	}
}
