// Package mcp grpc_schema_tool_test.go covers the grpc_schema MCP tool
// (USK-923) end-to-end: register / list / unregister / clear actions
// through the MCP client transport, plus the source="file" rejection
// path and the descriptor size cap.
package mcp

import (
	"context"
	_ "embed"
	"encoding/base64"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// embeddedTestDescBytes is the compiled FileDescriptorSet for the proto
// schema test fixture; sourced from
// internal/encoding/protoschema/testdata/test.proto. The file is
// duplicated under internal/mcp/testdata/ because go:embed paths cannot
// escape the package directory ("../" is rejected).
//
//go:embed testdata/test.desc
var embeddedTestDescBytes []byte

// embeddedTestDescMissingImports is the FileDescriptorSet generated
// WITHOUT --include_imports for the rejection-path test.
//
//go:embed testdata/with_imports_missing.desc
var embeddedTestDescMissingImports []byte

// callGRPCSchema invokes the grpc_schema tool and returns the raw result.
func callGRPCSchema(t *testing.T, cs *gomcp.ClientSession, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "grpc_schema",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	return result
}

// setupGRPCSchemaTestSession is a session helper modeled on
// setupMacroTestSession; it returns a connected MCP client.
func setupGRPCSchemaTestSession(t *testing.T, store flow.Store) *gomcp.ClientSession {
	t.Helper()
	return setupMacroTestSession(t, store)
}

func TestGRPCSchema_Register_Happy(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	b64 := base64.StdEncoding.EncodeToString(embeddedTestDescBytes)
	result := callGRPCSchema(t, cs, map[string]any{
		"action": "register",
		"params": map[string]any{
			"source":             "descriptor_set",
			"descriptor_set_b64": b64,
			"source_label":       "test-fixture",
		},
	})
	if result.IsError {
		t.Fatalf("register error: %v", result.Content)
	}

	var out grpcSchemaRegisterResult
	unmarshalExecuteResult(t, result, &out)
	if len(out.Registered) != 2 {
		t.Fatalf("Registered len = %d, want 2 (Greeter + Reflective)", len(out.Registered))
	}
	// Methods on Greeter must include SayHello + Echo.
	var greeter *grpcSchemaServiceEntry
	for i := range out.Registered {
		if out.Registered[i].Service == "usk.test.Greeter" {
			greeter = &out.Registered[i]
		}
	}
	if greeter == nil {
		t.Fatal("Greeter not present in register output")
	}
	if len(greeter.Methods) != 2 {
		t.Errorf("Greeter methods len = %d, want 2", len(greeter.Methods))
	}
	if greeter.SourceLabel != "test-fixture" {
		t.Errorf("Greeter SourceLabel = %q, want test-fixture", greeter.SourceLabel)
	}
}

// TestGRPCSchema_Register_FileSource_RequiresExplicitSource — U3:
// supplying proto_paths without source="file" is rejected; the caller
// has to be explicit about the mode (no auto-routing).
func TestGRPCSchema_Register_FileSource_RequiresExplicitSource(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	result := callGRPCSchema(t, cs, map[string]any{
		"action": "register",
		"params": map[string]any{
			"proto_paths": []any{"/abs/protos/x.proto"},
		},
	})
	if !result.IsError {
		t.Fatal("expected error for proto_paths without source=file")
	}
	msg := extractTextContent(result)
	if !strings.Contains(msg, "source=\"file\"") {
		t.Errorf("error must mention source=\"file\" requirement: %q", msg)
	}
}

// TestGRPCSchema_Register_FileSource_RequiresProtoPaths — U3:
// source="file" with no proto_paths is rejected.
func TestGRPCSchema_Register_FileSource_RequiresProtoPaths(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	result := callGRPCSchema(t, cs, map[string]any{
		"action": "register",
		"params": map[string]any{
			"source": "file",
		},
	})
	if !result.IsError {
		t.Fatal("expected error for source=file with no proto_paths")
	}
	msg := extractTextContent(result)
	if !strings.Contains(msg, "proto_paths is required") {
		t.Errorf("error must mention proto_paths required: %q", msg)
	}
}

// TestGRPCSchema_Register_DescriptorSetSource_RejectsProtoPaths — U3:
// explicit source="descriptor_set" + proto_paths is a mode mismatch.
func TestGRPCSchema_Register_DescriptorSetSource_RejectsProtoPaths(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	result := callGRPCSchema(t, cs, map[string]any{
		"action": "register",
		"params": map[string]any{
			"source":             "descriptor_set",
			"descriptor_set_b64": "Cg==",
			"proto_paths":        []any{"/abs/protos/x.proto"},
		},
	})
	if !result.IsError {
		t.Fatal("expected error for source=descriptor_set with proto_paths")
	}
	msg := extractTextContent(result)
	if !strings.Contains(msg, "proto_paths is only valid with source=\"file\"") {
		t.Errorf("error must explain mode mismatch: %q", msg)
	}
}

// TestGRPCSchema_Register_FileSource_RejectsDescriptorSetB64 — U3:
// source="file" with descriptor_set_b64 set is a mode mismatch.
func TestGRPCSchema_Register_FileSource_RejectsDescriptorSetB64(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	result := callGRPCSchema(t, cs, map[string]any{
		"action": "register",
		"params": map[string]any{
			"source":             "file",
			"proto_paths":        []any{"/abs/protos/x.proto"},
			"descriptor_set_b64": "Cg==",
		},
	})
	if !result.IsError {
		t.Fatal("expected error for source=file with descriptor_set_b64")
	}
	msg := extractTextContent(result)
	if !strings.Contains(msg, "descriptor_set_b64 is only valid with source=\"descriptor_set\"") {
		t.Errorf("error must explain mode mismatch: %q", msg)
	}
}

// TestGRPCSchema_Register_UnknownSource — any source value outside the
// {empty, descriptor_set, file} allowlist must be rejected.
func TestGRPCSchema_Register_UnknownSource(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	result := callGRPCSchema(t, cs, map[string]any{
		"action": "register",
		"params": map[string]any{
			"source": "reflection",
		},
	})
	if !result.IsError {
		t.Fatal("expected error for unknown source")
	}
}

func TestGRPCSchema_Register_MissingImportsRejected(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	b64 := base64.StdEncoding.EncodeToString(embeddedTestDescMissingImports)
	result := callGRPCSchema(t, cs, map[string]any{
		"action": "register",
		"params": map[string]any{
			"source":             "descriptor_set",
			"descriptor_set_b64": b64,
		},
	})
	if !result.IsError {
		t.Fatal("expected error for descriptor missing imports")
	}
	msg := extractTextContent(result)
	if !strings.Contains(msg, "include_imports") {
		t.Errorf("error must point at protoc --include_imports: %q", msg)
	}
}

func TestGRPCSchema_Register_ServiceFilter(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	b64 := base64.StdEncoding.EncodeToString(embeddedTestDescBytes)
	result := callGRPCSchema(t, cs, map[string]any{
		"action": "register",
		"params": map[string]any{
			"source":             "descriptor_set",
			"descriptor_set_b64": b64,
			"service_filter":     []any{"usk.test.Greeter"},
		},
	})
	if result.IsError {
		t.Fatalf("register error: %v", result.Content)
	}
	var out grpcSchemaRegisterResult
	unmarshalExecuteResult(t, result, &out)
	if len(out.Registered) != 1 || out.Registered[0].Service != "usk.test.Greeter" {
		t.Errorf("Registered = %+v, want exactly Greeter", out.Registered)
	}
}

func TestGRPCSchema_List_RoundTrip(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	b64 := base64.StdEncoding.EncodeToString(embeddedTestDescBytes)
	_ = callGRPCSchema(t, cs, map[string]any{
		"action": "register",
		"params": map[string]any{
			"source":             "descriptor_set",
			"descriptor_set_b64": b64,
		},
	})

	result := callGRPCSchema(t, cs, map[string]any{"action": "list"})
	if result.IsError {
		t.Fatalf("list error: %v", result.Content)
	}
	var out grpcSchemaListResult
	unmarshalExecuteResult(t, result, &out)
	if len(out.Schemas) != 2 {
		t.Errorf("Schemas len = %d, want 2", len(out.Schemas))
	}
	// Order is alphabetical.
	if out.Schemas[0].Service != "usk.test.Greeter" || out.Schemas[1].Service != "usk.test.Reflective" {
		t.Errorf("ordering wrong: %s, %s", out.Schemas[0].Service, out.Schemas[1].Service)
	}
}

func TestGRPCSchema_Unregister(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	b64 := base64.StdEncoding.EncodeToString(embeddedTestDescBytes)
	_ = callGRPCSchema(t, cs, map[string]any{
		"action": "register",
		"params": map[string]any{
			"source":             "descriptor_set",
			"descriptor_set_b64": b64,
		},
	})

	result := callGRPCSchema(t, cs, map[string]any{
		"action": "unregister",
		"params": map[string]any{"service": "usk.test.Greeter"},
	})
	if result.IsError {
		t.Fatalf("unregister error: %v", result.Content)
	}
	var out grpcSchemaUnregisterResult
	unmarshalExecuteResult(t, result, &out)
	if !out.Unregistered {
		t.Errorf("Unregistered = false, want true")
	}

	// list shows Reflective only.
	listResult := callGRPCSchema(t, cs, map[string]any{"action": "list"})
	var listOut grpcSchemaListResult
	unmarshalExecuteResult(t, listResult, &listOut)
	if len(listOut.Schemas) != 1 || listOut.Schemas[0].Service != "usk.test.Reflective" {
		t.Errorf("after unregister Schemas = %+v, want Reflective only", listOut.Schemas)
	}
}

func TestGRPCSchema_Unregister_Nonexistent(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	result := callGRPCSchema(t, cs, map[string]any{
		"action": "unregister",
		"params": map[string]any{"service": "no.such.Service"},
	})
	if result.IsError {
		t.Fatalf("unexpected error: %v", result.Content)
	}
	var out grpcSchemaUnregisterResult
	unmarshalExecuteResult(t, result, &out)
	if out.Unregistered {
		t.Error("Unregistered = true for nonexistent service")
	}
}

func TestGRPCSchema_Clear(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	b64 := base64.StdEncoding.EncodeToString(embeddedTestDescBytes)
	_ = callGRPCSchema(t, cs, map[string]any{
		"action": "register",
		"params": map[string]any{
			"source":             "descriptor_set",
			"descriptor_set_b64": b64,
		},
	})

	result := callGRPCSchema(t, cs, map[string]any{"action": "clear"})
	if result.IsError {
		t.Fatalf("clear error: %v", result.Content)
	}
	var out grpcSchemaClearResult
	unmarshalExecuteResult(t, result, &out)
	if out.Cleared != 2 {
		t.Errorf("Cleared = %d, want 2", out.Cleared)
	}

	// list returns empty.
	listResult := callGRPCSchema(t, cs, map[string]any{"action": "list"})
	var listOut grpcSchemaListResult
	unmarshalExecuteResult(t, listResult, &listOut)
	if len(listOut.Schemas) != 0 {
		t.Errorf("after clear Schemas = %+v, want empty", listOut.Schemas)
	}
}

func TestGRPCSchema_Register_OverwriteLastWriteWins(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	b64 := base64.StdEncoding.EncodeToString(embeddedTestDescBytes)
	// Register with label v1.
	_ = callGRPCSchema(t, cs, map[string]any{
		"action": "register",
		"params": map[string]any{
			"source":             "descriptor_set",
			"descriptor_set_b64": b64,
			"service_filter":     []any{"usk.test.Greeter"},
			"source_label":       "v1",
		},
	})
	// Register again with label v2.
	_ = callGRPCSchema(t, cs, map[string]any{
		"action": "register",
		"params": map[string]any{
			"source":             "descriptor_set",
			"descriptor_set_b64": b64,
			"service_filter":     []any{"usk.test.Greeter"},
			"source_label":       "v2",
		},
	})

	result := callGRPCSchema(t, cs, map[string]any{"action": "list"})
	var out grpcSchemaListResult
	unmarshalExecuteResult(t, result, &out)
	if len(out.Schemas) != 1 {
		t.Fatalf("Schemas len = %d, want 1", len(out.Schemas))
	}
	if out.Schemas[0].SourceLabel != "v2" {
		t.Errorf("SourceLabel = %q, want v2 (last-write-wins)", out.Schemas[0].SourceLabel)
	}
}

func TestGRPCSchema_Register_MissingDescriptorSetB64(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	result := callGRPCSchema(t, cs, map[string]any{
		"action": "register",
		"params": map[string]any{
			"source": "descriptor_set",
		},
	})
	if !result.IsError {
		t.Fatal("expected error for missing descriptor_set_b64")
	}
}

func TestGRPCSchema_InvalidAction(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	result := callGRPCSchema(t, cs, map[string]any{"action": "nope"})
	if !result.IsError {
		t.Fatal("expected error for invalid action")
	}
	msg := extractTextContent(result)
	if !strings.Contains(msg, "register") || !strings.Contains(msg, "list") {
		t.Errorf("error must enumerate valid actions: %q", msg)
	}
}

// TestGRPCSchema_Rehydrate_MultiServiceFromSameDescriptorSet is the
// regression test for USK-923 review F-1: ensureGRPCSchemaRehydrated
// previously cached parsed specs by descriptor_set bytes, which lost
// sibling services because the per-service filter ([rec.Service]) only
// returned one spec per cache entry. After fix, every service persisted
// under the same descriptor_set rehydrates independently.
func TestGRPCSchema_Rehydrate_MultiServiceFromSameDescriptorSet(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Seed two rows directly into the SchemaStore, both sharing the same
	// descriptor_set bytes (the realistic shape: handleGRPCSchemaRegister
	// writes the same `raw` once per service in the set).
	if err := store.SaveGRPCSchema(ctx, "usk.test.Greeter", embeddedTestDescBytes, "v1"); err != nil {
		t.Fatalf("SaveGRPCSchema Greeter: %v", err)
	}
	if err := store.SaveGRPCSchema(ctx, "usk.test.Reflective", embeddedTestDescBytes, "v1"); err != nil {
		t.Fatalf("SaveGRPCSchema Reflective: %v", err)
	}

	// Fresh in-memory Server (simulates process restart — no in-memory
	// Registry entries until rehydrate runs).
	s := newServer(ctx, nil, store, nil)
	if err := s.ensureGRPCSchemaRehydrated(ctx); err != nil {
		t.Fatalf("ensureGRPCSchemaRehydrated: %v", err)
	}

	svcs := s.grpcSchemaRegistry().ListServices()
	if len(svcs) != 2 {
		t.Fatalf("rehydrated services count = %d, want 2 (Greeter + Reflective)", len(svcs))
	}
	names := map[string]bool{}
	for _, sp := range svcs {
		names[sp.Service] = true
	}
	if !names["usk.test.Greeter"] || !names["usk.test.Reflective"] {
		t.Errorf("rehydrated services = %v, want both Greeter and Reflective", names)
	}
}

func TestGRPCSchema_EmptyAction(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	// The MCP transport's JSON schema rejects an entirely missing
	// "action" key. We exercise the handler's empty-action branch by
	// explicitly passing action="".
	result := callGRPCSchema(t, cs, map[string]any{"action": ""})
	if !result.IsError {
		t.Fatal("expected error for empty action")
	}
}
