//go:build e2e && !e2e_smoke

// Package mcp grpc_schema_file_source_integration_test.go is the
// USK-926 e2e test for the source="file" path: a temp directory holds
// a .proto file, the proxy invokes the host protoc binary to compile
// it, and the resulting schema lands in the Registry via the MCP
// transport.
//
// Lives in the exhaustive e2e tier (`//go:build e2e && !e2e_smoke`)
// because the host-protoc dependency is unsuitable for the per-PR
// smoke gate. Skipped when protoc is not on PATH (Resolved #20).
package mcp

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// helloProtoFixture is a minimal proto used by every file-source test
// here. Single service, single method, two scalar message fields.
const helloProtoFixture = `syntax = "proto3";

package usk.test.file;

service Hello {
  rpc Say (Req) returns (Resp);
}

message Req {
  string name = 1;
}

message Resp {
  string greeting = 1;
}
`

// writeHelloProto writes the fixture to a per-test temp dir and
// returns the absolute path. The dir doubles as the import root.
func writeHelloProto(t *testing.T) (dir, proto string) {
	t.Helper()
	dir = t.TempDir()
	proto = filepath.Join(dir, "hello.proto")
	if err := os.WriteFile(proto, []byte(helloProtoFixture), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return dir, proto
}

func TestGRPCSchema_Register_FileSource_HappyPath(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("protoc"); err != nil {
		t.Skip("protoc not on PATH: skipping host-invocation test (USK-926)")
	}
	dir, proto := writeHelloProto(t)
	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	result := callGRPCSchema(t, cs, map[string]any{
		"action": "register",
		"params": map[string]any{
			"source":       "file",
			"proto_paths":  []any{proto},
			"import_paths": []any{dir},
		},
	})
	if result.IsError {
		t.Fatalf("register file source: %v", result.Content)
	}
	var out grpcSchemaRegisterResult
	unmarshalExecuteResult(t, result, &out)
	if len(out.Registered) != 1 {
		t.Fatalf("Registered len = %d, want 1", len(out.Registered))
	}
	if out.Registered[0].Service != "usk.test.file.Hello" {
		t.Errorf("Service = %q, want usk.test.file.Hello", out.Registered[0].Service)
	}
	if len(out.Registered[0].Methods) != 1 || out.Registered[0].Methods[0].Name != "Say" {
		t.Errorf("Methods = %+v", out.Registered[0].Methods)
	}
	// SourceLabel defaults to basename when not supplied (Resolved #19).
	if out.Registered[0].SourceLabel != "hello.proto" {
		t.Errorf("SourceLabel = %q, want hello.proto", out.Registered[0].SourceLabel)
	}

	// list confirms persistence — rehydrate from store is identical to descriptor_set mode.
	listResult := callGRPCSchema(t, cs, map[string]any{"action": "list"})
	var listOut grpcSchemaListResult
	unmarshalExecuteResult(t, listResult, &listOut)
	if len(listOut.Schemas) != 1 || listOut.Schemas[0].Service != "usk.test.file.Hello" {
		t.Errorf("list after file register: %+v", listOut.Schemas)
	}
}

func TestGRPCSchema_Register_FileSource_DefaultImportPaths(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("protoc"); err != nil {
		t.Skip("protoc not on PATH: skipping host-invocation test (USK-926)")
	}
	_, proto := writeHelloProto(t)
	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	// Omit import_paths — the runner should derive filepath.Dir(proto).
	result := callGRPCSchema(t, cs, map[string]any{
		"action": "register",
		"params": map[string]any{
			"source":      "file",
			"proto_paths": []any{proto},
		},
	})
	if result.IsError {
		t.Fatalf("register with default import_paths: %v", result.Content)
	}
}

func TestGRPCSchema_Register_FileSource_ServiceFilter(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("protoc"); err != nil {
		t.Skip("protoc not on PATH: skipping host-invocation test (USK-926)")
	}
	dir, proto := writeHelloProto(t)
	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	result := callGRPCSchema(t, cs, map[string]any{
		"action": "register",
		"params": map[string]any{
			"source":         "file",
			"proto_paths":    []any{proto},
			"import_paths":   []any{dir},
			"service_filter": []any{"usk.test.file.Hello"},
		},
	})
	if result.IsError {
		t.Fatalf("register file source with filter: %v", result.Content)
	}
	var out grpcSchemaRegisterResult
	unmarshalExecuteResult(t, result, &out)
	if len(out.Registered) != 1 {
		t.Fatalf("Registered len = %d, want 1", len(out.Registered))
	}
}

func TestGRPCSchema_Register_FileSource_NonAbsolutePath_Rejected(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	// No need for protoc: the relative-path check fires before exec.
	result := callGRPCSchema(t, cs, map[string]any{
		"action": "register",
		"params": map[string]any{
			"source":      "file",
			"proto_paths": []any{"relative/hello.proto"},
		},
	})
	if !result.IsError {
		t.Fatal("expected error for relative proto path")
	}
}

func TestGRPCSchema_Register_FileSource_OutsideAllowedRoot_Rejected(t *testing.T) {
	// No t.Parallel — this test mutates the package-level osGetwd
	// indirection (and other parallel tests in this file dispatch
	// through buildAllowedRoots, which reads it). Keeping the test
	// serial is simpler than introducing a sync primitive around
	// osGetwd just for the test surface.
	if _, err := exec.LookPath("protoc"); err != nil {
		t.Skip("protoc not on PATH: skipping host-invocation test (USK-926)")
	}
	// Two separate temp dirs: proto lives in `protoDir`, the only
	// allowed import root is `allowedDir`. The runner must reject the
	// proto path because it escapes the explicit import_paths set.
	protoDir := t.TempDir()
	allowedDir := t.TempDir()
	proto := filepath.Join(protoDir, "leaked.proto")
	if err := os.WriteFile(proto, []byte(helloProtoFixture), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	// Pin osGetwd somewhere that does NOT contain the proto, so the
	// proto path can only be reached through explicit import_paths.
	hermeticCwd := t.TempDir()
	prev := osGetwd
	t.Cleanup(func() { osGetwd = prev })
	osGetwd = func() (string, error) { return hermeticCwd, nil }

	result := callGRPCSchema(t, cs, map[string]any{
		"action": "register",
		"params": map[string]any{
			"source":       "file",
			"proto_paths":  []any{proto},
			"import_paths": []any{allowedDir},
		},
	})
	if !result.IsError {
		t.Fatal("expected error for proto outside allowed roots")
	}
	msg := extractTextContent(result)
	if !strings.Contains(msg, "not under any allowed root") {
		t.Errorf("error must mention allowed root: %q", msg)
	}
}
