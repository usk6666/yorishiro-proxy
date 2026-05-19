// Package mcp grpc_schema_file_source_unit_test.go covers the
// USK-926 file-source validation table and the deriveFileSourceLabel /
// buildAllowedRoots helpers. The actual host-protoc invocation is
// exercised in the e2e tier (grpc_schema_file_source_integration_test.go).
package mcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateGRPCSchemaRegisterInput_FileSourceMatrix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		params  grpcSchemaToolParams
		wantErr string // substring; "" = no error
	}{
		{
			name:    "empty source + descriptor_set_b64 set (USK-923 back-compat)",
			params:  grpcSchemaToolParams{DescriptorSetB64: "Cg=="},
			wantErr: "",
		},
		{
			name:    "empty source + proto_paths rejected",
			params:  grpcSchemaToolParams{ProtoPaths: []string{"/abs/x.proto"}},
			wantErr: "source=\"file\" must be set explicitly",
		},
		{
			name:    "empty source + import_paths rejected",
			params:  grpcSchemaToolParams{ImportPaths: []string{"/abs"}, DescriptorSetB64: "Cg=="},
			wantErr: "import_paths is only valid with source=\"file\"",
		},
		{
			name:    "descriptor_set + proto_paths rejected",
			params:  grpcSchemaToolParams{Source: "descriptor_set", DescriptorSetB64: "Cg==", ProtoPaths: []string{"/abs/x.proto"}},
			wantErr: "proto_paths is only valid",
		},
		{
			name:    "descriptor_set + missing descriptor_set_b64 rejected",
			params:  grpcSchemaToolParams{Source: "descriptor_set"},
			wantErr: "descriptor_set_b64 is required",
		},
		{
			name:    "descriptor_set + import_paths rejected",
			params:  grpcSchemaToolParams{Source: "descriptor_set", DescriptorSetB64: "Cg==", ImportPaths: []string{"/abs"}},
			wantErr: "import_paths is only valid",
		},
		{
			name:    "file + proto_paths set (happy path)",
			params:  grpcSchemaToolParams{Source: "file", ProtoPaths: []string{"/abs/x.proto"}},
			wantErr: "",
		},
		{
			name:    "file + empty proto_paths rejected",
			params:  grpcSchemaToolParams{Source: "file"},
			wantErr: "proto_paths is required",
		},
		{
			name:    "file + descriptor_set_b64 rejected",
			params:  grpcSchemaToolParams{Source: "file", ProtoPaths: []string{"/abs/x.proto"}, DescriptorSetB64: "Cg=="},
			wantErr: "descriptor_set_b64 is only valid",
		},
		{
			name:    "unknown source rejected",
			params:  grpcSchemaToolParams{Source: "reflection"},
			wantErr: "is not supported",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateGRPCSchemaRegisterInput(tc.params)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestDeriveFileSourceLabel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"empty", nil, ""},
		{"single", []string{"/srv/protos/greeter.proto"}, "greeter.proto"},
		{"multiple", []string{"/srv/a/x.proto", "/srv/b/y.proto"}, "x.proto,y.proto"},
	}
	for _, tc := range cases {
		if got := deriveFileSourceLabel(tc.in); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestBuildAllowedRoots(t *testing.T) {
	// No t.Parallel — this test mutates the package-level osGetwd
	// indirection and would race against other tests that also call
	// buildAllowedRoots (e.g. the e2e file-source integration tests).
	tmp := t.TempDir()
	prev := osGetwd
	t.Cleanup(func() { osGetwd = prev })
	osGetwd = func() (string, error) { return tmp, nil }

	t.Run("only proto_paths -> cwd + dirs", func(t *testing.T) {
		params := grpcSchemaToolParams{
			Source:     "file",
			ProtoPaths: []string{"/srv/a/x.proto", "/srv/b/y.proto"},
		}
		got, err := buildAllowedRoots(params)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{tmp, "/srv/a", "/srv/b"}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("[%d] %q want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("explicit import_paths replace derivation", func(t *testing.T) {
		params := grpcSchemaToolParams{
			Source:      "file",
			ProtoPaths:  []string{"/srv/a/x.proto"},
			ImportPaths: []string{"/srv/imports"},
		}
		got, err := buildAllowedRoots(params)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{tmp, "/srv/imports"}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})

	t.Run("duplicate cwd not added twice", func(t *testing.T) {
		params := grpcSchemaToolParams{
			Source:      "file",
			ProtoPaths:  []string{filepath.Join(tmp, "x.proto")},
			ImportPaths: []string{tmp},
		}
		got, err := buildAllowedRoots(params)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, r := range got {
			if r == tmp {
				count++
			}
		}
		if count != 1 {
			t.Errorf("cwd appears %d times in %v", count, got)
		}
	})
}

func TestBuildAllowedRoots_GetwdFailure(t *testing.T) {
	// No t.Parallel — see TestBuildAllowedRoots for the rationale.
	prev := osGetwd
	t.Cleanup(func() { osGetwd = prev })
	osGetwd = func() (string, error) { return "", os.ErrPermission }

	params := grpcSchemaToolParams{
		Source:     "file",
		ProtoPaths: []string{"/abs/x.proto"},
	}
	_, err := buildAllowedRoots(params)
	if err == nil {
		t.Fatal("expected error when os.Getwd fails")
	}
}
