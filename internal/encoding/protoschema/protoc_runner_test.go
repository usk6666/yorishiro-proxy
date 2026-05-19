package protoschema

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateRunOptions covers the syntactic validation that runs
// before any filesystem call. These tests do NOT require protoc.
func TestValidateRunOptions(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	proto := filepath.Join(tmp, "x.proto")
	if err := os.WriteFile(proto, []byte("syntax = \"proto3\";"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		opts    ProtocRunOptions
		wantErr string
	}{
		{
			name: "empty binary rejected",
			opts: ProtocRunOptions{
				Binary:     "",
				ProtoPaths: []string{proto},
			},
			wantErr: "protoc binary is empty",
		},
		{
			name: "whitespace binary rejected",
			opts: ProtocRunOptions{
				Binary:     "  ",
				ProtoPaths: []string{proto},
			},
			wantErr: "protoc binary is empty",
		},
		{
			name: "empty proto_paths rejected",
			opts: ProtocRunOptions{
				Binary:     "protoc",
				ProtoPaths: nil,
			},
			wantErr: "proto_paths is empty",
		},
		{
			name: "empty entry rejected",
			opts: ProtocRunOptions{
				Binary:     "protoc",
				ProtoPaths: []string{""},
			},
			wantErr: "empty path",
		},
		{
			name: "NUL byte rejected",
			opts: ProtocRunOptions{
				Binary:     "protoc",
				ProtoPaths: []string{"/abs/path\x00null"},
			},
			wantErr: "contains NUL byte",
		},
		{
			name: "relative path rejected",
			opts: ProtocRunOptions{
				Binary:     "protoc",
				ProtoPaths: []string{"./relative.proto"},
			},
			wantErr: "not an absolute path",
		},
		{
			name: "non-canonical path rejected",
			opts: ProtocRunOptions{
				Binary:     "protoc",
				ProtoPaths: []string{"/abs/../traversal.proto"},
			},
			wantErr: "not in canonical form",
		},
		{
			name: "trailing-slash non-canonical rejected",
			opts: ProtocRunOptions{
				Binary:     "protoc",
				ProtoPaths: []string{"/abs/dir//x.proto"},
			},
			wantErr: "not in canonical form",
		},
		{
			name: "valid options pass syntactic check",
			opts: ProtocRunOptions{
				Binary:     "protoc",
				ProtoPaths: []string{proto},
			},
			wantErr: "",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateRunOptions(tc.opts)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want error %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestPathUnderAnyRoot(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path  string
		roots []string
		want  bool
	}{
		{"/srv/protos/x.proto", []string{"/srv/protos"}, true},
		{"/srv/protos", []string{"/srv/protos"}, true},
		{"/srv/protos/nested/y.proto", []string{"/srv/protos"}, true},
		// Prefix-only false-positive guard: "/srv/protos-other" is NOT
		// under "/srv/protos" even though strings.HasPrefix would say
		// so.
		{"/srv/protos-other/x.proto", []string{"/srv/protos"}, false},
		{"/etc/passwd", []string{"/srv/protos"}, false},
		// Multiple roots — second root matches.
		{"/home/me/protos/x.proto", []string{"/srv/protos", "/home/me"}, true},
		// No roots = no match.
		{"/srv/protos/x.proto", nil, false},
	}
	for _, tc := range cases {
		if got := pathUnderAnyRoot(tc.path, tc.roots); got != tc.want {
			t.Errorf("pathUnderAnyRoot(%q, %v) = %v, want %v", tc.path, tc.roots, got, tc.want)
		}
	}
}

func TestDeriveImportRoots(t *testing.T) {
	t.Parallel()
	in := []string{
		"/srv/a/x.proto",
		"/srv/a/y.proto", // dedup against /srv/a
		"/srv/b/z.proto",
	}
	got := deriveImportRoots(in)
	want := []string{"/srv/a", "/srv/b"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (got %v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestBuildProtocArgs(t *testing.T) {
	t.Parallel()
	args := buildProtocArgs(
		[]string{"/srv/a", "/srv/b"},
		"/tmp/out.desc",
		[]string{"/srv/a/x.proto"},
	)
	want := []string{
		"-I/srv/a",
		"-I/srv/b",
		"--include_imports",
		"--descriptor_set_out=/tmp/out.desc",
		"/srv/a/x.proto",
	}
	if len(args) != len(want) {
		t.Fatalf("got %v, want %v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Errorf("args[%d] = %q, want %q", i, args[i], want[i])
		}
	}
}

func TestTruncateForError(t *testing.T) {
	t.Parallel()
	if got := truncateForError(nil); got != "(no output)" {
		t.Errorf("empty: got %q, want (no output)", got)
	}
	short := []byte("short message")
	if got := truncateForError(short); got != "short message" {
		t.Errorf("short: got %q", got)
	}
	long := make([]byte, protocStderrLimit*2)
	for i := range long {
		long[i] = 'A'
	}
	got := truncateForError(long)
	if !strings.HasSuffix(got, "... (truncated)") {
		t.Errorf("long must end with truncation marker: %q", got[len(got)-20:])
	}
	if len(got) > protocStderrLimit+len("... (truncated)") {
		t.Errorf("truncated length %d exceeds cap", len(got))
	}
}

// TestResolveAndCheckPaths_AllowedRoots verifies that a path resolved
// via EvalSymlinks is rejected when it escapes the allowed roots.
// Uses t.TempDir; no protoc required.
func TestResolveAndCheckPaths_AllowedRoots(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	allowed := filepath.Join(tmp, "allowed")
	denied := filepath.Join(tmp, "denied")
	if err := os.MkdirAll(allowed, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(denied, 0o755); err != nil {
		t.Fatal(err)
	}
	goodProto := filepath.Join(allowed, "ok.proto")
	if err := os.WriteFile(goodProto, []byte("syntax = \"proto3\";"), 0o644); err != nil {
		t.Fatal(err)
	}
	badProto := filepath.Join(denied, "leak.proto")
	if err := os.WriteFile(badProto, []byte("syntax = \"proto3\";"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Happy path — under allowed root.
	got, err := resolveAndCheckPaths([]string{goodProto}, []string{allowed}, "proto_paths")
	if err != nil {
		t.Fatalf("good path rejected: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("resolved = %v", got)
	}

	// Escape path — under denied root.
	if _, err := resolveAndCheckPaths([]string{badProto}, []string{allowed}, "proto_paths"); err == nil {
		t.Fatal("escape path was not rejected")
	} else if !strings.Contains(err.Error(), "not under any allowed root") {
		t.Errorf("wrong error: %v", err)
	}
}

// TestResolveAndCheckPaths_Symlinks confirms EvalSymlinks resolution
// is applied: a symlink that points outside the allowed root is
// rejected, even if the link itself lives under the root.
func TestResolveAndCheckPaths_Symlinks(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	allowed := filepath.Join(tmp, "allowed")
	denied := filepath.Join(tmp, "denied")
	if err := os.MkdirAll(allowed, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(denied, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(denied, "secret.proto")
	if err := os.WriteFile(target, []byte("syntax = \"proto3\";"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(allowed, "ok-looking.proto")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unsupported on this platform: %v", err)
	}

	_, err := resolveAndCheckPaths([]string{link}, []string{allowed}, "proto_paths")
	if err == nil {
		t.Fatal("symlink to outside-allowed target was not rejected")
	}
	if !strings.Contains(err.Error(), "not under any allowed root") {
		t.Errorf("wrong error: %v", err)
	}
}

// TestRunProtoc_BinaryMissing exercises the protoc-not-found branch
// without requiring protoc on the host. The binary name uses a clearly
// nonsensical value so any future install does not flake this test.
func TestRunProtoc_BinaryMissing(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	proto := filepath.Join(tmp, "x.proto")
	if err := os.WriteFile(proto, []byte("syntax = \"proto3\";"), 0o644); err != nil {
		t.Fatal(err)
	}

	opts := ProtocRunOptions{
		Binary:       "yorishiro-no-such-protoc-binary-USK-926",
		ProtoPaths:   []string{proto},
		AllowedRoots: []string{tmp},
	}
	_, err := RunProtoc(context.Background(), opts)
	if err == nil {
		t.Fatal("missing binary was not rejected")
	}
	if !errors.Is(err, ErrProtocNotFound()) {
		t.Errorf("err is not ErrProtocNotFound: %v", err)
	}
	if !strings.Contains(err.Error(), "YP_PROTOC_BINARY") {
		t.Errorf("missing env-var hint in error: %q", err)
	}
}

// TestRunProtoc_Success exercises the happy path using a real protoc
// binary. Skipped when protoc is not on PATH (Resolved #20).
func TestRunProtoc_Success(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("protoc"); err != nil {
		t.Skip("protoc not on PATH: skipping host-invocation test (USK-926)")
	}
	tmp := t.TempDir()
	proto := filepath.Join(tmp, "hello.proto")
	const src = `syntax = "proto3";
package usk.test.runner;
service Hello {
  rpc Say (Req) returns (Resp);
}
message Req { string name = 1; }
message Resp { string greeting = 1; }
`
	if err := os.WriteFile(proto, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	opts := ProtocRunOptions{
		Binary:       "protoc",
		ProtoPaths:   []string{proto},
		AllowedRoots: []string{tmp},
	}
	res, err := RunProtoc(context.Background(), opts)
	if err != nil {
		t.Fatalf("RunProtoc: %v", err)
	}
	if len(res.DescriptorSet) == 0 {
		t.Fatal("DescriptorSet is empty")
	}
	specs, err := LoadFileDescriptorSet(res.DescriptorSet, nil)
	if err != nil {
		t.Fatalf("LoadFileDescriptorSet: %v", err)
	}
	if len(specs) != 1 || specs[0].Service != "usk.test.runner.Hello" {
		t.Errorf("specs = %+v", specs)
	}
}

// TestRunProtoc_ProtoSyntaxError_NonZeroExit confirms that a malformed
// .proto surfaces protoc's stderr in the returned error.
func TestRunProtoc_ProtoSyntaxError_NonZeroExit(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("protoc"); err != nil {
		t.Skip("protoc not on PATH: skipping host-invocation test (USK-926)")
	}
	tmp := t.TempDir()
	bad := filepath.Join(tmp, "bad.proto")
	if err := os.WriteFile(bad, []byte("not actually a proto"), 0o644); err != nil {
		t.Fatal(err)
	}

	opts := ProtocRunOptions{
		Binary:       "protoc",
		ProtoPaths:   []string{bad},
		AllowedRoots: []string{tmp},
	}
	_, err := RunProtoc(context.Background(), opts)
	if err == nil {
		t.Fatal("malformed proto was accepted")
	}
	if !strings.Contains(err.Error(), "protoc failed") {
		t.Errorf("err is not a protoc-failed wrap: %v", err)
	}
}
