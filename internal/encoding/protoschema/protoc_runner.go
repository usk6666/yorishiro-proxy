// Package protoschema protoc_runner.go invokes a host protoc binary to
// compile a list of .proto files into a FileDescriptorSet payload that
// the existing LoadFileDescriptorSet path can consume (USK-926).
//
// This is the runner side of the grpc_schema MCP tool's source="file"
// path. Lives in the protoschema package so internal/mcp/ stays free of
// os/exec. The MCP handler (handleGRPCSchemaRegister) calls
// RunProtoc(ctx, opts) and feeds the returned bytes into
// LoadFileDescriptorSet + SaveGRPCSchema → Registry.Register — i.e. the
// runner is a strict adaptor and the persistence semantics are byte-
// identical to source="descriptor_set" (Resolved #18).
//
// Security stance — every concern is enumerated below so a reader can
// audit the surface in one read (Resolved decisions 7–17):
//
//   - Inputs are server-side. The MCP handler enforces that proto_paths
//     and import_paths are absolute, NUL-free, and that filepath.Clean
//     preserves the value (no "..", no double-slashes).
//   - filepath.EvalSymlinks is applied AFTER the basic checks, so a
//     value that fails validation cannot trigger a stat on an attacker-
//     controlled location.
//   - The resolved paths must fall under at least one allowed root
//     (server CWD or a user-supplied import_paths entry). Without this
//     check, an MCP caller could enumerate file existence anywhere on
//     the host (Resolved #28 reality check).
//   - The protoc subprocess inherits ONLY PATH from the parent
//     environment; nothing else is propagated (Resolved #12).
//   - cmd.Dir is the per-call temp dir (Resolved #13).
//   - The 30-second timeout is hardcoded; the temp dir is removed in a
//     defer (Resolved #11, #15).
//   - Combined stdout+stderr is truncated to 4 KiB when included in
//     errors (Resolved #14).
package protoschema

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ProtocTimeout is the maximum wall-clock time a single protoc
// invocation is allowed to consume before the runner cancels it. 30s
// covers cold-cache reads of large proto trees on slow CI runners while
// remaining tight enough that an MCP caller does not block the server
// indefinitely (Resolved #11).
const ProtocTimeout = 30 * time.Second

// protocStderrLimit is the byte cap applied to the captured combined
// stdout+stderr buffer when included in an error string. 4 KiB matches
// the design-review decision (Resolved #14): enough to surface the
// "file not found" / "syntax error at line N" message family without
// letting a misbehaving protoc fill the MCP response with megabytes
// of noise.
const protocStderrLimit = 4 * 1024

// ProtocRunOptions is the per-invocation input to RunProtoc. Every
// field is server-side enumerated by the MCP handler; the runner
// itself does NOT consult untrusted state.
type ProtocRunOptions struct {
	// Binary is the protoc executable to invoke. Either a bare name
	// resolved via $PATH (e.g. "protoc") or an absolute path. The
	// caller is expected to have run config.ResolveProtocBinary first.
	Binary string

	// ProtoPaths is the list of .proto files to compile. All entries
	// must be absolute, syntactically clean (filepath.Clean preserves
	// the value) and free of NUL bytes; the runner re-validates these
	// defensively before exec. The values are exec'd literally as
	// trailing positional arguments to protoc.
	ProtoPaths []string

	// ImportPaths is the list of `-I` roots. May be empty — in that
	// case the runner derives a single import root from the directory
	// of the first proto path. All entries follow the same validation
	// rules as ProtoPaths.
	ImportPaths []string

	// AllowedRoots is the set of directories under which any resolved
	// (post-EvalSymlinks) proto/import path must fall. The runner
	// rejects an input that escapes every entry in this set. Typically
	// the MCP handler supplies {server CWD, all user-supplied import
	// paths} and falls back to {server CWD, each filepath.Dir of the
	// proto paths} when import_paths is empty.
	AllowedRoots []string
}

// ProtocResult is the structured output of RunProtoc.
type ProtocResult struct {
	// DescriptorSet is the raw bytes of the generated
	// FileDescriptorSet, ready to feed into LoadFileDescriptorSet. The
	// length is bounded by MaxDescriptorSetBytes (RunProtoc rejects a
	// larger output rather than passing it on).
	DescriptorSet []byte

	// DurationMS is the protoc subprocess wall-clock time, useful for
	// diagnostic logging.
	DurationMS int64
}

// errProtocNotFound is the sentinel returned when exec.LookPath fails
// for the configured Binary. Callers (MCP handler) may unwrap with
// errors.Is to surface an install hint without string-matching the
// message text.
var errProtocNotFound = errors.New("protoc binary not found")

// ErrProtocNotFound returns the sentinel for "protoc binary missing
// from PATH". Wrap-safe with errors.Is so callers can branch without
// inspecting the wrapped message.
func ErrProtocNotFound() error { return errProtocNotFound }

// RunProtoc invokes the configured protoc binary on the given proto
// paths and returns the resulting FileDescriptorSet bytes.
//
// The implementation is the strict design-review prescription (USK-926
// Resolved #11–#17):
//
//  1. exec.LookPath on opts.Binary; missing → wrapped errProtocNotFound.
//  2. Per-call temp dir via os.MkdirTemp; defer-removed.
//  3. context.WithTimeout(ProtocTimeout) derived from ctx.
//  4. cmd.Env = {PATH only}; cmd.Dir = temp dir.
//  5. argv = [-I<root1> -I<root2> ... --include_imports --descriptor_set_out=<tmp>/out.desc <protos...>].
//  6. CombinedOutput; on non-zero exit, include the captured output
//     truncated to 4 KiB in the wrapped error.
//  7. Read the .desc file. Reject if length > MaxDescriptorSetBytes
//     before calling LoadFileDescriptorSet (defensive double-check —
//     LoadFileDescriptorSet also checks).
//
// Returns a ProtocResult on success or a wrapped error otherwise. The
// caller is responsible for passing DescriptorSet to
// LoadFileDescriptorSet.
func RunProtoc(ctx context.Context, opts ProtocRunOptions) (*ProtocResult, error) {
	if err := validateRunOptions(opts); err != nil {
		return nil, err
	}

	binPath, err := exec.LookPath(opts.Binary)
	if err != nil {
		return nil, fmt.Errorf("%w: %q in PATH: install protoc and ensure it is on PATH, or set GRPCSchema.ProtocBinary in the config file (or YP_PROTOC_BINARY env var)", errProtocNotFound, opts.Binary)
	}

	resolvedProtos, err := resolveAndCheckPaths(opts.ProtoPaths, opts.AllowedRoots, "proto_paths")
	if err != nil {
		return nil, err
	}
	importRoots := opts.ImportPaths
	if len(importRoots) == 0 {
		importRoots = deriveImportRoots(opts.ProtoPaths)
	}
	resolvedImports, err := resolveAndCheckPaths(importRoots, opts.AllowedRoots, "import_paths")
	if err != nil {
		return nil, err
	}

	tmpDir, err := os.MkdirTemp("", "yorishiro-proxy-protoc-*")
	if err != nil {
		return nil, fmt.Errorf("create protoc temp dir: %w", err)
	}
	defer func() {
		if rerr := os.RemoveAll(tmpDir); rerr != nil {
			slog.Warn("failed to remove protoc temp dir", "dir", tmpDir, "err", rerr)
		}
	}()

	descPath := filepath.Join(tmpDir, "out.desc")
	args := buildProtocArgs(resolvedImports, descPath, resolvedProtos)

	runCtx, cancel := context.WithTimeout(ctx, ProtocTimeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, binPath, args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	cmd.Dir = tmpDir

	slog.DebugContext(ctx, "protoc invocation",
		"binary", binPath,
		"proto_count", len(resolvedProtos),
		"import_root_count", len(resolvedImports),
		"tmp_dir", tmpDir,
	)

	start := time.Now()
	combined, runErr := cmd.CombinedOutput()
	durMS := time.Since(start).Milliseconds()

	if runErr != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("protoc timed out after %s: %s", ProtocTimeout, truncateForError(combined))
		}
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			return nil, fmt.Errorf("protoc failed (exit %d): %s", exitErr.ExitCode(), truncateForError(combined))
		}
		return nil, fmt.Errorf("protoc failed: %w: %s", runErr, truncateForError(combined))
	}

	// Stat first so we can reject an oversized output before reading it
	// into memory. LoadFileDescriptorSet also enforces the cap, but
	// applying it pre-read bounds the worst-case allocation when a
	// future protoc bug or misuse produces a multi-GiB descriptor.
	fi, err := os.Stat(descPath)
	if err != nil {
		return nil, fmt.Errorf("read protoc output: %w: %s", err, truncateForError(combined))
	}
	if fi.Size() > MaxDescriptorSetBytes {
		return nil, fmt.Errorf("protoc output size %d exceeds maximum %d bytes", fi.Size(), MaxDescriptorSetBytes)
	}

	raw, err := os.ReadFile(descPath)
	if err != nil {
		return nil, fmt.Errorf("read protoc output %s: %w", descPath, err)
	}

	slog.DebugContext(ctx, "protoc invocation complete",
		"duration_ms", durMS,
		"descriptor_bytes", len(raw),
	)

	return &ProtocResult{
		DescriptorSet: raw,
		DurationMS:    durMS,
	}, nil
}

// validateRunOptions runs syntactic checks on the options before any
// filesystem or exec call. Mirrors the MCP handler validation so the
// runner is safe to call directly from tests with a fresh struct.
func validateRunOptions(opts ProtocRunOptions) error {
	if strings.TrimSpace(opts.Binary) == "" {
		return errors.New("protoc binary is empty")
	}
	if len(opts.ProtoPaths) == 0 {
		return errors.New("proto_paths is empty")
	}
	if err := validatePathList(opts.ProtoPaths, "proto_paths"); err != nil {
		return err
	}
	if err := validatePathList(opts.ImportPaths, "import_paths"); err != nil {
		return err
	}
	if err := validatePathList(opts.AllowedRoots, "allowed_roots"); err != nil {
		return err
	}
	return nil
}

// validatePathList enforces the Resolved #7 basics on every path in
// the list: absolute, NUL-free, syntactically clean. The check is
// done BEFORE EvalSymlinks so a malformed path cannot trigger a stat
// on attacker-controlled territory.
func validatePathList(paths []string, label string) error {
	for i, p := range paths {
		if p == "" {
			return fmt.Errorf("%s[%d]: empty path", label, i)
		}
		if strings.IndexByte(p, 0) >= 0 {
			return fmt.Errorf("%s[%d]: contains NUL byte", label, i)
		}
		if !filepath.IsAbs(p) {
			return fmt.Errorf("%s[%d]: %q is not an absolute path", label, i, p)
		}
		if cleaned := filepath.Clean(p); cleaned != p {
			return fmt.Errorf("%s[%d]: %q is not in canonical form (use %q)", label, i, p, cleaned)
		}
	}
	return nil
}

// resolveAndCheckPaths applies filepath.EvalSymlinks to each input and
// confirms the result falls under at least one allowed root
// (Resolved #8, #9). The resolved paths are returned so the caller
// can feed them to protoc verbatim — using the symlink-resolved value
// avoids surprises where protoc itself resolves the link to a path
// outside the allowed roots.
func resolveAndCheckPaths(paths []string, allowedRoots []string, label string) ([]string, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	resolvedRoots, err := resolveAllowedRoots(allowedRoots)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(paths))
	for i, p := range paths {
		resolved, err := filepath.EvalSymlinks(p)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: resolve %q: %w", label, i, p, err)
		}
		if !pathUnderAnyRoot(resolved, resolvedRoots) {
			return nil, fmt.Errorf("%s[%d]: %q (resolved %q) is not under any allowed root %v", label, i, p, resolved, allowedRoots)
		}
		out = append(out, resolved)
	}
	return out, nil
}

// resolveAllowedRoots applies EvalSymlinks to each allowed root once
// so the per-path comparison can use a string-prefix check on
// canonicalised paths. Missing roots are skipped (a stale entry in
// the config should not poison the entire registration).
func resolveAllowedRoots(roots []string) ([]string, error) {
	out := make([]string, 0, len(roots))
	for _, r := range roots {
		resolved, err := filepath.EvalSymlinks(r)
		if err != nil {
			// A missing allowed root is non-fatal — the remaining
			// roots can still cover the inputs. We do NOT fold the
			// error in: stale config entries are common (e.g. a CI
			// runner without the operator's home dir).
			continue
		}
		out = append(out, resolved)
	}
	return out, nil
}

// pathUnderAnyRoot returns true when p is identical to a root or sits
// beneath it. The comparison uses filepath.Rel to avoid the classic
// strings.HasPrefix("foo-bar", "foo") bug where a sibling directory
// shares a prefix with an allowed root.
func pathUnderAnyRoot(p string, roots []string) bool {
	for _, r := range roots {
		rel, err := filepath.Rel(r, p)
		if err != nil {
			continue
		}
		// A rel that escapes the root starts with ".." (or, on
		// Windows, is an absolute path back to a different volume).
		if rel == "." || (!strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel)) {
			return true
		}
	}
	return false
}

// deriveImportRoots returns one -I root per unique filepath.Dir of the
// proto paths. Used when the MCP caller did not supply explicit
// import_paths. The returned slice preserves the discovery order so
// protoc's lookup is deterministic.
func deriveImportRoots(protoPaths []string) []string {
	seen := make(map[string]struct{}, len(protoPaths))
	out := make([]string, 0, len(protoPaths))
	for _, p := range protoPaths {
		dir := filepath.Dir(p)
		if _, ok := seen[dir]; ok {
			continue
		}
		seen[dir] = struct{}{}
		out = append(out, dir)
	}
	return out
}

// buildProtocArgs assembles the argv list for the protoc subprocess.
// The order matches protoc's documented expectations:
//
//	-I<root>... --include_imports --descriptor_set_out=<file> <protos...>
//
// We always pass --include_imports so transitive imports are folded
// into the output. Without it, a downstream LoadFileDescriptorSet
// would reject the result for missing dependencies — defeating the
// purpose of source="file".
func buildProtocArgs(importRoots []string, descOut string, protoPaths []string) []string {
	args := make([]string, 0, len(importRoots)+2+len(protoPaths))
	for _, r := range importRoots {
		args = append(args, "-I"+r)
	}
	args = append(args, "--include_imports")
	args = append(args, "--descriptor_set_out="+descOut)
	args = append(args, protoPaths...)
	return args
}

// truncateForError clips long stdout+stderr captures so they do not
// dominate an MCP error message. UTF-8-safe in the sense that a
// truncated byte sequence is the worst case the caller already sees
// from protoc itself (which may emit any byte sequence on parse
// errors).
func truncateForError(b []byte) string {
	if len(b) == 0 {
		return "(no output)"
	}
	if len(b) <= protocStderrLimit {
		return string(b)
	}
	return string(b[:protocStderrLimit]) + "... (truncated)"
}
