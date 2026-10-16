package mcp

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Export directory confinement (USK-1127).
//
// manage export_flows / import_flows read and write files on the proxy
// server's filesystem. The MCP caller is the AI agent, which must never be
// able to change (or escape) the operator's Policy Layer — yet an
// unconfined output_path let it atomically replace any file in any
// directory writable by the proxy user: the -target-policy-file, the
// -config file, the CA key pair, the flow DB, or ~/.bashrc. Every
// server-side path these actions touch is therefore confined to one
// operator-configured export directory (-export-dir / YP_EXPORT_DIR,
// default ~/.yorishiro-proxy/exports/).
//
// Two layers enforce it:
//
//  1. resolveExportPath maps the requested path onto the directory and
//     rejects anything that resolves outside it (absolute paths elsewhere,
//     ".." escapes, symlinked directories pointing out) with a typed,
//     actionable error.
//  2. The actual open / create / rename goes through an os.Root opened on
//     the export directory, so the kernel-level lookup cannot escape it
//     even if the tree changes between the check and the use.
//
// This supersedes the USK-868 contract (paths resolved relative to the
// server process's working directory).

// maxExportPathLen bounds a caller-supplied output_path / input_path. It
// matches Linux PATH_MAX; longer inputs are rejected before any
// filesystem call.
const maxExportPathLen = 4096

// exportDirHint is appended to export-path errors so the caller (and the
// operator reading them) knows which knob controls the directory.
const exportDirHint = "set -export-dir / YP_EXPORT_DIR or use a path relative to it"

// exportEvalSymlinks and exportLstat are the filesystem probes
// resolveExportPath performs. They are package variables only so a test
// can record every probed path and assert that none lies lexically
// outside the export directory: an agent-supplied path must be rejected
// before any filesystem access (on Windows a UNC path would otherwise
// open an SMB / WebDAV connection and leak the proxy user's NTLM hash;
// on Linux it could trigger autofs or stall on a network mount).
var (
	exportEvalSymlinks = filepath.EvalSymlinks
	exportLstat        = os.Lstat
)

// WithExportDir sets the directory that confines manage export_flows /
// import_flows file paths (USK-1127). Relative output_path / input_path
// values resolve against it and paths outside it are rejected. An empty
// dir (the default) disables file export / import entirely — inline
// JSONL export keeps working. The value is operator-owned: no MCP tool
// can change it.
func WithExportDir(dir string) ServerOption {
	return func(s *Server) {
		s.misc.exportDir = dir
	}
}

// exportPath is a caller-supplied output_path / input_path mapped onto the
// export directory.
type exportPath struct {
	// rel is the clean, export-directory-relative path ("a/b.har"). It is
	// always filepath.IsLocal and never ".".
	rel string
	// abs is the absolute path reported back to the caller:
	// filepath.Join(exportDir, rel).
	abs string
}

// exportPathOutsideError reports a path that resolves outside the export
// directory. Callers use errors.As to log the escape attempt.
type exportPathOutsideError struct {
	requested string
	root      string
}

func (e *exportPathOutsideError) Error() string {
	return fmt.Sprintf("path %q resolves outside export directory %s; %s", e.requested, e.root, exportDirHint)
}

// resolveExportPath maps requested onto exportDir.
//
// Relative paths resolve against exportDir. Absolute paths are accepted
// only when they lie lexically inside exportDir as configured or inside
// its symlink-resolved form; an absolute path that reaches the directory
// through some other alias is rejected. That lexical decision is made
// before any filesystem access to the requested path: every probe below
// touches only paths inside the export directory. The parent directory
// must already exist (subdirectories are never created), a
// final-component symlink is rejected, and any intermediate symlink that
// leads outside the directory is rejected. Containment uses filepath.Rel +
// filepath.IsLocal, never a string-prefix test.
func resolveExportPath(exportDir, requested string) (exportPath, error) {
	if exportDir == "" {
		return exportPath{}, errors.New("file export/import is disabled: no export directory is configured; set -export-dir / YP_EXPORT_DIR on the server")
	}
	if err := validateRequestedPath(requested); err != nil {
		return exportPath{}, err
	}

	rootReal, err := exportEvalSymlinks(exportDir)
	if err != nil {
		return exportPath{}, fmt.Errorf("export directory %s is unavailable: %w; set -export-dir / YP_EXPORT_DIR to an existing directory", exportDir, err)
	}

	outside := &exportPathOutsideError{requested: requested, root: exportDir}

	rel, ok := lexicalRel(exportDir, rootReal, requested)
	if !ok {
		return exportPath{}, outside
	}
	if rel == "." {
		return exportPath{}, fmt.Errorf("file path %q must name a file inside export directory %s, not the directory itself", requested, exportDir)
	}

	// The parent must exist (no implicit mkdir) and, once symlinks are
	// resolved, must still be inside the export directory.
	parentReal, err := exportEvalSymlinks(filepath.Join(rootReal, filepath.Dir(rel)))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return exportPath{}, fmt.Errorf("directory %q does not exist in export directory %s; subdirectories are not created automatically", filepath.Dir(rel), exportDir)
		}
		return exportPath{}, fmt.Errorf("resolve parent directory of %q: %w", requested, err)
	}
	if !pathWithin(rootReal, parentReal) {
		return exportPath{}, outside
	}

	if info, err := exportLstat(filepath.Join(parentReal, filepath.Base(rel))); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return exportPath{}, fmt.Errorf("file path must not be a symbolic link: %s", filepath.Join(exportDir, rel))
	}

	return exportPath{rel: rel, abs: filepath.Join(exportDir, rel)}, nil
}

// validateRequestedPath rejects empty, oversized and NUL-bearing input
// before any filesystem call.
func validateRequestedPath(requested string) error {
	if requested == "" {
		return errors.New("file path must not be empty")
	}
	if len(requested) > maxExportPathLen {
		return fmt.Errorf("file path is too long (%d bytes, max %d)", len(requested), maxExportPathLen)
	}
	if strings.IndexByte(requested, 0) >= 0 {
		return errors.New("file path must not contain NUL bytes")
	}
	return nil
}

// lexicalRel returns the clean root-relative form of requested ("." for
// the root itself), or ok=false when it lies outside the export
// directory. Relative paths must be filepath.IsLocal after cleaning;
// absolute paths go through relInsideRoot. Intermediate symlinks are
// checked separately by the caller.
func lexicalRel(root, rootReal, requested string) (rel string, ok bool) {
	if filepath.IsAbs(requested) {
		return relInsideRoot(root, rootReal, filepath.Clean(requested))
	}
	rel = filepath.Clean(requested)
	if rel != "." && !filepath.IsLocal(rel) {
		return "", false
	}
	return rel, true
}

// relInsideRoot returns the root-relative form of the absolute, clean
// path p when p lies lexically inside the configured root or its
// symlink-resolved form. It is purely lexical and must stay so: p is
// agent-supplied, and resolving symlinks in a path outside the root would
// be attacker-directed I/O (a UNC path on Windows makes the server
// authenticate to a remote SMB / WebDAV host). Callers that spell the root
// through any other alias must use a relative path or the form reported
// as export_dir.
func relInsideRoot(root, rootReal, p string) (string, bool) {
	for _, r := range []string{root, rootReal} {
		if rel, err := filepath.Rel(r, p); err == nil && (rel == "." || filepath.IsLocal(rel)) {
			return rel, true
		}
	}
	return "", false
}

// pathWithin reports whether p equals root or lies beneath it. Both must
// be absolute and clean.
func pathWithin(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && (rel == "." || filepath.IsLocal(rel))
}

// openExportRoot opens exportDir as an os.Root, translating failure into
// an error that names the directory and the flag.
func openExportRoot(exportDir string) (*os.Root, error) {
	root, err := os.OpenRoot(exportDir)
	if err != nil {
		return nil, fmt.Errorf("export directory %s is unavailable: %w; set -export-dir / YP_EXPORT_DIR to an existing directory", exportDir, err)
	}
	return root, nil
}

// writeExportFileAtomic writes target inside exportDir via a temp file in
// the same directory followed by a rename, all through an os.Root so no
// step can leave the export directory. writeFn receives the temp file and
// returns the number of items written. The resulting file has mode 0600.
// Overwriting an existing regular file inside the directory is allowed.
func writeExportFileAtomic(exportDir string, target exportPath, writeFn func(f *os.File) (int, error)) (n int, err error) {
	root, err := openExportRoot(exportDir)
	if err != nil {
		return 0, err
	}
	defer root.Close()

	tmpRel := filepath.Join(filepath.Dir(target.rel), ".yorishiro-export-"+rand.Text()+".tmp")
	tmpFile, err := root.OpenFile(tmpRel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, fmt.Errorf("create temp file for export: %w", err)
	}
	success := false
	defer func() {
		tmpFile.Close()
		if !success {
			_ = root.Remove(tmpRel)
		}
	}()

	// O_CREATE's mode is filtered by the umask; pin it explicitly.
	if err := tmpFile.Chmod(0o600); err != nil {
		return 0, fmt.Errorf("set file permissions: %w", err)
	}

	n, err = writeFn(tmpFile)
	if err != nil {
		return 0, err
	}
	if err := tmpFile.Close(); err != nil {
		return 0, fmt.Errorf("close temp file: %w", err)
	}

	// Re-check right before the rename: the target must not have become a
	// symlink since resolution. (Root.Rename replaces a symlink rather than
	// following it, so this is about honouring the documented contract, not
	// about escaping the directory.)
	if info, statErr := root.Lstat(target.rel); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return 0, fmt.Errorf("output_path must not be a symbolic link: %s", target.abs)
	}

	if err := root.Rename(tmpRel, target.rel); err != nil {
		return 0, fmt.Errorf("rename temp file to output: %w", err)
	}
	success = true
	return n, nil
}

// readExportFile opens target inside exportDir through an os.Root and
// passes it to readFn. Only regular files are accepted; symlinks are
// rejected.
func readExportFile(exportDir string, target exportPath, readFn func(f *os.File) error) error {
	root, err := openExportRoot(exportDir)
	if err != nil {
		return err
	}
	defer root.Close()

	info, err := root.Lstat(target.rel)
	if err != nil {
		return fmt.Errorf("open input file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("input_path must not be a symbolic link: %s", target.abs)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("input_path must be a regular file: %s", target.abs)
	}

	f, err := root.Open(target.rel)
	if err != nil {
		return fmt.Errorf("open input file: %w", err)
	}
	defer f.Close()
	// Re-check on the opened handle: the entry may have been swapped for a
	// non-regular file between the Lstat above and the Open.
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat input file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("input_path must be a regular file: %s", target.abs)
	}
	return readFn(f)
}
