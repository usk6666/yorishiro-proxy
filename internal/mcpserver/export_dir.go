package mcpserver

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
)

// Export directory boot handling (USK-1127).
//
// The export directory is the only place the MCP manage tool may write
// (export_flows) or read (import_flows) files. Confinement is only
// meaningful if nothing the operator relies on lives inside it: an agent
// that can replace the policy file, the config file, the CA, the DB or a
// plugin script through export_flows can rewrite the Policy Layer on the
// next restart. The server therefore refuses to start when any such path
// resolves inside the export directory. There is deliberately no
// "unrestricted" escape hatch.

// exportDirSetting is the resolved export directory.
type exportDirSetting struct {
	// dir is the absolute, clean export directory path.
	dir string
	// isDefault is true when no -export-dir / YP_EXPORT_DIR was given and
	// dir is config.DefaultExportDir(), which the server creates on demand.
	isDefault bool
}

// resolveExportDir returns the export directory selected by cfg.ExportDir
// (already validated to exist by Config.Validate when non-empty), or the
// default when it is empty.
func resolveExportDir(cfg *config.Config) (exportDirSetting, error) {
	dir, isDefault := cfg.ExportDir, false
	if dir == "" {
		dir, isDefault = config.DefaultExportDir(), true
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return exportDirSetting{}, fmt.Errorf("resolve export directory %q: %w", dir, err)
	}
	return exportDirSetting{dir: abs, isDefault: isDefault}, nil
}

// setupExportDir resolves the export directory, refuses a directory that
// contains any operator-owned boot path, and records the resolved absolute
// path on cfg.ExportDir (the value handed to mcp.WithExportDir). It has no
// filesystem side effects; prepareExportDir creates the default directory
// once logging is up.
func setupExportDir(cfg *config.Config, configFile, targetPolicyFile string, proxyCfg *config.ProxyConfig) (exportDirSetting, error) {
	setting, err := resolveExportDir(cfg)
	if err != nil {
		return exportDirSetting{}, err
	}
	if err := checkExportDirIsolation(setting.dir, protectedBootPaths(cfg, configFile, targetPolicyFile, proxyCfg)); err != nil {
		return exportDirSetting{}, err
	}
	cfg.ExportDir = setting.dir
	return setting, nil
}

// protectedPath is an operator-owned path that must not be reachable from
// the export directory.
type protectedPath struct {
	// what describes the path for the refusal message ("-config file").
	what string
	path string
	// isDir marks a directory whose contents are operator-owned (-ui-dir):
	// the export directory must neither contain it nor lie inside it.
	isDir bool
}

// protectedBootPaths lists every operator-owned path known at boot that
// manage export_flows must never be able to overwrite.
func protectedBootPaths(cfg *config.Config, configFile, targetPolicyFile string, proxyCfg *config.ProxyConfig) []protectedPath {
	var out []protectedPath
	add := func(what, p string) {
		if p != "" {
			out = append(out, protectedPath{what: what, path: p})
		}
	}

	add("-config file", configFile)
	add("-target-policy-file", targetPolicyFile)

	// CA: explicit files, or the auto-persisted default location (which
	// may not exist yet — InitCA creates it on first boot).
	add("-ca-cert file", cfg.CACertPath)
	add("-ca-key file", cfg.CAKeyPath)
	if !cfg.CAEphemeral && cfg.CACertPath == "" && cfg.CAKeyPath == "" {
		certPath, keyPath := cert.DefaultCACertPath(), cert.DefaultCAKeyPath()
		if cfg.CADataDir != "" {
			certPath, keyPath = filepath.Join(cfg.CADataDir, "ca.crt"), filepath.Join(cfg.CADataDir, "ca.key")
		}
		add("persisted CA certificate", certPath)
		add("persisted CA private key", keyPath)
	}

	if dbPath, err := config.ResolveDBPath(cfg.DBPath); err == nil {
		add("-db database", dbPath)
	}
	add("-log-file", cfg.LogFile)
	if cfg.UIDir != "" {
		out = append(out, protectedPath{what: "-ui-dir", path: cfg.UIDir, isDir: true})
	}
	if p, err := ServerJSONPath(); err == nil {
		add("server.json", p)
	}

	if proxyCfg != nil {
		for i, pl := range proxyCfg.Plugins {
			add(fmt.Sprintf("plugin script (plugins[%d])", i), pl.Path)
		}
		add("client_cert file", proxyCfg.ClientCertPath)
		add("client_key file", proxyCfg.ClientKeyPath)
		hosts := make([]string, 0, len(proxyCfg.HostTLS))
		for h := range proxyCfg.HostTLS {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		for _, h := range hosts {
			e := proxyCfg.HostTLS[h]
			if e == nil {
				continue
			}
			add(fmt.Sprintf("host_tls[%s] client_cert file", h), e.ClientCertPath)
			add(fmt.Sprintf("host_tls[%s] client_key file", h), e.ClientKeyPath)
			add(fmt.Sprintf("host_tls[%s] ca_bundle file", h), e.CABundlePath)
		}
	}
	return out
}

// checkExportDirIsolation returns an error when any protected path
// resolves inside exportDir (or, for directories, when exportDir resolves
// inside it). Paths are compared after symlink resolution of their longest
// existing prefix, so neither a symlinked -export-dir nor a not-yet-created
// file (DB, default CA) slips through. Each comparison is also made by
// identity (insideDir / os.SameFile), which catches aliases a lexical
// comparison misses: a case-variant spelling on a case-insensitive
// filesystem, or a bind-mounted directory.
func checkExportDirIsolation(exportDir string, protected []protectedPath) error {
	root, err := resolveExistingPrefix(exportDir)
	if err != nil {
		return fmt.Errorf("resolve export directory %s: %w", exportDir, err)
	}
	// rootInfo is nil when the export directory does not exist yet (the
	// default, created after this check); the lexical comparison still
	// applies then.
	rootInfo, _ := os.Stat(root)
	for _, p := range protected {
		resolved, err := resolveExistingPrefix(p.path)
		if err != nil {
			return fmt.Errorf("resolve %s %s: %w", p.what, p.path, err)
		}
		if insideDir(root, rootInfo, resolved) {
			return fmt.Errorf("refusing to start: %s %s is inside the export directory %s, where the MCP manage tool could overwrite it; "+
				"choose a separate -export-dir / YP_EXPORT_DIR", p.what, p.path, exportDir)
		}
		if !p.isDir {
			continue
		}
		dirInfo, _ := os.Stat(resolved)
		if insideDir(resolved, dirInfo, root) {
			return fmt.Errorf("refusing to start: the export directory %s is inside the %s %s, where the MCP manage tool could replace its files; "+
				"choose a separate -export-dir / YP_EXPORT_DIR", exportDir, p.what, p.path)
		}
	}
	return nil
}

// resolveExistingPrefix returns p as an absolute path with symlinks
// resolved in its longest existing prefix; the non-existent remainder is
// appended verbatim.
func resolveExistingPrefix(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	cur, rest := abs, ""
	for {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			return filepath.Join(resolved, rest), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// insideDir reports whether the absolute path p is dir or lies beneath it,
// either lexically (isWithin) or by identity: p itself or one of its
// existing ancestors is the same file as dir (os.SameFile against
// dirInfo, the os.Stat of dir). dirInfo may be nil when dir does not
// exist, in which case only the lexical comparison applies. Boot-time
// only: dir and p are operator-supplied, so the ancestor Stat calls are
// not attacker-directed I/O.
func insideDir(dir string, dirInfo fs.FileInfo, p string) bool {
	if isWithin(dir, p) {
		return true
	}
	if dirInfo == nil {
		return false
	}
	for cur := p; ; {
		if fi, err := os.Stat(cur); err == nil && os.SameFile(dirInfo, fi) {
			return true
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return false
		}
		cur = parent
	}
}

// isWithin reports whether p equals root or lies beneath it (both absolute
// and clean). Uses filepath.Rel, never a string-prefix test.
func isWithin(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && (rel == "." || filepath.IsLocal(rel))
}

// prepareExportDir creates the default export directory (mode 0700) when
// it does not exist yet. Failure is not fatal: the server still boots, and
// file export / import report the unavailable directory and the flag on
// use. An operator-supplied directory was already validated to exist.
func prepareExportDir(setting exportDirSetting, logger *slog.Logger) {
	if !setting.isDefault {
		return
	}
	if err := os.MkdirAll(setting.dir, 0o700); err != nil {
		logger.Warn("failed to create export directory; manage export_flows / import_flows to files will fail until -export-dir / YP_EXPORT_DIR points at a usable directory",
			"dir", setting.dir, "error", err)
	}
}
