package setup

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
)

// nssNickname is the certificate nickname used in the NSSDB so that
// idempotent re-registration can locate and replace the previous entry.
const nssNickname = "yorishiro-proxy"

// execCommand is exec.Command, swappable in tests so that NSSDB helpers
// can be exercised without invoking the real `certutil` binary.
var execCommand = exec.Command

// geteuid is os.Geteuid, swappable in tests so that the SUDO_USER
// recovery branch in resolveTargetHomeForNSSDB can be exercised
// without running the test binary as root.
var geteuid = os.Geteuid

// CAInfo holds information about the CA certificate for display.
type CAInfo struct {
	CertPath    string
	Fingerprint string
	Generated   bool // true if the CA was newly generated during setup
}

// EnsureCA ensures a CA certificate exists at the given directory.
// If caDir is empty, the default path (~/.yorishiro-proxy/ca/) is used.
// If the CA already exists, it loads it. Otherwise, it generates a new one.
// Returns CAInfo with the certificate path and fingerprint.
func EnsureCA(caDir string) (*CAInfo, error) {
	if caDir == "" {
		caDir = cert.DefaultCADir()
	} else {
		caDir = filepath.Clean(caDir)
	}
	certPath := filepath.Join(caDir, "ca.crt")
	keyPath := filepath.Join(caDir, "ca.key")

	ca := &cert.CA{}
	generated := false

	// Try loading existing CA.
	if _, err := os.Stat(certPath); err == nil {
		if err := ca.Load(certPath, keyPath); err != nil {
			return nil, fmt.Errorf("load existing CA: %w", err)
		}
	} else if os.IsNotExist(err) {
		// Generate a new CA.
		if err := ca.Generate(); err != nil {
			return nil, fmt.Errorf("generate CA: %w", err)
		}
		// Save to disk.
		if err := os.MkdirAll(caDir, 0700); err != nil {
			return nil, fmt.Errorf("create CA directory: %w", err)
		}
		if err := ca.Save(certPath, keyPath); err != nil {
			return nil, fmt.Errorf("save CA: %w", err)
		}
		generated = true
	} else {
		return nil, fmt.Errorf("check CA certificate: %w", err)
	}

	// Compute fingerprint.
	fingerprint := sha256.Sum256(ca.Certificate().Raw)
	fingerprintStr := formatFingerprint(fingerprint[:])

	return &CAInfo{
		CertPath:    certPath,
		Fingerprint: fingerprintStr,
		Generated:   generated,
	}, nil
}

// CAInstallInstructions returns OS-specific instructions for installing the CA certificate.
func CAInstallInstructions(certPath string) string {
	return caInstallInstructionsForOS(certPath, runtime.GOOS)
}

// caInstallInstructionsForOS returns OS-specific instructions for a given GOOS value.
// Exported via CAInstallInstructions; this helper enables testing with arbitrary GOOS.
func caInstallInstructionsForOS(certPath, goos string) string {
	var b strings.Builder

	// Shell-quote the cert path to prevent injection via special characters.
	quoted := shellQuote(certPath)

	b.WriteString("Install the CA certificate in your OS trust store:\n\n")

	switch goos {
	case "darwin":
		b.WriteString("  macOS:\n")
		fmt.Fprintf(&b, "    sudo security add-trusted-cert -d -r trustRoot \\\n")
		fmt.Fprintf(&b, "      -k /Library/Keychains/System.keychain \\\n")
		fmt.Fprintf(&b, "      %s\n", quoted)
	case "linux":
		b.WriteString("  Linux (Debian/Ubuntu) — system trust store:\n")
		fmt.Fprintf(&b, "    sudo cp %s \\\n", quoted)
		b.WriteString("      /usr/local/share/ca-certificates/yorishiro-proxy.crt\n")
		b.WriteString("    sudo update-ca-certificates\n\n")
		b.WriteString("  Linux — Chromium / Firefox NSSDB (per user):\n")
		b.WriteString("    mkdir -p ~/.pki/nssdb\n")
		b.WriteString("    certutil -d sql:$HOME/.pki/nssdb -N --empty-password   # only if DB is new\n")
		fmt.Fprintf(&b, "    certutil -d sql:$HOME/.pki/nssdb -A -t \"C,,\" -n %q -i %s\n", nssNickname, quoted)
		b.WriteString("    # certutil ships in libnss3-tools (Debian/Ubuntu) / nss-tools (RHEL/CentOS) /\n")
		b.WriteString("    # mozilla-nss-tools (openSUSE).\n")
	case "windows":
		b.WriteString("  Windows (run as Administrator):\n")
		fmt.Fprintf(&b, "    certutil -addstore \"Root\" %s\n", quoted)
	default:
		b.WriteString("  Copy the CA certificate to your OS trust store.\n")
		fmt.Fprintf(&b, "  CA certificate path: %s\n", certPath)
	}

	return b.String()
}

// shellQuote wraps a string in single quotes, escaping any embedded single quotes.
// This prevents shell injection when the string is used in displayed shell commands.
func shellQuote(s string) string {
	// Replace each ' with '\'' (end quote, escaped quote, start quote).
	escaped := strings.ReplaceAll(s, "'", "'\\''")
	return "'" + escaped + "'"
}

// TrustCA registers the CA certificate in the OS trust store.
// It auto-detects the OS and runs the appropriate command.
// Requires elevated privileges (sudo on macOS/Linux, Administrator on Windows).
func TrustCA(certPath string) error {
	return trustCAForOS(certPath, runtime.GOOS)
}

// trustCAForOS implements OS-specific trust store registration.
// This helper enables testing with arbitrary GOOS values.
func trustCAForOS(certPath, goos string) error {
	certPath = filepath.Clean(certPath)
	switch goos {
	case "darwin":
		cmd := exec.Command("sudo", "security", "add-trusted-cert",
			"-d", "-r", "trustRoot",
			"-k", "/Library/Keychains/System.keychain",
			certPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("macOS trust store registration: %w", err)
		}
		return nil
	case "linux":
		destPath := "/usr/local/share/ca-certificates/yorishiro-proxy.crt"
		cpCmd := exec.Command("sudo", "cp", certPath, destPath)
		cpCmd.Stdout = os.Stdout
		cpCmd.Stderr = os.Stderr
		cpCmd.Stdin = os.Stdin
		if err := cpCmd.Run(); err != nil {
			return fmt.Errorf("copy CA to trust store: %w", err)
		}
		updateCmd := exec.Command("sudo", "update-ca-certificates")
		updateCmd.Stdout = os.Stdout
		updateCmd.Stderr = os.Stderr
		updateCmd.Stdin = os.Stdin
		if err := updateCmd.Run(); err != nil {
			return fmt.Errorf("update-ca-certificates: %w", err)
		}
		// Chromium and Firefox-default profiles consult NSSDB
		// (~/.pki/nssdb), which is independent of the system trust
		// store updated above. Without the next step, MITM fails
		// inside browsers even though OpenSSL-based clients trust
		// the CA. See USK-857.
		if err := installLinuxNSSDB(certPath); err != nil {
			return fmt.Errorf("NSSDB registration: %w", err)
		}
		return nil
	case "windows":
		cmd := exec.Command("certutil", "-addstore", "Root", certPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("windows trust store registration: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported OS for trust store registration: %s", goos)
	}
}

// formatFingerprint formats a byte slice as a colon-separated uppercase hex string.
func formatFingerprint(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}

// installLinuxNSSDB registers certPath into the per-user NSSDB at
// ~/.pki/nssdb so that Chromium and Firefox-default profiles trust the
// CA. Idempotent: an existing nickname-matching entry is deleted before
// re-registration. Returns an error if `certutil` is missing, if the
// process is running as root without SUDO_USER, or if certutil itself
// fails.
func installLinuxNSSDB(certPath string) error {
	certutil, err := exec.LookPath("certutil")
	if err != nil {
		return fmt.Errorf("certutil not found in PATH. " +
			"Install NSS tools: " +
			"apt install libnss3-tools (Debian/Ubuntu), " +
			"yum install nss-tools (RHEL/CentOS), or " +
			"zypper install mozilla-nss-tools (openSUSE)")
	}

	home, uid, gid, err := resolveTargetHomeForNSSDBWith(geteuid)
	if err != nil {
		return err
	}

	nssDir := filepath.Join(home, ".pki", "nssdb")
	if err := ensureNSSDB(certutil, nssDir, uid, gid); err != nil {
		return err
	}

	dbArg := "sql:" + nssDir

	// Idempotency: delete a previous entry if present. certutil exits
	// non-zero when the nickname is absent — that is the expected path
	// on a fresh DB, so the exit status is intentionally ignored.
	_, _ = runCertutil(certutil, "-D", "-d", dbArg, "-n", nssNickname)

	if out, err := runCertutil(certutil, "-A", "-d", dbArg,
		"-t", "C,,", "-n", nssNickname, "-i", certPath); err != nil {
		return fmt.Errorf("certutil -A: %w: %s", err, out)
	}
	return nil
}

// resolveTargetHomeForNSSDBWith returns the home directory (and uid/gid
// for chowning newly created files) of the user whose NSSDB should be
// updated. uid/gid are -1 when chown is unnecessary (i.e. the process
// is already running as that user).
//
// When the process is running as root (Geteuid()==0), the SUDO_USER
// environment variable identifies the original invoker; without it we
// have no way to know which user's NSSDB to write to and must
// hard-fail with actionable instructions.
func resolveTargetHomeForNSSDBWith(getuidFn func() int) (home string, uid int, gid int, err error) {
	if getuidFn() != 0 {
		h, e := os.UserHomeDir()
		if e != nil {
			return "", -1, -1, fmt.Errorf("resolve home: %w", e)
		}
		return h, -1, -1, nil
	}

	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser == "" {
		slog.Error("install ca --trust running as root without SUDO_USER; NSSDB step failed")
		return "", -1, -1, fmt.Errorf(
			"running as root without SUDO_USER; cannot determine target NSSDB. " +
				"Run without sudo, or manually register: " +
				"certutil -d sql:$HOME/.pki/nssdb -A -t \"C,,\" -n " + nssNickname + " -i <certPath>",
		)
	}

	u, e := user.Lookup(sudoUser)
	if e != nil {
		return "", -1, -1, fmt.Errorf("lookup sudo user %q: %w", sudoUser, e)
	}
	uidN, e := strconv.Atoi(u.Uid)
	if e != nil {
		return "", -1, -1, fmt.Errorf("parse uid %q: %w", u.Uid, e)
	}
	gidN, e := strconv.Atoi(u.Gid)
	if e != nil {
		return "", -1, -1, fmt.Errorf("parse gid %q: %w", u.Gid, e)
	}
	return u.HomeDir, uidN, gidN, nil
}

// ensureNSSDB ensures nssDir exists and contains an initialised NSS
// database. If uid/gid are >= 0, newly created `.pki` and `.pki/nssdb`
// directories are chown'd to that user — required when this code runs
// under sudo so that subsequent in-user invocations do not hit
// permission denials.
func ensureNSSDB(certutilPath, nssDir string, uid, gid int) error {
	pkiDir := filepath.Dir(nssDir)

	pkiCreated, err := mkdirIfMissing(pkiDir)
	if err != nil {
		return err
	}
	dbExists, err := nssDirExists(nssDir)
	if err != nil {
		return err
	}
	nssCreated := false
	if !dbExists {
		if err := os.MkdirAll(nssDir, 0700); err != nil {
			return fmt.Errorf("create %s: %w", nssDir, err)
		}
		nssCreated = true
	}

	if uid >= 0 && gid >= 0 {
		if err := chownIfCreated(pkiDir, pkiCreated, uid, gid); err != nil {
			return err
		}
		if err := chownIfCreated(nssDir, nssCreated, uid, gid); err != nil {
			return err
		}
	}

	if dbExists {
		return nil
	}
	return initNSSDB(certutilPath, nssDir, uid, gid)
}

// mkdirIfMissing creates dir (and parents) with mode 0700 when absent,
// returning whether it actually created the directory. Pre-existing
// directories are left untouched.
func mkdirIfMissing(dir string) (created bool, err error) {
	if _, statErr := os.Stat(dir); statErr == nil {
		return false, nil
	} else if !os.IsNotExist(statErr) {
		return false, fmt.Errorf("stat %s: %w", dir, statErr)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return false, fmt.Errorf("create %s: %w", dir, err)
	}
	return true, nil
}

// nssDirExists reports whether nssDir already exists on disk.
func nssDirExists(nssDir string) (bool, error) {
	if _, err := os.Stat(nssDir); err == nil {
		return true, nil
	} else if os.IsNotExist(err) {
		return false, nil
	} else {
		return false, fmt.Errorf("stat %s: %w", nssDir, err)
	}
}

// chownIfCreated chowns path to uid/gid only when created is true,
// preventing accidental ownership changes on pre-existing user data.
func chownIfCreated(path string, created bool, uid, gid int) error {
	if !created {
		return nil
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	return nil
}

// initNSSDB invokes `certutil -N --empty-password` to bootstrap the
// shared SQL NSS database under nssDir, then chowns the newly created
// db files to uid/gid when running under sudo (uid/gid >= 0).
func initNSSDB(certutilPath, nssDir string, uid, gid int) error {
	if out, err := runCertutil(certutilPath, "-N", "-d", "sql:"+nssDir, "--empty-password"); err != nil {
		return fmt.Errorf("certutil -N (init NSSDB): %w: %s", err, out)
	}
	if uid < 0 || gid < 0 {
		return nil
	}
	entries, err := os.ReadDir(nssDir)
	if err != nil {
		return fmt.Errorf("read nssdb after init: %w", err)
	}
	for _, e := range entries {
		p := filepath.Join(nssDir, e.Name())
		if err := os.Chown(p, uid, gid); err != nil {
			return fmt.Errorf("chown %s: %w", p, err)
		}
	}
	return nil
}

// runCertutil invokes certutil with the supplied arguments via the
// swappable execCommand var, returning the combined stdout/stderr
// output along with any error. certutil is silent on success, so
// streaming is unhelpful; CombinedOutput keeps the diagnostic body
// available for inclusion in wrapped errors.
func runCertutil(certutilPath string, args ...string) ([]byte, error) {
	slog.Debug("running certutil", "path", certutilPath, "args", args)
	cmd := execCommand(certutilPath, args...)
	return cmd.CombinedOutput()
}
