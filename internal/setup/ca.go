package setup

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
)

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
		b.WriteString("  Linux (Debian/Ubuntu):\n")
		fmt.Fprintf(&b, "    sudo cp %s \\\n", quoted)
		b.WriteString("      /usr/local/share/ca-certificates/yorishiro-proxy.crt\n")
		b.WriteString("    sudo update-ca-certificates\n")
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
