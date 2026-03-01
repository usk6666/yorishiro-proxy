package setup

import (
	"crypto/sha256"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/usk6666/katashiro-proxy/internal/cert"
)

// CAInfo holds information about the CA certificate for display.
type CAInfo struct {
	CertPath    string
	Fingerprint string
	Generated   bool // true if the CA was newly generated during setup
}

// EnsureCA ensures a CA certificate exists at the default path.
// If the CA already exists, it loads it. Otherwise, it generates a new one.
// Returns CAInfo with the certificate path and fingerprint.
func EnsureCA() (*CAInfo, error) {
	caDir := cert.DefaultCADir()
	certPath := cert.DefaultCACertPath()
	keyPath := cert.DefaultCAKeyPath()

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

	b.WriteString("Install the CA certificate in your OS trust store:\n\n")

	switch goos {
	case "darwin":
		b.WriteString("  macOS:\n")
		fmt.Fprintf(&b, "    sudo security add-trusted-cert -d -r trustRoot \\\n")
		fmt.Fprintf(&b, "      -k /Library/Keychains/System.keychain \\\n")
		fmt.Fprintf(&b, "      %s\n", certPath)
	case "linux":
		b.WriteString("  Linux (Debian/Ubuntu):\n")
		fmt.Fprintf(&b, "    sudo cp %s \\\n", certPath)
		b.WriteString("      /usr/local/share/ca-certificates/katashiro-proxy.crt\n")
		b.WriteString("    sudo update-ca-certificates\n")
	case "windows":
		b.WriteString("  Windows (run as Administrator):\n")
		fmt.Fprintf(&b, "    certutil -addstore \"Root\" %s\n", certPath)
	default:
		b.WriteString("  Copy the CA certificate to your OS trust store.\n")
		fmt.Fprintf(&b, "  CA certificate path: %s\n", certPath)
	}

	return b.String()
}

// formatFingerprint formats a byte slice as a colon-separated uppercase hex string.
func formatFingerprint(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}
