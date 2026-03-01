package cert

import (
	"os"
	"path/filepath"
)

// DefaultCADir returns the default directory for persisted CA files: ~/.yorishiro-proxy/ca/.
func DefaultCADir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".yorishiro-proxy", "ca")
	}
	return filepath.Join(home, ".yorishiro-proxy", "ca")
}

// DefaultCACertPath returns the default path for the CA certificate: ~/.yorishiro-proxy/ca/ca.crt.
func DefaultCACertPath() string {
	return filepath.Join(DefaultCADir(), "ca.crt")
}

// DefaultCAKeyPath returns the default path for the CA private key: ~/.yorishiro-proxy/ca/ca.key.
func DefaultCAKeyPath() string {
	return filepath.Join(DefaultCADir(), "ca.key")
}
