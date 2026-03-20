package cert

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultCAPaths(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home directory")
	}

	dir := DefaultCADir()
	if dir == "" {
		t.Fatal("DefaultCADir returned empty string")
	}
	if !strings.HasSuffix(dir, filepath.Join(".yorishiro-proxy", "ca")) {
		t.Errorf("DefaultCADir = %q, want suffix %q", dir, filepath.Join(".yorishiro-proxy", "ca"))
	}
	if !strings.HasPrefix(dir, home) {
		t.Errorf("DefaultCADir = %q, want prefix %q", dir, home)
	}

	certPath := DefaultCACertPath()
	if !strings.HasSuffix(certPath, filepath.Join(".yorishiro-proxy", "ca", "ca.crt")) {
		t.Errorf("DefaultCACertPath = %q, want suffix ca/ca.crt", certPath)
	}

	keyPath := DefaultCAKeyPath()
	if !strings.HasSuffix(keyPath, filepath.Join(".yorishiro-proxy", "ca", "ca.key")) {
		t.Errorf("DefaultCAKeyPath = %q, want suffix ca/ca.key", keyPath)
	}
}
