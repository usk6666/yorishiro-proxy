package cert

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultCADir(t *testing.T) {
	dir := DefaultCADir()
	if dir == "" {
		t.Fatal("DefaultCADir returned empty string")
	}
	if !strings.HasSuffix(dir, filepath.Join(".katashiro-proxy", "ca")) {
		t.Errorf("DefaultCADir = %q, want suffix %q", dir, filepath.Join(".katashiro-proxy", "ca"))
	}
}

func TestDefaultCACertPath(t *testing.T) {
	p := DefaultCACertPath()
	if !strings.HasSuffix(p, filepath.Join(".katashiro-proxy", "ca", "ca.crt")) {
		t.Errorf("DefaultCACertPath = %q, want suffix ca/ca.crt", p)
	}
}

func TestDefaultCAKeyPath(t *testing.T) {
	p := DefaultCAKeyPath()
	if !strings.HasSuffix(p, filepath.Join(".katashiro-proxy", "ca", "ca.key")) {
		t.Errorf("DefaultCAKeyPath = %q, want suffix ca/ca.key", p)
	}
}

func TestDefaultCADir_UsesHomeDir(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home directory")
	}
	dir := DefaultCADir()
	if !strings.HasPrefix(dir, home) {
		t.Errorf("DefaultCADir = %q, want prefix %q", dir, home)
	}
}
