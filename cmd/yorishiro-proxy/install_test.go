package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/setup"
)

func TestRunInstall_AllTargets(t *testing.T) {
	dir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			t.Logf("chdir back: %v", err)
		}
	}()

	// Run install with no target (all) — non-interactive by default.
	err = runInstall(context.Background(), nil)
	if err != nil {
		t.Fatalf("runInstall() error: %v", err)
	}

	// Check that .mcp.json was created.
	configPath := filepath.Join(dir, ".mcp.json")
	if _, err := os.Stat(configPath); err != nil {
		t.Errorf(".mcp.json not created: %v", err)
	}
}

func TestRunInstall_MCPTarget(t *testing.T) {
	dir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			t.Logf("chdir back: %v", err)
		}
	}()

	err = runInstall(context.Background(), []string{"mcp"})
	if err != nil {
		t.Fatalf("runInstall(mcp) error: %v", err)
	}

	configPath := filepath.Join(dir, ".mcp.json")
	if _, err := os.Stat(configPath); err != nil {
		t.Errorf(".mcp.json not created: %v", err)
	}
}

func TestRunInstall_CATarget(t *testing.T) {
	dir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			t.Logf("chdir back: %v", err)
		}
	}()

	// Use --dir to avoid polluting the default CA directory.
	caDir := filepath.Join(dir, "test-ca")
	err = runInstall(context.Background(), []string{"ca", "--dir", caDir})
	if err != nil {
		t.Fatalf("runInstall(ca) error: %v", err)
	}

	// Check that CA files were created.
	certPath := filepath.Join(caDir, "ca.crt")
	if _, err := os.Stat(certPath); err != nil {
		t.Errorf("ca.crt not created: %v", err)
	}
	keyPath := filepath.Join(caDir, "ca.key")
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("ca.key not created: %v", err)
	}
}

func TestRunInstall_SkillsTarget(t *testing.T) {
	dir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			t.Logf("chdir back: %v", err)
		}
	}()

	err = runInstall(context.Background(), []string{"skills"})
	if err != nil {
		t.Fatalf("runInstall(skills) error: %v", err)
	}

	// Check that skills directory was created.
	skillsDir := filepath.Join(dir, ".claude", "skills", "yorishiro")
	if _, err := os.Stat(skillsDir); err != nil {
		t.Errorf("skills directory not created: %v", err)
	}
}

func TestRunInstall_InvalidTarget(t *testing.T) {
	err := runInstall(context.Background(), []string{"invalid"})
	if err == nil {
		t.Fatal("expected error for invalid target")
	}
	if !strings.Contains(err.Error(), "unknown install target") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunInstall_HelpFlag(t *testing.T) {
	err := runInstall(context.Background(), []string{"-h"})
	if err == nil {
		t.Fatal("expected error from -h flag (flag.ErrHelp)")
	}
}

func TestRunInstall_TrustFlagOnWrongTarget(t *testing.T) {
	err := runInstall(context.Background(), []string{"mcp", "--trust"})
	if err == nil {
		t.Fatal("expected error for --trust on mcp target")
	}
	if !strings.Contains(err.Error(), "--trust is only valid") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunInstall_UserScopeFlag(t *testing.T) {
	dir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() {
		if err := os.Chdir(origDir); err != nil {
			t.Logf("chdir back: %v", err)
		}
	}()

	// --user-scope should write to user scope (which would be ~/.claude/settings.json).
	// Just verify the flag is accepted without error.
	err = runInstall(context.Background(), []string{"mcp", "--user-scope"})
	if err != nil {
		t.Fatalf("runInstall(mcp --user-scope) error: %v", err)
	}
}

func TestParseInstallTarget(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		want     setup.Target
		wantArgs []string
		wantErr  bool
	}{
		{
			name:     "no args",
			args:     nil,
			want:     setup.TargetAll,
			wantArgs: nil,
		},
		{
			name:     "empty args",
			args:     []string{},
			want:     setup.TargetAll,
			wantArgs: []string{},
		},
		{
			name:     "mcp target",
			args:     []string{"mcp"},
			want:     setup.TargetMCP,
			wantArgs: []string{},
		},
		{
			name:     "ca target with flags",
			args:     []string{"ca", "--trust"},
			want:     setup.TargetCA,
			wantArgs: []string{"--trust"},
		},
		{
			name:     "flag first (no target)",
			args:     []string{"--interactive"},
			want:     setup.TargetAll,
			wantArgs: []string{"--interactive"},
		},
		{
			name:    "invalid target",
			args:    []string{"unknown"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotArgs, err := parseInstallTarget(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseInstallTarget() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got != tt.want {
					t.Errorf("parseInstallTarget() target = %v, want %v", got, tt.want)
				}
				if len(gotArgs) != len(tt.wantArgs) {
					t.Errorf("parseInstallTarget() args = %v, want %v", gotArgs, tt.wantArgs)
				}
			}
		})
	}
}
