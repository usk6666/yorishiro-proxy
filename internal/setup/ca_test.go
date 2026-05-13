package setup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
)

func TestCAInstallInstructions(t *testing.T) {
	certPath := "/home/user/.yorishiro-proxy/ca/ca.crt"
	quotedPath := "'" + certPath + "'"

	tests := []struct {
		name     string
		goos     string
		contains []string
	}{
		{
			name: "macOS instructions",
			goos: "darwin",
			contains: []string{
				"macOS",
				"security add-trusted-cert",
				quotedPath,
			},
		},
		{
			name: "Linux instructions",
			goos: "linux",
			contains: []string{
				"Linux",
				"update-ca-certificates",
				quotedPath,
				// USK-857: NSSDB step is part of the manual install path too.
				"~/.pki/nssdb",
				"certutil -d sql:$HOME/.pki/nssdb",
				"libnss3-tools",
			},
		},
		{
			name: "Windows instructions",
			goos: "windows",
			contains: []string{
				"Windows",
				"certutil",
				quotedPath,
			},
		},
		{
			name: "unknown OS instructions",
			goos: "plan9",
			contains: []string{
				"CA certificate path",
				certPath, // default case uses unquoted path for display
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := caInstallInstructionsForOS(certPath, tt.goos)
			for _, s := range tt.contains {
				if !strings.Contains(result, s) {
					t.Errorf("instructions for %s missing %q\ngot: %s", tt.goos, s, result)
				}
			}
		})
	}
}

func TestShellQuote(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple path",
			input: "/home/user/.yorishiro-proxy/ca/ca.crt",
			want:  "'/home/user/.yorishiro-proxy/ca/ca.crt'",
		},
		{
			name:  "path with spaces",
			input: "/home/my user/ca.crt",
			want:  "'/home/my user/ca.crt'",
		},
		{
			name:  "path with single quote",
			input: "/home/user's/ca.crt",
			want:  "'/home/user'\\''s/ca.crt'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shellQuote(tt.input)
			if got != tt.want {
				t.Errorf("shellQuote(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormatFingerprint(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "empty",
			input: []byte{},
			want:  "",
		},
		{
			name:  "single byte",
			input: []byte{0xAB},
			want:  "AB",
		},
		{
			name:  "multiple bytes",
			input: []byte{0xAB, 0xCD, 0xEF, 0x01},
			want:  "AB:CD:EF:01",
		},
		{
			name:  "all zeros",
			input: []byte{0x00, 0x00},
			want:  "00:00",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatFingerprint(tt.input)
			if got != tt.want {
				t.Errorf("formatFingerprint() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEnsureCA_ExistingCA(t *testing.T) {
	// Set up a temporary CA directory to avoid touching the real one.
	dir := t.TempDir()
	caDir := filepath.Join(dir, "ca")
	if err := os.MkdirAll(caDir, 0700); err != nil {
		t.Fatalf("create ca dir: %v", err)
	}

	// Generate and save a test CA.
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	certPath := filepath.Join(caDir, "ca.crt")
	keyPath := filepath.Join(caDir, "ca.key")
	if err := ca.Save(certPath, keyPath); err != nil {
		t.Fatalf("save CA: %v", err)
	}

	// EnsureCA with explicit caDir should load the existing CA.
	info, err := EnsureCA(caDir)
	if err != nil {
		t.Fatalf("EnsureCA() error: %v", err)
	}
	if info.Generated {
		t.Error("expected Generated=false for existing CA")
	}
	if info.CertPath != certPath {
		t.Errorf("CertPath = %q, want %q", info.CertPath, certPath)
	}
	if info.Fingerprint == "" {
		t.Error("expected non-empty fingerprint")
	}
}

func TestEnsureCA_NewCA(t *testing.T) {
	// Use an empty temp directory so EnsureCA generates a new CA.
	dir := t.TempDir()
	caDir := filepath.Join(dir, "ca")

	info, err := EnsureCA(caDir)
	if err != nil {
		t.Fatalf("EnsureCA() error: %v", err)
	}
	if !info.Generated {
		t.Error("expected Generated=true for new CA")
	}
	if info.Fingerprint == "" {
		t.Error("expected non-empty fingerprint")
	}

	// Verify the files were created.
	if _, err := os.Stat(filepath.Join(caDir, "ca.crt")); err != nil {
		t.Errorf("ca.crt not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(caDir, "ca.key")); err != nil {
		t.Errorf("ca.key not created: %v", err)
	}
}

// --- USK-857 NSSDB tests ---
//
// These tests use the canonical Go "TestHelperProcess" pattern to mock
// `exec.Command` without invoking the real certutil binary. The package
// vars `execCommand` and `geteuid` are swapped via t.Cleanup. Because
// they are global state, these tests must NOT call t.Parallel().

// TestHelperProcess is invoked as a subprocess by fakeExecCommand. It
// is not a real test — it inspects environment variables to decide
// what to print to stdout/stderr and which exit code to return,
// emulating an external binary.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	// Print what the parent asked for, then exit with the requested code.
	if out := os.Getenv("HELPER_STDOUT"); out != "" {
		fmt.Fprint(os.Stdout, out)
	}
	if out := os.Getenv("HELPER_STDERR"); out != "" {
		fmt.Fprint(os.Stderr, out)
	}
	code := 0
	if c := os.Getenv("HELPER_EXIT"); c != "" {
		if _, err := fmt.Sscanf(c, "%d", &code); err != nil {
			code = 1
		}
	}
	os.Exit(code)
}

// scriptedCertutil represents the canned response certutil should
// produce for one invocation (subcommand = the first non-flag arg, e.g.
// "-A", "-D", "-N").
type scriptedCertutil struct {
	subcmd string
	stdout string
	stderr string
	exit   int
}

// installScriptedExecCommand replaces execCommand with a fake that
// dispatches to TestHelperProcess. The script slice is consumed in
// order: each invocation pulls the next entry. If subcmd doesn't match
// the first non-flag arg, the test fails — this catches arg-order
// regressions.
func installScriptedExecCommand(t *testing.T, script []scriptedCertutil) *[]string {
	t.Helper()
	orig := execCommand
	t.Cleanup(func() { execCommand = orig })

	calls := make([]string, 0, len(script))
	idx := 0

	execCommand = func(name string, args ...string) *exec.Cmd {
		if idx >= len(script) {
			t.Fatalf("unexpected extra certutil call #%d: %s %v", idx+1, name, args)
		}
		entry := script[idx]
		idx++

		// Find the subcommand (first arg starting with '-' is the action: -A/-D/-N/-L).
		var subcmd string
		for _, a := range args {
			if strings.HasPrefix(a, "-") && len(a) == 2 {
				subcmd = a
				break
			}
		}
		if subcmd != entry.subcmd {
			t.Fatalf("call #%d: subcommand mismatch: got %q args=%v, want %q", idx, subcmd, args, entry.subcmd)
		}
		calls = append(calls, fmt.Sprintf("%s %s", subcmd, strings.Join(args, " ")))

		// Re-exec the test binary in helper mode.
		cs := []string{"-test.run=^TestHelperProcess$", "--"}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{
			"GO_WANT_HELPER_PROCESS=1",
			"HELPER_STDOUT=" + entry.stdout,
			"HELPER_STDERR=" + entry.stderr,
			fmt.Sprintf("HELPER_EXIT=%d", entry.exit),
		}
		return cmd
	}
	return &calls
}

// withFakeHome rewrites HOME to a temp directory and ensures geteuid
// reports a non-root euid so resolveTargetHomeForNSSDBWith picks the
// in-user branch. Returns the temp HOME.
func withFakeHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	// Some platforms also consult these.
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))

	origGeteuid := geteuid
	geteuid = func() int { return 1000 } // any non-zero
	t.Cleanup(func() { geteuid = origGeteuid })
	return dir
}

// withCertutilOnPath stages a fake `certutil` executable in a fresh
// PATH dir so exec.LookPath("certutil") succeeds. The script field
// drives the in-test behaviour via installScriptedExecCommand; the
// stub on disk only needs to exist so LookPath finds it.
func withCertutilOnPath(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	stub := filepath.Join(dir, "certutil")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatalf("write stub certutil: %v", err)
	}
	t.Setenv("PATH", dir)
}

// withoutCertutilOnPath restricts PATH to a directory we control which
// is empty, ensuring exec.LookPath("certutil") fails.
func withoutCertutilOnPath(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("PATH", dir)
}

func TestInstallLinuxNSSDB_HappyPath_FreshDB(t *testing.T) {
	home := withFakeHome(t)
	withCertutilOnPath(t)

	// Fresh DB ⇒ ensureNSSDB will run "-N" first, then we run "-D"
	// (delete may fail since nickname is absent) then "-A".
	calls := installScriptedExecCommand(t, []scriptedCertutil{
		{subcmd: "-N", exit: 0},
		{subcmd: "-D", exit: 255, stderr: "nickname not found"}, // ignored
		{subcmd: "-A", exit: 0},
	})

	if err := installLinuxNSSDB("/some/cert.crt"); err != nil {
		t.Fatalf("installLinuxNSSDB returned error: %v", err)
	}

	if _, err := os.Stat(filepath.Join(home, ".pki", "nssdb")); err != nil {
		t.Errorf("nssdb dir not created: %v", err)
	}
	if len(*calls) != 3 {
		t.Errorf("expected 3 certutil calls, got %d: %v", len(*calls), *calls)
	}
}

func TestInstallLinuxNSSDB_HappyPath_ExistingDB(t *testing.T) {
	home := withFakeHome(t)
	withCertutilOnPath(t)

	// Pre-create the nssdb dir so ensureNSSDB skips "-N".
	nssDir := filepath.Join(home, ".pki", "nssdb")
	if err := os.MkdirAll(nssDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	calls := installScriptedExecCommand(t, []scriptedCertutil{
		{subcmd: "-D", exit: 0}, // existing entry deleted
		{subcmd: "-A", exit: 0},
	})

	if err := installLinuxNSSDB("/some/cert.crt"); err != nil {
		t.Fatalf("installLinuxNSSDB returned error: %v", err)
	}
	if len(*calls) != 2 {
		t.Errorf("expected 2 certutil calls, got %d: %v", len(*calls), *calls)
	}
}

func TestInstallLinuxNSSDB_DeleteFailureIgnored(t *testing.T) {
	home := withFakeHome(t)
	withCertutilOnPath(t)

	nssDir := filepath.Join(home, ".pki", "nssdb")
	if err := os.MkdirAll(nssDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Delete fails (no entry); -A succeeds. Net effect: no error.
	installScriptedExecCommand(t, []scriptedCertutil{
		{subcmd: "-D", exit: 1, stderr: "no certificate matching"},
		{subcmd: "-A", exit: 0},
	})

	if err := installLinuxNSSDB("/some/cert.crt"); err != nil {
		t.Fatalf("installLinuxNSSDB returned error despite -D failure being expected: %v", err)
	}
}

func TestInstallLinuxNSSDB_AddFailure(t *testing.T) {
	home := withFakeHome(t)
	withCertutilOnPath(t)

	nssDir := filepath.Join(home, ".pki", "nssdb")
	if err := os.MkdirAll(nssDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	installScriptedExecCommand(t, []scriptedCertutil{
		{subcmd: "-D", exit: 0},
		{subcmd: "-A", exit: 1, stderr: "certutil: cannot read input file"},
	})

	err := installLinuxNSSDB("/missing/cert.crt")
	if err == nil {
		t.Fatal("expected error from -A failure, got nil")
	}
	if !strings.Contains(err.Error(), "certutil -A") {
		t.Errorf("error missing 'certutil -A' context: %v", err)
	}
	if !strings.Contains(err.Error(), "cannot read input file") {
		t.Errorf("error did not include certutil stderr: %v", err)
	}
}

func TestInstallLinuxNSSDB_CertutilMissing(t *testing.T) {
	withFakeHome(t)
	withoutCertutilOnPath(t)

	err := installLinuxNSSDB("/some/cert.crt")
	if err == nil {
		t.Fatal("expected error when certutil is missing, got nil")
	}
	for _, want := range []string{
		"certutil not found",
		"libnss3-tools",
		"nss-tools",
		"mozilla-nss-tools",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q: %v", want, err)
		}
	}
}

func TestInstallLinuxNSSDB_FreshDB_InitFails(t *testing.T) {
	withFakeHome(t)
	withCertutilOnPath(t)

	// First call (-N) fails. -D / -A must NOT be invoked.
	installScriptedExecCommand(t, []scriptedCertutil{
		{subcmd: "-N", exit: 1, stderr: "certutil: function failed: SEC_ERROR_BAD_DATABASE"},
	})

	err := installLinuxNSSDB("/some/cert.crt")
	if err == nil {
		t.Fatal("expected error from -N failure, got nil")
	}
	if !strings.Contains(err.Error(), "certutil -N") {
		t.Errorf("error missing 'certutil -N' context: %v", err)
	}
}

func TestResolveTargetHomeForNSSDBWith_NonRoot(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	home, uid, gid, err := resolveTargetHomeForNSSDBWith(func() int { return 1000 })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if home != dir {
		t.Errorf("home = %q, want %q", home, dir)
	}
	if uid != -1 || gid != -1 {
		t.Errorf("uid,gid = %d,%d; want -1,-1 for non-root", uid, gid)
	}
}

func TestResolveTargetHomeForNSSDBWith_RootNoSudoUser(t *testing.T) {
	t.Setenv("SUDO_USER", "")

	_, _, _, err := resolveTargetHomeForNSSDBWith(func() int { return 0 })
	if err == nil {
		t.Fatal("expected error for root without SUDO_USER, got nil")
	}
	if !strings.Contains(err.Error(), "SUDO_USER") {
		t.Errorf("error should mention SUDO_USER: %v", err)
	}
	if !strings.Contains(err.Error(), nssNickname) {
		t.Errorf("error should include nickname for manual recovery: %v", err)
	}
}

func TestResolveTargetHomeForNSSDBWith_RootWithUnknownSudoUser(t *testing.T) {
	t.Setenv("SUDO_USER", "this-user-should-not-exist-USK857")

	_, _, _, err := resolveTargetHomeForNSSDBWith(func() int { return 0 })
	if err == nil {
		t.Fatal("expected error for unknown sudo user, got nil")
	}
	if !strings.Contains(err.Error(), "lookup sudo user") {
		t.Errorf("error should mention lookup failure: %v", err)
	}
}

func TestEnsureNSSDB_CreatesDirAndInitsDB(t *testing.T) {
	home := t.TempDir()
	withCertutilOnPath(t) // ensure exec.LookPath path doesn't leak system PATH
	nssDir := filepath.Join(home, ".pki", "nssdb")

	calls := installScriptedExecCommand(t, []scriptedCertutil{
		{subcmd: "-N", exit: 0},
	})

	if err := ensureNSSDB("/fake/certutil", nssDir, -1, -1); err != nil {
		t.Fatalf("ensureNSSDB: %v", err)
	}
	if _, err := os.Stat(nssDir); err != nil {
		t.Errorf("nssdb dir missing: %v", err)
	}
	if len(*calls) != 1 {
		t.Errorf("expected 1 certutil call, got %d", len(*calls))
	}
}

func TestEnsureNSSDB_ExistingDirSkipsInit(t *testing.T) {
	home := t.TempDir()
	nssDir := filepath.Join(home, ".pki", "nssdb")
	if err := os.MkdirAll(nssDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	calls := installScriptedExecCommand(t, []scriptedCertutil{
		// Empty: no calls expected.
	})
	if err := ensureNSSDB("/fake/certutil", nssDir, -1, -1); err != nil {
		t.Fatalf("ensureNSSDB: %v", err)
	}
	if len(*calls) != 0 {
		t.Errorf("expected 0 certutil calls (DB already exists), got %d: %v", len(*calls), *calls)
	}
}
