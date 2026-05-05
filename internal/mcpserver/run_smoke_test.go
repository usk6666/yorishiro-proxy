package mcpserver

import (
	"context"
	"flag"
	"strings"
	"testing"
)

// TestRun_RejectsInvalidLogLevel verifies that Run surfaces config
// validation errors instead of silently proceeding when the CLI input is
// malformed. This is the smoke test for USK-723: it does not exercise
// full server boot (USK-724 will), but it proves the relocated entry
// point parses flags and reaches cfg.Validate without crashing.
func TestRun_RejectsInvalidLogLevel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fs := flag.NewFlagSet("smoke", flag.ContinueOnError)
	// Suppress the FlagSet's stderr output during failure paths so the
	// test log stays clean.
	fs.SetOutput(discardWriter{})

	args := []string{
		"-log-level", "INVALID_LEVEL",
		"-db", t.TempDir() + "/smoke.db",
		"-ca-ephemeral",
		"-no-http-mcp", // exercise an alternate transport flag without binding a port
	}

	err := Run(ctx, fs, args, RunOptions{Version: "smoke"})
	if err == nil {
		t.Fatal("Run with invalid -log-level: expected error, got nil")
	}
	// The error must surface from configuration validation, not from a
	// listener crash deeper in the pipeline. The exact wrapping is
	// "invalid configuration: ..." per cfg.Validate's contract.
	if !strings.Contains(err.Error(), "invalid configuration") {
		t.Errorf("Run error = %q, want substring %q", err.Error(), "invalid configuration")
	}
}

// TestRun_RejectsConflictingTLSFingerprint verifies that the
// -tls-fingerprint guard reports invalid profile names through Run's
// error return, preserving the production behavior of cmd/yorishiro-proxy.
func TestRun_RejectsConflictingTLSFingerprint(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fs := flag.NewFlagSet("smoke-tls", flag.ContinueOnError)
	fs.SetOutput(discardWriter{})

	args := []string{
		"-tls-fingerprint", "not-a-real-browser",
		"-db", t.TempDir() + "/smoke-tls.db",
		"-ca-ephemeral",
		"-no-http-mcp",
	}

	err := Run(ctx, fs, args, RunOptions{Version: "smoke"})
	if err == nil {
		t.Fatal("Run with invalid -tls-fingerprint: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "invalid -tls-fingerprint") {
		t.Errorf("Run error = %q, want substring %q", err.Error(), "invalid -tls-fingerprint")
	}
}

// TestRun_RejectsAllTransportsDisabled verifies that disabling both HTTP
// and stdio transports surfaces an error rather than starting a server
// nobody can reach.
func TestRun_RejectsAllTransportsDisabled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fs := flag.NewFlagSet("smoke-no-transport", flag.ContinueOnError)
	fs.SetOutput(discardWriter{})

	args := []string{
		"-db", t.TempDir() + "/smoke-no-transport.db",
		"-ca-ephemeral",
		"-no-http-mcp", // disables HTTP MCP
		// stdio MCP not enabled
	}

	err := Run(ctx, fs, args, RunOptions{Version: "smoke"})
	if err == nil {
		t.Fatal("Run with all transports disabled: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "no MCP transport enabled") {
		t.Errorf("Run error = %q, want substring %q", err.Error(), "no MCP transport enabled")
	}
}

// discardWriter satisfies io.Writer with a no-op so the FlagSet's parse
// errors do not leak into test output.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
