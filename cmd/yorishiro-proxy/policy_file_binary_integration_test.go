//go:build e2e

package main_test

import (
	"bytes"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestE2E_Binary_RefusesInvalidTargetPolicyFile is USK-1084 T11: the
// production binary must exit non-zero, naming the offending rule, when
// -target-policy-file carries a Policy-layer rule outside RFC-001 §3.8's
// closed scheme vocabulary. Before the gate the server booted and the deny
// silently matched nothing (matchTargetRule ANDs the schemes condition, and
// no connection ever has scheme "wss").
//
// HTTP MCP is enabled on a free port so an un-gated binary keeps running;
// the bounded wait turns that into an assertion failure instead of a hang.
func TestE2E_Binary_RefusesInvalidTargetPolicyFile(t *testing.T) {
	binary := buildBinary(t)
	dir := t.TempDir()

	policyPath := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyPath, []byte(`{"denies":[{"hostname":"chat.internal","schemes":["wss"]}]}`), 0o644); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	port := pickFreeBinaryPort(t)
	cmd := exec.Command(binary,
		"server",
		"-mcp-http-addr", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		"-mcp-http-token", "policy-smoke-token-0123456789abcdef",
		"-db", filepath.Join(dir, "policy-smoke.db"),
		"-ca-ephemeral",
		"-log-level", "error",
		"-target-policy-file", policyPath,
	)
	cmd.Env = binaryChildEnv(t.TempDir())
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server binary: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() == 0 {
			t.Fatalf("server exit = %v, want a non-zero exit code\nstderr:\n%s", err, stderr.String())
		}
		for _, want := range []string{"load target policy file", "denies[0]", `scheme "wss" is not allowed`} {
			if !strings.Contains(stderr.String(), want) {
				t.Errorf("stderr missing %q\nstderr:\n%s", want, stderr.String())
			}
		}
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("server kept running with an invalid -target-policy-file (no startup gate)\nstderr:\n%s", stderr.String())
	}
}
