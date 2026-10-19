//go:build e2e

// USK-1115: Policy Layer reload on SIGHUP, exercised against the production
// binary — the only layer where main.go's signal wiring runs.
package main_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// writeBinaryPolicy replaces the policy file atomically (temp + rename).
func writeBinaryPolicy(t *testing.T, path, content string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("rename policy: %v", err)
	}
}

// runClientTool runs `<binary> client <tool> <params...>` against the
// server and returns stdout. Failures fatal the calling test.
func runClientTool(t *testing.T, binary string, port int, token, tool string, params ...string) []byte {
	t.Helper()
	args := append([]string{
		"client", tool,
		"--server-addr", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		"--token", token,
		"--format", "json",
	}, params...)
	cmd := exec.Command(binary, args...)
	cmd.Env = binaryChildEnv(t.TempDir())
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	timer := time.AfterFunc(15*time.Second, func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	defer timer.Stop()
	if err := cmd.Run(); err != nil {
		t.Fatalf("client %s exit error: %v\nstdout=%s\nstderr=%s", tool, err, stdout.String(), stderr.String())
	}
	return stdout.Bytes()
}

// policyAllowHosts returns the policy allow hostnames from a
// get_target_scope JSON result.
func policyAllowHosts(t *testing.T, raw []byte) []string {
	t.Helper()
	var out struct {
		Policy struct {
			Allows []struct {
				Hostname string `json:"hostname"`
			} `json:"allows"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode get_target_scope: %v\nraw=%s", err, raw)
	}
	var hosts []string
	for _, a := range out.Policy.Allows {
		hosts = append(hosts, a.Hostname)
	}
	return hosts
}

// TestE2E_Binary_SIGHUPReloadsPolicy is T4: with -target-policy-file, a
// real SIGHUP re-reads the file and installs it; the process keeps running
// and logs the reload at Info.
func TestE2E_Binary_SIGHUPReloadsPolicy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SIGHUP is never delivered on Windows; the reload trigger is unix-only")
	}
	binary := buildBinary(t)
	port := pickFreeBinaryPort(t)
	token := "binary-sighup-token-0123456789abcdef"
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	writeBinaryPolicy(t, policyPath, `{"allows":[{"hostname":"before.test"}]}`)

	srv := startServerProcess(t, binary, port, token, filepath.Join(dir, "sighup.db"),
		"-target-policy-file", policyPath, "-log-level", "info")
	defer srv.terminate(t)
	if !waitForListener(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), binaryBootTimeout) {
		t.Fatalf("binary server did not bind within %v; stderr:\n%s", binaryBootTimeout, srv.stderrSnapshot())
	}

	testTarget := func(host string) bool {
		t.Helper()
		raw := runClientTool(t, binary, port, token, "security", "test_target", "params.url=https://"+host+"/")
		var out struct {
			StructuredContent struct {
				Allowed      *bool `json:"allowed"`
				TestedTarget struct {
					Hostname string `json:"hostname"`
				} `json:"tested_target"`
			} `json:"structuredContent"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode test_target: %v\nraw=%s", err, raw)
		}
		sc := out.StructuredContent
		if sc.Allowed == nil || sc.TestedTarget.Hostname != host {
			t.Fatalf("test_target(%s): unexpected result %s", host, raw)
		}
		return *sc.Allowed
	}
	if !testTarget("before.test") || testTarget("after.test") {
		t.Fatal("boot policy: want before.test allowed and after.test blocked")
	}

	writeBinaryPolicy(t, policyPath, `{"allows":[{"hostname":"after.test"}]}`)
	if err := srv.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	reloaded := false
	for !reloaded && time.Now().Before(deadline) {
		// Give an unhandled SIGHUP time to kill the process, so that
		// failure is reported as such rather than as a client error.
		select {
		case <-srv.done:
			t.Fatalf("server exited after SIGHUP (%v); stderr:\n%s", srv.waitWithTimeout(time.Second), srv.stderrSnapshot())
		case <-time.After(200 * time.Millisecond):
		}
		reloaded = testTarget("after.test")
	}
	if !reloaded {
		t.Fatalf("after.test still blocked 10s after SIGHUP; stderr:\n%s", srv.stderrSnapshot())
	}
	if testTarget("before.test") {
		t.Error("before.test still allowed after the reloaded policy dropped it")
	}

	stderr := srv.stderrSnapshot()
	if !strings.Contains(stderr, "target scope policy reloaded") || !strings.Contains(stderr, "trigger=SIGHUP") {
		t.Errorf("stderr lacks the Info reload line with trigger=SIGHUP:\n%s", stderr)
	}

	if err := srv.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	if err := srv.waitWithTimeout(10 * time.Second); err != nil {
		t.Errorf("server did not shut down cleanly after SIGTERM: %v\nstderr:\n%s", err, srv.stderrSnapshot())
	}
}

// TestE2E_Binary_SIGHUPWithoutPolicySourceUnchanged is T4b at the binary
// layer (decision U2), a characterization: with no -target-policy-file and
// no -config the handler is not installed, so SIGHUP keeps Go's default and
// terminates the process, exactly as before USK-1115.
func TestE2E_Binary_SIGHUPWithoutPolicySourceUnchanged(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SIGHUP is never delivered on Windows")
	}
	binary := buildBinary(t)
	port := pickFreeBinaryPort(t)
	srv := startServerProcess(t, binary, port, "binary-sighup-nosrc-token-0123456789", filepath.Join(t.TempDir(), "nosrc.db"))
	defer srv.terminate(t)
	if !waitForListener(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), binaryBootTimeout) {
		t.Fatalf("binary server did not bind within %v; stderr:\n%s", binaryBootTimeout, srv.stderrSnapshot())
	}

	if err := srv.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatalf("send SIGHUP: %v", err)
	}
	err := srv.waitWithTimeout(10 * time.Second)
	if err == nil {
		t.Fatal("server exited 0 on SIGHUP, want termination by the signal")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("server still running 10s after SIGHUP without a policy source: %v", err)
	}
	if ws, ok := exitErr.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGHUP {
		t.Errorf("server exit = %v, want killed by SIGHUP", exitErr)
	}
}

// TestE2E_Binary_StdioAgentCannotModifyPolicyLayer is the stdio half of T5
// / acceptance criterion 3: over the stdio MCP transport the agent can
// neither widen nor replace the Policy Layer.
func TestE2E_Binary_StdioAgentCannotModifyPolicyLayer(t *testing.T) {
	binary := buildBinary(t)
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	writeBinaryPolicy(t, policyPath, `{"allows":[{"hostname":"allowed.test"}]}`)

	cmd := exec.Command(binary, "server",
		"-stdio-mcp", "-no-http-mcp",
		"-target-policy-file", policyPath,
		"-db", filepath.Join(dir, "stdio.db"),
		"-ca-ephemeral",
		"-log-level", "error",
	)
	cmd.Env = binaryChildEnv(t.TempDir())
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	client := gomcp.NewClient(&gomcp.Implementation{Name: "usk1115-stdio", Version: "0"}, nil)
	cs, err := client.Connect(ctx, &gomcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect over stdio: %v", err)
	}
	defer cs.Close()

	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	for _, tool := range tools.Tools {
		lower := strings.ToLower(tool.Name)
		if strings.Contains(lower, "policy") || strings.Contains(lower, "reload") || strings.Contains(lower, "admin") {
			t.Errorf("stdio tools/list exposes %q", tool.Name)
		}
	}

	res, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "security",
		Arguments: map[string]any{
			"action": "set_target_scope",
			"params": map[string]any{"allows": []map[string]any{{"hostname": "outside.test"}}},
		},
	})
	if err != nil {
		t.Fatalf("set_target_scope transport error: %v", err)
	}
	if !res.IsError || !strings.Contains(stdioText(res), "outside policy allow boundary") {
		t.Errorf("set_target_scope outside the policy: isError=%v text=%q, want rejection", res.IsError, stdioText(res))
	}

	res, err = cs.CallTool(ctx, &gomcp.CallToolParams{
		Name:      "security",
		Arguments: map[string]any{"action": "get_target_scope", "params": map[string]any{}},
	})
	if err != nil || res.IsError {
		t.Fatalf("get_target_scope: err=%v isError=%v text=%q", err, res != nil && res.IsError, stdioText(res))
	}
	if got := policyAllowHosts(t, []byte(stdioText(res))); len(got) != 1 || got[0] != "allowed.test" {
		t.Errorf("policy allows over stdio = %v, want [allowed.test] unchanged", got)
	}
}

func stdioText(res *gomcp.CallToolResult) string {
	if res == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*gomcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}
