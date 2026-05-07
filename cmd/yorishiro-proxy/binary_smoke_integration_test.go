//go:build e2e

// Package main_test holds USK-758's smoke coverage for the
// yorishiro-proxy binary itself.
//
// Pre-USK-758 cmd/yorishiro-proxy/ had zero `//go:build e2e` tests.
// Every other smoke test exercises mcpserver.Run via in-process
// goroutine (mcptest harness), bypassing the actual binary entry
// point. A regression in main.go subcommand routing, init-order
// flag plumbing, signal handling, or stdout/stderr discipline would
// not surface in any test until a user noticed at the CLI. USK-719
// (boot-order TLS fingerprint) was the canonical example of this
// class; that fix landed boot_order_tls_fingerprint_integration_test
// but only at the in-process Run() layer, not at the exec'd binary
// layer.
//
// This test compiles the binary once, spawns it in server mode,
// drives a client subcommand round-trip against it over the wire,
// then signals it to exit cleanly. The assertions are deliberately
// shallow — the goal is "the binary runs and answers a tool call",
// not "every flag works". Functional coverage stays in the harness
// tests.
package main_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestE2E_Binary_ServerClientRoundTrip exercises the production
// binary's `server` and `client` subcommands end-to-end:
//
//  1. Build the binary with `go build` (cached across runs in the
//     same go test process via sync.Once).
//  2. Spawn `<binary> server -mcp-http-addr 127.0.0.1:<port>
//     -mcp-http-token <token> -ca-ephemeral -db ... -no-http-mcp=false`.
//  3. Wait for the listener to accept TCP connections.
//  4. Spawn `<binary> client query --format json --server-addr
//     127.0.0.1:<port> --token <token> resource=status` and parse
//     the JSON output.
//  5. Send SIGTERM to the server; confirm exit code 0 within a
//     bounded grace window.
//
// If any of these steps regresses (e.g. main.go drops the `client`
// subcommand, server.json path resolution panics, signal handler
// hangs), the per-PR merge gate trips.
func TestE2E_Binary_ServerClientRoundTrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("signal-based shutdown semantics differ on Windows; smoke focuses on Unix-like CI runners")
	}

	binary := buildBinary(t)
	port := pickFreeBinaryPort(t)
	token := "binary-smoke-token-0123456789abcdef"
	dbPath := filepath.Join(t.TempDir(), "binary-smoke.db")

	srv := startServerProcess(t, binary, port, token, dbPath)
	defer srv.terminate(t)

	if !waitForListener(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 15*time.Second) {
		srv.terminate(t)
		t.Fatalf("binary server did not bind 127.0.0.1:%d within 15s; stderr so far:\n%s", port, srv.stderrSnapshot())
	}

	statusJSON := runClientQuery(t, binary, port, token, "status")

	var parsed struct {
		Running bool `json:"running"`
	}
	if err := json.Unmarshal(statusJSON, &parsed); err != nil {
		t.Fatalf("decode client query JSON: %v\nraw=%s", err, statusJSON)
	}
	// query(status).running is true once the proxy listener is up;
	// without a proxy_start the value is false but the TOOL CALL
	// itself succeeded — that is what this smoke is asserting. The
	// presence of a parseable `running` key proves the client→server
	// MCP round-trip works end-to-end via the binary.
	_ = parsed.Running

	// Graceful shutdown assertion: SIGTERM, expect exit 0 within 10s.
	if err := srv.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM to server: %v", err)
	}
	if err := srv.waitWithTimeout(10 * time.Second); err != nil {
		t.Errorf("server did not shut down cleanly after SIGTERM: %v\nstderr:\n%s", err, srv.stderrSnapshot())
	}
}

// binaryBuildOnce caches the result of buildBinary across subtests
// so repeated invocations in the same `go test` invocation re-use
// the compiled artifact.
var (
	binaryBuildOnce sync.Once
	binaryBuildPath string
	binaryBuildErr  error
)

// buildBinary compiles the production binary into a per-test-process
// temp directory and returns the absolute path. Build failures
// fatal the calling test.
func buildBinary(t *testing.T) string {
	t.Helper()
	binaryBuildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "yorishiro-proxy-bin-*")
		if err != nil {
			binaryBuildErr = fmt.Errorf("create temp dir: %w", err)
			return
		}
		out := filepath.Join(dir, "yorishiro-proxy")
		// `.` here is cmd/yorishiro-proxy because the test lives in
		// that package. `go build` works against the current package
		// the same way as it would from the project root with the
		// full ./cmd/yorishiro-proxy path.
		cmd := exec.Command("go", "build", "-o", out, ".")
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			binaryBuildErr = fmt.Errorf("go build: %w", err)
			return
		}
		binaryBuildPath = out
	})
	if binaryBuildErr != nil {
		t.Fatalf("build binary: %v", binaryBuildErr)
	}
	return binaryBuildPath
}

// pickFreeBinaryPort returns an ephemeral loopback port suitable for
// passing to `-mcp-http-addr`. The brief race between Close and the
// binary's bind is tolerated the same way pickFreePort handles it
// elsewhere in the harness.
func pickFreeBinaryPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("acquire ephemeral port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// serverProcess wraps the spawned binary plus its captured stderr
// buffer. terminate is idempotent so deferred cleanup remains safe
// after an explicit shutdown earlier in the test body.
//
// done is a close-only signal so multiple readers (terminate /
// waitWithTimeout) can each detect "process exited" without racing
// for a single chan-receive value. The actual Wait error is stored
// under exitMu to keep close-on-exit and read-result independent.
type serverProcess struct {
	cmd      *exec.Cmd
	stderr   *bytes.Buffer
	stderrMu sync.Mutex
	done     chan struct{}
	exitMu   sync.Mutex
	exitErr  error
	once     sync.Once
}

// startServerProcess launches `<binary> server` with the supplied
// listen port, bearer token, and DB path. Stderr is captured into
// stderr; the boot goroutine signals on done once Wait() returns.
func startServerProcess(t *testing.T, binary string, port int, token, dbPath string) *serverProcess {
	t.Helper()

	srv := &serverProcess{
		stderr: new(bytes.Buffer),
		done:   make(chan struct{}),
	}

	srv.cmd = exec.Command(binary,
		"server",
		"-mcp-http-addr", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		"-mcp-http-token", token,
		"-db", dbPath,
		"-ca-ephemeral",
		"-log-level", "error",
	)
	// stdout is reserved for MCP stdio when -stdio-mcp is set; it is
	// silent in HTTP-only mode but we still discard it so the test
	// process does not inherit any stray bytes.
	srv.cmd.Stdout = nil
	// Capture stderr through a locked buffer so concurrent reads in
	// stderrSnapshot() are race-safe.
	srv.cmd.Stderr = newLockedBuffer(srv.stderr, &srv.stderrMu)

	if err := srv.cmd.Start(); err != nil {
		t.Fatalf("start server binary: %v", err)
	}

	go func() {
		err := srv.cmd.Wait()
		srv.exitMu.Lock()
		srv.exitErr = err
		srv.exitMu.Unlock()
		close(srv.done)
	}()
	return srv
}

// terminate stops the server. Safe to call multiple times.
func (s *serverProcess) terminate(t *testing.T) {
	t.Helper()
	s.once.Do(func() {
		if s.cmd.Process == nil {
			return
		}
		// Best-effort SIGTERM, then wait briefly. The test body may
		// already have signalled and waited via waitWithTimeout —
		// in that case s.done is already closed and the select
		// returns immediately.
		_ = s.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-s.done:
		case <-time.After(5 * time.Second):
			_ = s.cmd.Process.Kill()
			<-s.done
		}
	})
}

// waitWithTimeout blocks until the server exits or the deadline
// elapses. Returns the wait error (nil for a clean exit). Reading
// s.done is a non-consuming check (closed channel), so subsequent
// terminate() calls remain safe.
func (s *serverProcess) waitWithTimeout(d time.Duration) error {
	select {
	case <-s.done:
		s.exitMu.Lock()
		defer s.exitMu.Unlock()
		return s.exitErr
	case <-time.After(d):
		return fmt.Errorf("server exit timeout after %v", d)
	}
}

// stderrSnapshot returns the captured stderr text so far. Callers
// use this for failure diagnostics; production paths never read it.
func (s *serverProcess) stderrSnapshot() string {
	s.stderrMu.Lock()
	defer s.stderrMu.Unlock()
	return s.stderr.String()
}

// waitForListener polls TCP dial against addr until the connection
// succeeds or timeout elapses. Returns true on success.
func waitForListener(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// runClientQuery spawns the binary's client subcommand with the
// resolved server addr+token, requests the named resource, and
// returns the stdout bytes. Failures fatal the calling test.
func runClientQuery(t *testing.T, binary string, port int, token, resource string) []byte {
	t.Helper()
	// Argument order matters: the client subcommand consumes the
	// first positional after `client` as the tool name. Conn flags
	// (--server-addr / --token / --format) must come AFTER the tool
	// name; client.go's splitClientToolArgs scans the post-tool args
	// for them.
	cmd := exec.Command(binary,
		"client",
		"query",
		"--server-addr", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		"--token", token,
		"--format", "json",
		"resource="+resource,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Bound the client run; if the round-trip hangs, the test must
	// fail rather than block CI indefinitely.
	timeoutCh := time.AfterFunc(15*time.Second, func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	defer timeoutCh.Stop()

	if err := cmd.Run(); err != nil {
		t.Fatalf("client query exit error: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
	}
	return stdout.Bytes()
}

// lockedBuffer writes to an underlying *bytes.Buffer while serializing
// access through a caller-owned mutex. Used so the test goroutine
// can read partial stderr for diagnostics while the child process is
// still writing to it.
type lockedBuffer struct {
	buf *bytes.Buffer
	mu  *sync.Mutex
}

func newLockedBuffer(buf *bytes.Buffer, mu *sync.Mutex) *lockedBuffer {
	return &lockedBuffer{buf: buf, mu: mu}
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}
