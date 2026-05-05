package connector

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// drainAndCapture reads all bytes from r until EOF or 1 second of inactivity.
// Used by tests to capture proxy error responses without hanging.
func drainAndCapture(t *testing.T, r net.Conn) []byte {
	t.Helper()
	r.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 512)
	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	return buf
}

func TestPeekForwardTarget_AbsoluteForm(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	go func() {
		clientA.Write([]byte("GET http://example.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	}()

	pc := NewPeekConn(clientB)
	target, err := peekForwardTarget(pc)
	if err != nil {
		t.Fatalf("peekForwardTarget: %v", err)
	}
	if target != "example.com:80" {
		t.Errorf("target = %q, want %q", target, "example.com:80")
	}
}

func TestPeekForwardTarget_AbsoluteFormWithPort(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	go func() {
		clientA.Write([]byte("GET http://example.com:8080/path HTTP/1.1\r\nHost: example.com:8080\r\n\r\n"))
	}()

	pc := NewPeekConn(clientB)
	target, err := peekForwardTarget(pc)
	if err != nil {
		t.Fatalf("peekForwardTarget: %v", err)
	}
	if target != "example.com:8080" {
		t.Errorf("target = %q, want %q", target, "example.com:8080")
	}
}

func TestPeekForwardTarget_OriginFormHostHeader(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	go func() {
		clientA.Write([]byte("GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	}()

	pc := NewPeekConn(clientB)
	target, err := peekForwardTarget(pc)
	if err != nil {
		t.Fatalf("peekForwardTarget: %v", err)
	}
	if target != "example.com:80" {
		t.Errorf("target = %q, want %q", target, "example.com:80")
	}
}

func TestPeekForwardTarget_OriginFormHostHeaderCaseInsensitive(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	go func() {
		clientA.Write([]byte("GET /path HTTP/1.1\r\nhOsT: example.com:9000\r\n\r\n"))
	}()

	pc := NewPeekConn(clientB)
	target, err := peekForwardTarget(pc)
	if err != nil {
		t.Fatalf("peekForwardTarget: %v", err)
	}
	if target != "example.com:9000" {
		t.Errorf("target = %q, want %q", target, "example.com:9000")
	}
}

func TestPeekForwardTarget_PreservesBufferedBytes(t *testing.T) {
	// Verify Peek does not consume bytes — subsequent Read returns the
	// same bytes the http1 Layer would re-parse.
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	wire := "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n"
	go func() { clientA.Write([]byte(wire)) }()

	pc := NewPeekConn(clientB)
	if _, err := peekForwardTarget(pc); err != nil {
		t.Fatalf("peekForwardTarget: %v", err)
	}

	// Read what's buffered. Bytes peeked must still be readable.
	tmp := make([]byte, len(wire))
	n, err := io.ReadFull(pc, tmp)
	if err != nil {
		t.Fatalf("ReadFull after peek: %v", err)
	}
	if got := string(tmp[:n]); got != wire {
		t.Errorf("read after peek = %q, want %q", got, wire)
	}
}

func TestPeekForwardTarget_RejectsCONNECT(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	go func() {
		clientA.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
	}()

	pc := NewPeekConn(clientB)
	if _, err := peekForwardTarget(pc); err == nil {
		t.Error("expected error for CONNECT method, got nil")
	}
}

func TestPeekForwardTarget_MissingHostHeader(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	go func() {
		clientA.Write([]byte("GET /path HTTP/1.1\r\nUser-Agent: x\r\n\r\n"))
	}()

	pc := NewPeekConn(clientB)
	if _, err := peekForwardTarget(pc); err == nil {
		t.Error("expected error for missing Host header, got nil")
	}
}

// TestPeekUntilHeadersEnd_DeadlineExceeded covers the Slowloris path: the
// client sends a partial request prefix without "\r\n\r\n", the handler's
// read deadline fires before any more bytes arrive, and the function must
// return an error that wraps os.ErrDeadlineExceeded so callers can produce
// accurate diagnostics instead of a misleading "malformed request line".
//
// This is the security-relevant codepath that pre-USK-710 silently mapped
// to a structural-parse error (F-2 in the review).
func TestPeekUntilHeadersEnd_DeadlineExceeded(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	// Write a partial request prefix and stop. Do NOT close the writer —
	// we want the read side to block on more bytes, then trip the deadline.
	go func() {
		_, _ = clientA.Write([]byte("GET / HT"))
	}()

	pc := NewPeekConn(clientB)
	if err := pc.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	buf, err := peekUntilHeadersEnd(pc, peekHeaderSize)
	if err == nil {
		t.Fatalf("expected error on deadline expiry, got buf=%q nil", buf)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("error should wrap os.ErrDeadlineExceeded for diagnostics; got %v", err)
	}
	// Partial bytes should still be returned alongside the error so callers
	// retain visibility into what actually arrived on the wire.
	if !bytes.Equal(buf, []byte("GET / HT")) {
		t.Errorf("partial buf = %q, want %q", buf, "GET / HT")
	}
}

func TestEnsurePort(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"example.com", "example.com:80"},
		{"example.com:8080", "example.com:8080"},
		{"127.0.0.1", "127.0.0.1:80"},
		{"127.0.0.1:443", "127.0.0.1:443"},
		// IPv6 without port. JoinHostPort wraps in brackets.
		{"::1", "[::1]:80"},
	}
	for _, c := range cases {
		got := ensurePort(c.in, "80")
		if got != c.want {
			t.Errorf("ensurePort(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNewHTTP1ForwardHandler_ScopeDenial(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules(nil, []TargetRule{
		{Hostname: "blocked.example.com"},
	})

	var stackCalled atomic.Bool
	handler := NewHTTP1ForwardHandler(HTTP1ForwardHandlerConfig{
		Scope: scope,
		OnStack: func(ctx context.Context, stack *ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
			stackCalled.Store(true)
		},
	})

	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		clientA.Write([]byte("GET http://blocked.example.com/path HTTP/1.1\r\nHost: blocked.example.com\r\n\r\n"))
		// Read the proxy's 403 response.
		buf := drainAndCapture(t, clientA)
		if !bytes.Contains(buf, []byte("403")) {
			t.Errorf("expected 403 response, got %q", buf)
		}
		if !bytes.Contains(buf, []byte("Server: yorishiro-proxy")) {
			t.Errorf("expected Server: yorishiro-proxy in response, got %q", buf)
		}
	}()

	pc := NewPeekConn(clientB)
	ctx := ContextWithConnID(context.Background(), "test-conn")
	if err := handler(ctx, pc); err != nil {
		t.Errorf("handler returned error: %v", err)
	}
	clientB.Close()
	wg.Wait()

	if stackCalled.Load() {
		t.Error("OnStack should not be called when scope denies the target")
	}
}

func TestNewHTTP1ForwardHandler_CONNECTRejected(t *testing.T) {
	var stackCalled atomic.Bool
	handler := NewHTTP1ForwardHandler(HTTP1ForwardHandlerConfig{
		OnStack: func(ctx context.Context, stack *ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
			stackCalled.Store(true)
		},
	})

	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		clientA.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
		buf := drainAndCapture(t, clientA)
		if !bytes.Contains(buf, []byte("400")) {
			t.Errorf("expected 400 for CONNECT-method routed to OnHTTP1, got %q", buf)
		}
	}()

	pc := NewPeekConn(clientB)
	ctx := ContextWithConnID(context.Background(), "test-conn")
	if err := handler(ctx, pc); err != nil {
		t.Errorf("handler returned error: %v", err)
	}
	clientB.Close()
	wg.Wait()

	if stackCalled.Load() {
		t.Error("OnStack should not be called for rejected CONNECT method")
	}
}

func TestNewHTTP1ForwardHandler_DialFailure(t *testing.T) {
	var stackCalled atomic.Bool
	handler := NewHTTP1ForwardHandler(HTTP1ForwardHandlerConfig{
		OnStack: func(ctx context.Context, stack *ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
			stackCalled.Store(true)
		},
	})

	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	// Pick a port that's almost certainly unbound to force dial failure.
	// 127.0.0.1:1 is reserved and refuses connections on most systems.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		clientA.Write([]byte("GET http://127.0.0.1:1/ HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n"))
		buf := drainAndCapture(t, clientA)
		if !bytes.Contains(buf, []byte("502")) {
			t.Errorf("expected 502 on dial failure, got %q", buf)
		}
	}()

	pc := NewPeekConn(clientB)
	ctx := ContextWithConnID(context.Background(), "test-conn")
	// Bound the dial wait so the test doesn't hang on a slow CI runner.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := handler(ctx, pc); err != nil {
		t.Errorf("handler returned error: %v", err)
	}
	clientB.Close()
	wg.Wait()

	if stackCalled.Load() {
		t.Error("OnStack should not be called when upstream dial fails")
	}
}

func TestNewHTTP1ForwardHandler_RateLimitDenial(t *testing.T) {
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{
		MaxRequestsPerSecond: 0.001,
	})
	rl.Check("rl.example.com")
	rl.Check("rl.example.com")
	rl.Check("rl.example.com")

	var stackCalled atomic.Bool
	handler := NewHTTP1ForwardHandler(HTTP1ForwardHandlerConfig{
		RateLimiter: rl,
		OnStack: func(ctx context.Context, stack *ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
			stackCalled.Store(true)
		},
	})

	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		clientA.Write([]byte("GET http://rl.example.com/ HTTP/1.1\r\nHost: rl.example.com\r\n\r\n"))
		buf := drainAndCapture(t, clientA)
		if !bytes.Contains(buf, []byte("429")) {
			t.Errorf("expected 429 on rate limit denial, got %q", buf)
		}
	}()

	pc := NewPeekConn(clientB)
	ctx := ContextWithConnID(context.Background(), "test-conn")
	if err := handler(ctx, pc); err != nil {
		t.Errorf("handler returned error: %v", err)
	}
	clientB.Close()
	wg.Wait()

	if stackCalled.Load() {
		t.Error("OnStack should not be called when rate limiter denies the target")
	}
}

func TestWriteForwardErrorResponse_Format(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	go func() {
		writeForwardErrorResponse(clientB, 502, "Bad Gateway", "test detail")
		clientB.Close()
	}()

	got, err := io.ReadAll(clientA)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp := string(got)
	if !strings.HasPrefix(resp, "HTTP/1.1 502 Bad Gateway\r\n") {
		t.Errorf("missing status line: %q", resp)
	}
	if !strings.Contains(resp, "Server: yorishiro-proxy\r\n") {
		t.Errorf("missing Server header: %q", resp)
	}
	if !strings.Contains(resp, "Connection: close\r\n") {
		t.Errorf("missing Connection: close: %q", resp)
	}
	if !strings.HasSuffix(resp, "test detail\r\n") {
		t.Errorf("missing body: %q", resp)
	}
}
