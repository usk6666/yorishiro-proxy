//go:build e2e

package testconnector_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/testutil/testconnector"
)

// TestCONNECTUpstreamUnreachable verifies that a CONNECT to a dead port
// fails cleanly: OnBlock fires with reason="upstream_unreachable" and no
// HTTP/1.x stream is recorded because no TLS MITM handshake succeeded.
func TestCONNECTUpstreamUnreachable(t *testing.T) {
	h := testconnector.Start(t)

	// Pick an unused port by opening and immediately closing a listener.
	unused := unusedPort(t)
	target := fmt.Sprintf("127.0.0.1:%d", unused)

	conn, err := net.DialTimeout("tcp", h.ClientAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)

	br := bufio.NewReader(conn)
	// We expect either a 200 (if the proxy writes it before learning the
	// upstream is dead) or the connection to close. Drain whatever comes
	// back — the assertion is the OnBlock callback.
	// Note: the current TunnelHandler writes CONNECT 200 *before* the
	// upstream dial, so a 200 line is expected, followed by tunnel close.
	_, _ = br.ReadString('\n')

	select {
	case info := <-h.BlockCh:
		if info.Reason != "upstream_unreachable" {
			t.Fatalf("BlockInfo.Reason=%q want upstream_unreachable", info.Reason)
		}
		if info.Protocol != "CONNECT" {
			t.Fatalf("BlockInfo.Protocol=%q want CONNECT", info.Protocol)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for upstream_unreachable BlockInfo")
	}
}

// TestCONNECTScopeBlock verifies CONNECT scope denials fire OnBlock with
// reason=target_scope.
func TestCONNECTScopeBlock(t *testing.T) {
	denies := []connector.TargetRule{{Hostname: "127.0.0.1"}}
	h := testconnector.Start(t, testconnector.WithScopePolicy(nil, denies))

	// CONNECT to the blocked upstream.
	conn, err := net.DialTimeout("tcp", h.ClientAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", h.UpstreamAddr, h.UpstreamAddr)

	// The CONNECT path does not send a special reply on scope block; it
	// just closes the connection after firing OnBlock. Drain whatever the
	// proxy sent (if anything) and confirm the block.
	_, _ = io.ReadAll(conn)

	select {
	case info := <-h.BlockCh:
		if info.Reason != "target_scope" {
			t.Fatalf("BlockInfo.Reason=%q want target_scope", info.Reason)
		}
		if info.Protocol != "CONNECT" {
			t.Fatalf("BlockInfo.Protocol=%q want CONNECT", info.Protocol)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for target_scope BlockInfo")
	}
}

// TestCONNECTRateLimitBlock verifies that exceeding the configured rate
// limit produces an OnBlock with reason=rate_limit. golang.org/x/time/rate
// uses burst=int(rate)+1, so with rate=0.5 the burst is 1 and the second
// CONNECT within the second will be denied.
func TestCONNECTRateLimitBlock(t *testing.T) {
	h := testconnector.Start(t, testconnector.WithRateLimit(connector.RateLimitConfig{
		MaxRequestsPerSecond: 0.5,
	}))

	// Fire two CONNECTs concurrently so both hit the rate check without
	// the 3-second slow TLS handshake draining the bucket in between.
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", h.ClientAddr, 3*time.Second)
			if err != nil {
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(1 * time.Second))
			fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", h.UpstreamAddr, h.UpstreamAddr)
			_, _ = io.ReadAll(c)
		}()
	}
	wg.Wait()

	deadline := time.After(3 * time.Second)
	for {
		select {
		case info := <-h.BlockCh:
			if info.Reason == "rate_limit" {
				if info.Protocol != "CONNECT" {
					t.Fatalf("rate_limit block on protocol=%q want CONNECT", info.Protocol)
				}
				return
			}
		case <-deadline:
			t.Fatal("timed out waiting for rate_limit BlockInfo")
		}
	}
}

// TestCONNECTMalformedTargetClosesCleanly verifies that a CONNECT with a
// malformed host:port is rejected at the negotiator level without a crash.
// OnBlock is not fired here because the listener dispatcher handles the
// error (not TunnelHandler).
func TestCONNECTMalformedTargetClosesCleanly(t *testing.T) {
	h := testconnector.Start(t)

	conn, err := net.DialTimeout("tcp", h.ClientAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// An obviously-invalid CONNECT target.
	fmt.Fprint(conn, "CONNECT not-a-valid-host HTTP/1.1\r\nHost: not-a-valid-host\r\n\r\n")

	buf, _ := io.ReadAll(conn)
	_ = buf
	// Sanity: no HTTP/1.x stream should ever appear after a malformed CONNECT.
	// Poll for a bounded window so we both (a) give the server time to react
	// and (b) fail fast if a stream is unexpectedly recorded.
	ctx := context.Background()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		streams, _ := h.Store.ListStreams(ctx, flow.StreamListOptions{})
		for _, st := range streams {
			if st.Protocol == "HTTP/1.x" {
				t.Fatalf("unexpected HTTP/1.x stream after malformed CONNECT: %+v", st)
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// TestTLSHandshakeFailureClient verifies that a client that completes
// CONNECT but then sends garbage instead of a TLS ClientHello causes the
// tunnel to shut down cleanly. The assertion is that io.ReadAll returns
// within the read deadline via a clean close (EOF / reset), not via a
// deadline-exceeded timeout — i.e. the proxy actively tore the tunnel down.
func TestTLSHandshakeFailureClient(t *testing.T) {
	h := testconnector.Start(t)

	conn, err := net.DialTimeout("tcp", h.ClientAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	// Bound the total read wait so a hung tunnel produces a deadline error
	// (which we explicitly reject below) rather than stalling forever.
	conn.SetDeadline(time.Now().Add(12 * time.Second))

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", h.UpstreamAddr, h.UpstreamAddr)
	br := bufio.NewReader(conn)
	// Drain CONNECT 200 + headers.
	_, _ = br.ReadString('\n')
	for {
		l, _ := br.ReadString('\n')
		if l == "\r\n" || l == "\n" || l == "" {
			break
		}
	}

	// Send non-TLS garbage.
	if _, err := conn.Write([]byte("not-a-tls-hello-just-random-bytes")); err != nil {
		t.Fatalf("write garbage: %v", err)
	}

	// The proxy should actively close the tunnel after the TLS handshake
	// fails. io.ReadAll must return via a clean close — either io.EOF or
	// "use of closed network connection" / "connection reset" — and NOT
	// via a read deadline. A deadline-exceeded error here means the proxy
	// left the tunnel open, which is the failure mode we care about.
	start := time.Now()
	_, err = io.ReadAll(conn)
	elapsed := time.Since(start)
	if err != nil && !isClosedNetErr(err) {
		t.Fatalf("read after garbage returned unexpected error: %v (elapsed=%v)", err, elapsed)
	}
	if elapsed >= 12*time.Second {
		t.Fatalf("proxy did not close tunnel after failed TLS handshake (elapsed=%v)", elapsed)
	}
}

// --- helpers ---------------------------------------------------------------

func unusedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for unused port: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	ln.Close()
	return addr.Port
}

func isClosedNetErr(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	return strings.Contains(err.Error(), "use of closed network connection") ||
		strings.Contains(err.Error(), "connection reset")
}
