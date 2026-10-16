//go:build e2e && !e2e_smoke

package connector_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// USK-1162: request-head deadline (net/http ReadHeaderTimeout equivalent)
// on the client side of CONNECT negotiation, the client-side TLS MITM
// handshake, and the MITM HTTP/1.x Layer.

const usk1162HeaderTimeout = 300 * time.Millisecond

// usk1162Trickle writes b to w one byte at a time, gap apart, until done is
// closed or a write fails.
func usk1162Trickle(w net.Conn, b []byte, gap time.Duration, done <-chan struct{}) {
	for i := range b {
		select {
		case <-done:
			return
		case <-time.After(gap):
		}
		if _, err := w.Write(b[i : i+1]); err != nil {
			return
		}
	}
}

// usk1162AwaitClose reads conn until the proxy closes it, failing if it is
// still open after guard. Returns everything read.
func usk1162AwaitClose(t *testing.T, conn net.Conn, guard time.Duration) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(guard))
	var got strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		got.Write(buf[:n])
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatalf("connection still open after %v (read so far: %.120q)", guard, got.String())
			}
			return got.String()
		}
	}
}

// usk1162SlowHead is a request head long enough that trickling it at
// 50ms/byte takes far longer than the test guard.
func usk1162SlowHead(requestLine, host string) string {
	return requestLine + "\r\nHost: " + host + "\r\nX-Pad: " + strings.Repeat("p", 200) + "\r\n\r\n"
}

func TestFullListener_CONNECT_SlowlorisRequestClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	proxyAddr, _, _ := startFullListenerProxy(t, ctx, fullListenerOpts{requestHeaderTimeout: usk1162HeaderTimeout})

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// The request line goes out in one write so protocol detection
	// classifies the conn as CONNECT; the header section is trickled.
	if _, err := conn.Write([]byte("CONNECT 127.0.0.1:1 HTTP/1.1\r\n")); err != nil {
		t.Fatalf("write request line: %v", err)
	}
	done := make(chan struct{})
	defer close(done)
	slowHeaders := "Host: 127.0.0.1:1\r\nX-Pad: " + strings.Repeat("p", 200) + "\r\n\r\n"
	go usk1162Trickle(conn, []byte(slowHeaders), 50*time.Millisecond, done)

	got := usk1162AwaitClose(t, conn, 3*time.Second)
	if strings.Contains(got, "200") {
		t.Errorf("proxy answered a trickled CONNECT: %q", got)
	}
}

func TestFullListener_CONNECT_HTTPS_MITM_SlowlorisRequestLineClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var upstreamHits atomic.Int32
	upstreamLn, _ := startUpstreamHTTPS(t, func(_ []byte) []byte {
		upstreamHits.Add(1)
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, _, wg := startFullListenerProxy(t, ctx, fullListenerOpts{requestHeaderTimeout: usk1162HeaderTimeout})

	wg.Add(1)
	tlsConn := connectThroughProxy(t, proxyAddr, target)
	defer tlsConn.Close()

	done := make(chan struct{})
	defer close(done)
	go usk1162Trickle(tlsConn, []byte(usk1162SlowHead("GET /slow HTTP/1.1", target)), 50*time.Millisecond, done)

	got := usk1162AwaitClose(t, tlsConn, 3*time.Second)
	if got != "" {
		t.Errorf("proxy replied to a trickled request: %.120q", got)
	}
	if n := upstreamHits.Load(); n != 0 {
		t.Errorf("upstream received %d requests, want 0", n)
	}
	waitSessionDone(t, wg)
}

// firstWriteOnlyConn forwards the first Write (the TLS ClientHello) and
// silently discards every later one, so the server never sees the client's
// Finished and its handshake stalls.
type firstWriteOnlyConn struct {
	net.Conn
	once    sync.Once
	written atomic.Bool
}

func (c *firstWriteOnlyConn) Write(b []byte) (int, error) {
	if c.written.Load() {
		return len(b), nil
	}
	n, err := c.Conn.Write(b)
	c.once.Do(func() { c.written.Store(true) })
	return n, err
}

func TestFullListener_CONNECT_TLSMITMHandshakeStallClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	upstreamLn, _ := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, _, _ := startFullListenerProxy(t, ctx, fullListenerOpts{requestHeaderTimeout: usk1162HeaderTimeout})

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	buf := make([]byte, 256)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "200") {
		t.Fatalf("CONNECT response = %q, err = %v", buf[:n], err)
	}
	_ = conn.SetReadDeadline(time.Time{})

	// Client half of the handshake runs to completion locally; the proxy
	// never receives our Finished and must give up on its own.
	stalled := &firstWriteOnlyConn{Conn: conn}
	tc := tls.Client(stalled, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS13}) //nolint:gosec // test
	// Handshake (not HandshakeContext) so the test itself never closes
	// conn; the outcome is irrelevant, only the proxy's side matters.
	hsDone := make(chan struct{})
	go func() {
		defer close(hsDone)
		_ = tc.Handshake()
	}()
	select {
	case <-hsDone:
	case <-time.After(5 * time.Second):
		t.Fatal("client half of the TLS handshake did not finish")
	}

	usk1162AwaitClose(t, conn, 3*time.Second)
}
