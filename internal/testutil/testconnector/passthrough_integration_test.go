//go:build e2e

package testconnector_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/testutil/testconnector"
)

// TestPassthroughBypassesTLSMITM verifies that when the CONNECT target
// matches the passthrough list, the tunnel relays raw bytes directly and
// the client's TLS handshake goes end-to-end with the upstream (not the
// proxy). Consequently no Pipeline Step is invoked and no Stream is
// recorded — the proxy cannot inspect bytes it never decrypts.
func TestPassthroughBypassesTLSMITM(t *testing.T) {
	// Use a raw upstream so the client trusts only the upstream's cert.
	// A passthrough tunnel means the client sees the upstream's cert, not
	// the harness MITM CA, so TLS verification tests are meaningful.
	rawUp := startRawTLSUpstream(t)
	defer rawUp.Close()

	upstreamHost, _, _ := net.SplitHostPort(rawUp.Listener.Addr().String())
	_ = upstreamHost

	h := testconnector.Start(t,
		testconnector.WithRawUpstream(rawUp.Listener.Addr(), rawUp.Cert),
		// Passthrough uses hostname matching, not IP — use 127.0.0.1 because
		// that's what the listener binds to.
		testconnector.WithPassthroughHosts([]string{"127.0.0.1"}),
	)

	// Issue a CONNECT and TLS handshake. With passthrough the leaf cert
	// should be rawUp.Cert, NOT a MITM cert from h.CA.
	conn, err := net.DialTimeout("tcp", h.ClientAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	target := h.UpstreamAddr
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)

	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}
	if !strings.Contains(status, " 200 ") {
		t.Fatalf("CONNECT response not 200: %q", status)
	}
	// Drain headers.
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// Preserve any bytes bufio may have buffered.
	buffered, _ := br.Peek(br.Buffered())
	wrapped := &peekReadConn{Conn: conn, remaining: append([]byte(nil), buffered...)}

	// TLS handshake — because this is passthrough, the client must trust
	// the *raw upstream* cert, not the harness MITM CA.
	tlsConn := tls.Client(wrapped, &tls.Config{
		ServerName: "localhost",
		RootCAs:    h.UpstreamCAPool,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake via passthrough: %v", err)
	}

	// Verify we really saw the raw upstream's certificate.
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("no peer certs")
	}
	if state.PeerCertificates[0].Subject.CommonName != "rawupstream" {
		t.Fatalf("peer CN=%q want rawupstream (MITM was NOT bypassed)",
			state.PeerCertificates[0].Subject.CommonName)
	}

	// Send a request through so the upstream records it.
	req := "GET /pt HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n"
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	_, _ = io.ReadAll(tlsConn)
	tlsConn.Close()

	// Verify the raw upstream received it.
	raw := rawUp.WaitFirst(t, 2*time.Second)
	if !strings.Contains(raw, "GET /pt") {
		t.Fatalf("upstream did not see request bytes: %q", raw)
	}

	// And critically: no HTTP/1.x stream should have been recorded by the
	// Pipeline (passthrough means no Codec ran). Poll for a bounded window
	// so we give the server time to settle and fail fast if a stream does
	// appear.
	ctx := context.Background()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		streams, err := h.Store.ListStreams(ctx, flow.StreamListOptions{Protocol: "HTTP/1.x"})
		if err != nil {
			t.Fatalf("list streams: %v", err)
		}
		if len(streams) != 0 {
			t.Fatalf("expected zero HTTP/1.x streams under passthrough, got %d", len(streams))
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// TestPassthroughMissUsesMITM verifies the negative case: a host that is
// NOT in the passthrough list still goes through the MITM path and gets
// recorded by the Pipeline.
func TestPassthroughMissUsesMITM(t *testing.T) {
	h := testconnector.Start(t,
		testconnector.WithPassthroughHosts([]string{"not-in-list.example"}),
	)

	client := httpsClientViaProxy(t, h)
	resp, err := client.Get(h.UpstreamServer.URL + "/miss")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	waitForFlows(t, h.Store, "HTTP/1.x", 2, 3*time.Second)
}
