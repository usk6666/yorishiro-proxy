//go:build e2e && !e2e_smoke

package connector_test

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector/testutil"
)

// TestSniffFirstMITM_RFC7301Violation_Demo1NextcloudRegression is the
// end-to-end USK-997 regression for the USK-995 reproducer: an upstream
// nginx with ssl_alpn_protocol http/1.1 returns http/1.1 even for a solo
// h2 ALPN offer (RFC 7301 §3.2 violation).
//
// Pre-USK-997 the proxy's speculative-then-redial logic mishandled this:
// it asked upstream what *it* preferred, got http/1.1, then advertised
// [h2, http/1.1] to the client (the USK-884 widening), the client picked
// h2, and the mismatch redial dance then either looped or settled on a
// wrong protocol → curl 0-byte timeout symptom in the wild.
//
// Post-USK-997 the proxy peeks the client's ClientHello, forwards the
// client's exact ALPN list to upstream, observes upstream's wrong pick
// http/1.1, and advertises [http/1.1] back to the client. End-to-end
// http/1.1 by construction; no mismatch, no redial dance.
//
// The test asserts the round-trip succeeds and the inner client's
// NegotiatedProtocol equals http/1.1 — i.e. the proxy transparently
// propagated upstream's (incorrect-per-RFC) ALPN pick.
func TestSniffFirstMITM_RFC7301Violation_Demo1NextcloudRegression(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := testutil.StartRFC7301NonCompliantUpstream(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 4096)
		for n := 0; n < len(buf); {
			nn, err := conn.Read(buf[n:])
			if err != nil {
				return
			}
			n += nn
			if bytes.Contains(buf[:n], []byte("\r\n\r\n")) {
				break
			}
		}
		_, _ = conn.Write([]byte(
			"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nsniff-first!"))
	})
	defer upstream.Close()
	target := upstream.Addr

	proxyAddr, _, wg := startFullListenerProxy(t, ctx, fullListenerOpts{})

	// Client offers both h2 and http/1.1. Upstream's spec-violating
	// behaviour will pick http/1.1; the sniff-first MITM path must
	// advertise [http/1.1] to the client.
	wg.Add(1)
	tlsConn := connectThroughProxyWithALPN(t, proxyAddr, target, []string{"h2", "http/1.1"})
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != "http/1.1" {
		t.Fatalf("client ALPN = %q, want http/1.1 (sniff-first MITM must propagate upstream's RFC 7301 §3.2 wrong pick)",
			state.NegotiatedProtocol)
	}

	// Drive an HTTP/1.x request through to verify the data path is
	// healthy (no mid-flight crash from a wrong inner-route dispatch
	// — the pre-USK-997 USK-995 symptom).
	if _, err := tlsConn.Write([]byte(
		"GET /sniff-first HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp := readHTTPResponse(t, tlsConn)
	if !strings.Contains(resp, "200 OK") {
		t.Errorf("response missing 200 OK: %q", resp)
	}
	if !strings.HasSuffix(resp, "sniff-first!") {
		t.Errorf("response body unexpected: %q", resp)
	}

	waitSessionDone(t, wg)
}
