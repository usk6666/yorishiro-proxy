//go:build e2e

package connector_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestCONNECT_ClientHTTP1Upstream_H2_NoMisdispatch_Fallback is the
// regression guard for USK-793 exercised on the legacy fallback path.
// USK-997 made sniff-first MITM the primary route; this test keeps
// coverage of the pre-sniff widening + mismatch-redial flow by opting
// out of the peek via fullListenerOpts.disableClientHelloPeek.
//
// Setup: an upstream TLS server that advertises both "h2" and "http/1.1"
// ALPN protocols (with "h2" first, so it would be picked when the proxy
// offers both — matching the real curl/httpbin scenario in the bug report).
// The actual server speaks HTTP/1.x on the wire — the test does not run a
// real h2 implementation; we only need the upstream's TLS server to PICK
// h2 in the ALPN handshake, which lets the proxy think "h2 is the route".
//
// Behaviour under test: a client connects via CONNECT, performs a TLS
// handshake offering ONLY "http/1.1" ALPN, and sends a plain HTTP/1.x
// request. Pre-USK-793 the proxy would offer the client only "h2"
// (learned from upstream), the client+server TLS would complete with
// empty NegotiatedProtocol (Go's silent fallback), the proxy would route
// the inner stack via HTTP/2 because it consulted upstream's ALPN
// instead of the client's, and the HTTP/2 framer would reject the
// "GET / HTTP/1.1\r\n..." preface as invalid → curl 0-byte timeout.
//
// Post-USK-793: the proxy advertises BOTH ALPNs to the client, the
// client picks "http/1.1", the proxy detects the client/upstream
// mismatch and re-dials upstream with "http/1.1" so the inner stack
// is single-protocol end-to-end. Round-trip succeeds; flow is recorded
// with state=complete, protocol=http, scheme=https.
func TestCONNECT_ClientHTTP1Upstream_H2_NoMisdispatch_Fallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, getUpstreamReqs := startUpstreamHTTPSWithALPN(t,
		[]string{"h2", "http/1.1"},
		func(_ []byte) []byte {
			return []byte("HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nh1-served")
		},
	)
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, store, wg := startFullListenerProxy(t, ctx, fullListenerOpts{
		disableClientHelloPeek: true,
	})

	wg.Add(1)
	rawReq := fmt.Sprintf(
		"GET /alpn-mismatch HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		target,
	)
	resp := connectAndSendHTTPWithClientALPN(t, proxyAddr, target, []string{"http/1.1"}, rawReq)

	upstreamReqs := getUpstreamReqs()
	waitSessionDone(t, wg)

	// --- Verify response ---
	if !strings.Contains(resp, "200 OK") {
		t.Errorf("response missing 200 OK: %q", resp)
	}
	if !strings.HasSuffix(resp, "h1-served") {
		t.Errorf("response body unexpected: %q", resp)
	}

	// --- Verify upstream received the HTTP/1.x request (not an h2 preface) ---
	if len(upstreamReqs) < 1 {
		t.Fatal("upstream received no requests")
	}
	if !bytes.Contains(upstreamReqs[0], []byte("GET /alpn-mismatch HTTP/1.1")) {
		t.Errorf("upstream did not receive HTTP/1.x GET request: %q", upstreamReqs[0])
	}
	// Pre-USK-793, the upstream would have received the HTTP/2 client
	// preface bytes ("PRI * HTTP/2.0..." or 0x00-prefixed framing) as the
	// proxy attempted to bridge h1↔h2.
	if bytes.HasPrefix(upstreamReqs[0], []byte("PRI ")) {
		t.Errorf("upstream received HTTP/2 client preface — proxy misdispatched to h2: %q", upstreamReqs[0])
	}

	// --- Verify stream recording: protocol=http, scheme=https, state=complete ---
	streams := store.getStreams()
	if len(streams) < 1 {
		t.Fatal("expected at least 1 stream, got 0")
	}
	if streams[0].Protocol != "http" {
		t.Errorf("stream protocol = %q, want %q", streams[0].Protocol, "http")
	}
	if streams[0].Scheme != "https" {
		t.Errorf("stream scheme = %q, want %q", streams[0].Scheme, "https")
	}
	// Pre-USK-793 the misdispatch produced State="error" on the recorded
	// stream because the inner h2 framer rejected the HTTP/1.x preface.
	// Post-fix the stream stays "active" while in flight or transitions
	// to "complete"; both are healthy outcomes, "error" is not.
	if streams[0].State == "error" {
		t.Errorf("stream state = %q (regression: USK-793 misdispatch surfaces as state=error)",
			streams[0].State)
	}

	// --- Verify flow recording (Send/Receive) ---
	sendFlows := store.flowsByDirection("send")
	if len(sendFlows) < 1 {
		t.Fatal("expected at least 1 send flow, got 0")
	}
	recvFlows := store.flowsByDirection("receive")
	if len(recvFlows) < 1 {
		t.Fatal("expected at least 1 receive flow, got 0")
	}
	if len(sendFlows[0].RawBytes) == 0 {
		t.Error("send flow RawBytes is empty (L4-capable principle violated)")
	}
	if len(recvFlows[0].RawBytes) == 0 {
		t.Error("receive flow RawBytes is empty")
	}
}

// TestCONNECT_ClientH2Upstream_H2_StillWorks_Fallback is the positive
// control for USK-793 on the legacy fallback path. USK-997 moved
// sniff-first to the primary route; this variant continues to verify
// the pre-sniff widening behaviour. The test guards against the
// "fix everything to h1" regression mode on the fallback flow.
func TestCONNECT_ClientH2Upstream_H2_StillWorks_Fallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream advertises both protocols. The proxy will dial with
	// [h2, http/1.1], upstream picks h2.
	upstreamLn, _ := startUpstreamHTTPSWithALPN(t,
		[]string{"h2", "http/1.1"},
		func(_ []byte) []byte {
			return []byte("HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nh1-served")
		},
	)
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, _, wg := startFullListenerProxy(t, ctx, fullListenerOpts{
		disableClientHelloPeek: true,
	})

	// Client offers both protocols. Should pick h2 (proxy's first offer
	// matches upstream's first offer).
	wg.Add(1)
	tlsConn := connectThroughProxyWithALPN(t, proxyAddr, target, []string{"h2", "http/1.1"})
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		t.Errorf("client negotiated ALPN = %q, want %q (proxy must still pick h2 when both sides support it)",
			state.NegotiatedProtocol, "h2")
	}
	// Don't continue with h2 framing — TLS negotiation success is what we
	// were testing. Closing the TLS conn unwinds the proxy session.
}

// startUpstreamHTTPSWithALPN starts a raw TLS server that advertises the
// given ALPN list and serves HTTP/1.x requests via handler. Used by the
// USK-793 regression test to set up an upstream whose ALPN choice differs
// from what the client wants.
func startUpstreamHTTPSWithALPN(
	t *testing.T,
	nextProtos []string,
	handler func(reqBytes []byte) []byte,
) (net.Listener, func() [][]byte) {
	t.Helper()
	tlsCfg := newTestTLSConfig(t)
	tlsCfg.NextProtos = nextProtos
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}

	captured := make(chan [][]byte, 1)
	var captureMu sync.Mutex
	var allReqs [][]byte
	publishOnce := sync.Once{}
	publish := func() {
		publishOnce.Do(func() {
			captureMu.Lock()
			out := make([][]byte, len(allReqs))
			copy(out, allReqs)
			captureMu.Unlock()
			captured <- out
		})
	}

	// Accept loop: the proxy may dial upstream multiple times when the
	// client's ALPN does not match the upstream's first preference (USK-793
	// re-dial behaviour). Each accepted connection is served independently
	// so we don't hang waiting for the first connection to drive a request
	// that the proxy actually issues on a later one.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				publish()
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Force the TLS handshake so the underlying ALPN choice
				// is settled before we attempt to read.
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.HandshakeContext(context.Background())
				}
				br := bufio.NewReader(c)
				for {
					c.SetReadDeadline(time.Now().Add(5 * time.Second))
					reqBytes, err := readHTTPRequest(br)
					if err != nil {
						return
					}
					reqCopy := make([]byte, len(reqBytes))
					copy(reqCopy, reqBytes)
					captureMu.Lock()
					allReqs = append(allReqs, reqCopy)
					captureMu.Unlock()
					// Publish as soon as the first real HTTP/1.x request
					// arrives so the test can assert without waiting for
					// the upstream side to fully tear down (the proxy's
					// session teardown depends on the test client closing
					// _its_ TLS conn after reading the response).
					publish()

					resp := handler(reqBytes)
					c.SetWriteDeadline(time.Now().Add(5 * time.Second))
					if _, werr := c.Write(resp); werr != nil {
						return
					}
					if bytes.Contains(bytes.ToLower(resp), []byte("connection: close")) {
						return
					}
				}
			}(conn)
		}
	}()

	return ln, func() [][]byte {
		select {
		case b := <-captured:
			return b
		case <-time.After(15 * time.Second):
			t.Fatal("timeout waiting for upstream captured bytes")
			return nil
		}
	}
}

// connectThroughProxyWithALPN is connectThroughProxy with a custom client
// ALPN offer set, so tests can exercise the USK-793 misdispatch path.
func connectThroughProxyWithALPN(t *testing.T, proxyAddr, target string, alpnOffers []string) *tls.Conn {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		t.Fatalf("write CONNECT: %v", err)
	}

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		t.Fatalf("read CONNECT response: %v", err)
	}
	if got := string(buf[:n]); got != "HTTP/1.1 200 Connection Established\r\n\r\n" {
		conn.Close()
		t.Fatalf("unexpected CONNECT response: %q", got)
	}

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test
		NextProtos:         alpnOffers,
	})
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		t.Fatalf("TLS handshake through proxy: %v", err)
	}

	return tlsConn
}

// connectAndSendHTTPWithClientALPN performs a CONNECT + TLS handshake with
// the specified client ALPN offers, sends a raw HTTP request, and returns
// the response.
func connectAndSendHTTPWithClientALPN(t *testing.T, proxyAddr, target string, alpnOffers []string, rawRequest string) string {
	t.Helper()
	tlsConn := connectThroughProxyWithALPN(t, proxyAddr, target, alpnOffers)
	defer tlsConn.Close()

	if _, err := tlsConn.Write([]byte(rawRequest)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	return readHTTPResponse(t, tlsConn)
}
