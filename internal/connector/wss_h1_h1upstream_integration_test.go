//go:build e2e

package connector_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6455 mandates SHA-1 for the WS handshake
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// ---------------------------------------------------------------------------
// USK-839: e2e coverage for h1.1 listener × h2-advertising upstream
//
// USK-838 design review (2026-05-11) surfaced that no existing test exercises
// the combination of:
//
//   1. Full production wiring via proxybuild.BuildLiveStack +
//      connector.FullListener (NOT an in-process hand-rolled stack).
//   2. EnabledProtocols filter excluding HTTP/2 — set on both the listener
//      (peek-time gate) and BuildConfig (MITM ALPN advertise filter via
//      alpnOffersAllowedByEnabledProtocols, internal/connector/alpn_routing.go).
//   3. Upstream advertising NextProtos=["h2","http/1.1"] (Fly.io edge shape) so
//      the proxy's strip-h2 → upstream redial path is exercised.
//   4. flow.Store assertion: Protocol="ws" Stream with >= 2 Flows (Send +
//      Receive frame pair) and non-empty Raw bytes (L4-capable principle).
//
// USK-838 itself was closed as a pattern-match false positive; this test is
// the gap-closure that locks in the recording behavior so any future drift
// surfaces in the merge-gate smoke tier.
//
// Build tag is plain `//go:build e2e` (smoke tier). CLAUDE.md describes
// e2e_smoke as an exclusion filter applied to exhaustive files via
// `//go:build e2e && !e2e_smoke`; smoke files use only `//go:build e2e`.
// The Issue body's `e2e && e2e_smoke` was a typo per the orchestrator's
// design-review note.
// ---------------------------------------------------------------------------

// TestFullListener_CONNECT_WS_H1Listener_H2AdvertisingUpstream_FlowPersistence
// drives a WS round-trip through a proxy built with proxybuild.BuildLiveStack
// where:
//
//   - The listener has EnabledProtocols=["HTTP/1.x","HTTPS","WebSocket","TCP"]
//     (HTTP/2 excluded). BuildConfig also receives SetEnabledProtocols(...)
//     so the MITM ALPN extension never advertises "h2" even when upstream
//     does — this is the strip-h2 → redial path covered by
//     alpnOffersAllowedByEnabledProtocols.
//   - The upstream test server advertises NextProtos=["h2","http/1.1"] and
//     speaks plain HTTP/1.1 on top of TLS, hijacking the connection to run
//     a minimal WS echo loop.
//   - The client opens a CONNECT tunnel through the proxy, TLS-handshakes
//     with NextProtos=["http/1.1"], performs the RFC 6455 WS upgrade, and
//     exchanges one text frame.
//
// e2e Subsystem Verification Checklist (CLAUDE.md):
//
//	(a) Stream recording: at least one Stream with Protocol="ws" after the
//	    handshake completes — the post-Upgrade ws.Layer retag fired.
//	(b) Flow recording: >= 2 flows under the ws Stream (1 Send + 1 Receive
//	    for the text frame pair).
//	(c) Raw bytes recording: at least one ws-protocol flow on each direction
//	    carries non-empty RawBytes (L4-capable principle).
//	(d) Upstream durably observed the WS frame — wsEchoHits counter
//	    increments on the upstream side.
func TestFullListener_CONNECT_WS_H1Listener_H2AdvertisingUpstream_FlowPersistence(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Upstream: TLS server advertising ["h2","http/1.1"] (Fly.io edge
	//    shape) that ultimately serves http/1.1 after ALPN negotiation. The
	//    proxy must strip "h2" from the offer it sends upstream because its
	//    EnabledProtocols filter excludes HTTP/2 — if that strip is broken,
	//    the upstream will pick h2 first and the proxy's http/1.1-only stack
	//    will mis-route, surfacing as a missing or wrong-protocol Stream.
	hits := newWSEchoHits()
	upstreamAddr, upstreamShutdown := startWSEchoUpstreamH1AdvertisingH2(t, hits)
	defer upstreamShutdown()

	// 2. Proxy: production wiring via proxybuild.BuildLiveStack, with the
	//    EnabledProtocols filter applied to both the listener and BuildConfig.
	proxyAddr, store, shutdown := startWSH1H2AdvertProxy(t, ctx)
	defer shutdown()

	// 3. Client: CONNECT tunnel + TLS NextProtos=["http/1.1"] + RFC 6455 WS
	//    upgrade + text frame round-trip.
	const payload = "usk-839-hello"
	if err := driveWSEchoThroughProxyH1(ctx, proxyAddr, upstreamAddr, payload); err != nil {
		t.Fatalf("WS echo through h1.1 listener (h2-advertising upstream): %v", err)
	}

	// (d) Upstream durably observed the frame.
	if got := hits.totalText(); got < 1 {
		t.Fatalf("upstream WS echo handler text-frame hits = %d, want >= 1 (proxy never delivered the frame)", got)
	}

	// Allow asynchronous Stream/Flow recording to settle before assertion.
	// RecordStep emits via the same session goroutine, but OnComplete state
	// finalisation runs after RunSession returns — give the listener a brief
	// window to drain.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if hasWSStreamWithFlows(store) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// (a) Stream recording.
	streams := store.getStreams()
	wsStreams := 0
	for _, st := range streams {
		if st == nil {
			continue
		}
		if st.Protocol == "ws" {
			wsStreams++
		}
	}
	if wsStreams == 0 {
		t.Fatalf("expected at least one Stream with Protocol=ws; got streams=%+v (USK-838 reproduction candidate: WS retag never landed)",
			summarizeStreams(streams))
	}

	// (b) Flow recording: at least one Send and one Receive flow, both at
	//     the WS protocol tag.
	sendFlows := store.flowsByDirection("send")
	recvFlows := store.flowsByDirection("receive")
	if len(sendFlows) == 0 {
		t.Fatal("no send-direction flows recorded for the WS exchange (USK-838 reproduction candidate)")
	}
	if len(recvFlows) == 0 {
		t.Fatal("no receive-direction flows recorded for the WS exchange (USK-838 reproduction candidate)")
	}

	// (c) Raw bytes: each direction must carry at least one ws-protocol flow
	//     with non-empty RawBytes. Defined locally rather than reusing the
	//     helper in wss_over_h2_integration_test.go because that file's
	//     build tag is `//go:build e2e && !e2e_smoke` — the helper would not
	//     be linked in the smoke tier this test targets.
	if !wsFlowHasNonEmptyRaw(sendFlows) {
		t.Errorf("no ws-protocol send flow with non-empty RawBytes (L4-capable principle violated; USK-838 reproduction candidate)")
	}
	if !wsFlowHasNonEmptyRaw(recvFlows) {
		t.Errorf("no ws-protocol receive flow with non-empty RawBytes (L4-capable principle violated; USK-838 reproduction candidate)")
	}
}

// wsFlowHasNonEmptyRaw reports whether any flow in flows has
// Metadata["protocol"]=="ws" AND carries non-empty RawBytes. Mirrors
// flowHasNonEmptyRawForProtocol in wss_over_h2_integration_test.go but
// scoped to ws because this test only checks WS frames.
//
// Metadata["protocol"] is the canonical per-flow protocol marker stamped
// by RecordStep's envelopeToFlow projection — checking Stream.Protocol
// alone is not sufficient because a Stream's Protocol retag at WS upgrade
// only updates the row, while flows recorded before the retag (the 101
// response itself) keep their pre-retag protocol tag.
func wsFlowHasNonEmptyRaw(flows []*flow.Flow) bool {
	for _, f := range flows {
		if f == nil {
			continue
		}
		if f.Metadata == nil {
			continue
		}
		if f.Metadata["protocol"] != "ws" {
			continue
		}
		if len(f.RawBytes) > 0 {
			return true
		}
	}
	return false
}

// hasWSStreamWithFlows reports whether the store already holds a ws Stream
// plus at least one ws Flow on each direction — used by the post-drive
// settle loop so the assertion does not race the recorder.
func hasWSStreamWithFlows(store *testStore) bool {
	streams := store.getStreams()
	sawWS := false
	for _, st := range streams {
		if st != nil && st.Protocol == "ws" {
			sawWS = true
			break
		}
	}
	if !sawWS {
		return false
	}
	sendOK := wsFlowHasNonEmptyRaw(store.flowsByDirection("send"))
	recvOK := wsFlowHasNonEmptyRaw(store.flowsByDirection("receive"))
	return sendOK && recvOK
}

// summarizeStreams renders a compact view of the recorded streams so a
// failure surface includes enough context to triage without the full struct.
func summarizeStreams(streams []*flow.Stream) []string {
	out := make([]string, 0, len(streams))
	for _, st := range streams {
		if st == nil {
			out = append(out, "<nil>")
			continue
		}
		out = append(out, fmt.Sprintf("{id=%s proto=%q state=%q scheme=%q}", st.ID, st.Protocol, st.State, st.Scheme))
	}
	return out
}

// ---------------------------------------------------------------------------
// Upstream test server: TLS advertising ["h2","http/1.1"] with WS echo over
// http/1.1.
// ---------------------------------------------------------------------------

// wsEchoHits counts data-frame opcodes observed by the upstream echo
// handler. Tests assert .totalText() to confirm the proxy actually
// delivered the client frame (durable upstream-side assertion in the
// MITM-diagnostic test philosophy).
type wsEchoHits struct {
	text   atomic.Int64
	binary atomic.Int64
}

func newWSEchoHits() *wsEchoHits { return &wsEchoHits{} }

func (h *wsEchoHits) totalText() int64 { return h.text.Load() }

// startWSEchoUpstreamH1AdvertisingH2 binds a TLS listener that advertises
// NextProtos=["h2","http/1.1"] — mimicking the Fly.io edge shape that
// triggered USK-838's investigation. After ALPN negotiation the accepted
// connection is parsed as HTTP/1.1; the handler does the RFC 6455 §1.3 WS
// handshake then runs an echo loop. Returns (host:port, shutdown).
//
// The handler is intentionally minimal — no net/http server. The MITM
// implementation principle ("do not normalize what the wire did not") and
// the per-test-self-contained convention (RFC-001 / CLAUDE.md) discourage
// importing net/http machinery just for the handshake parse.
func startWSEchoUpstreamH1AdvertisingH2(t *testing.T, hits *wsEchoHits) (string, func()) {
	t.Helper()
	tlsCfg := newWSEchoUpstreamTLSConfig(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}

	var (
		wg      sync.WaitGroup
		closeMu sync.Mutex
		closed  bool
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				// Settle the TLS handshake so the ALPN choice is fixed before
				// we attempt to read request bytes.
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
					if err := tc.HandshakeContext(context.Background()); err != nil {
						return
					}
					_ = tc.SetDeadline(time.Time{})
					if got := tc.ConnectionState().NegotiatedProtocol; got != "" && got != "http/1.1" {
						// The proxy should have stripped h2 from its offer.
						// If we land here, the test is exposing a real
						// strip-h2 regression — leave the connection open
						// long enough for the assertion at the test level
						// to capture the symptom via flow store contents.
						return
					}
				}
				serveWSEchoOverH1(c, hits)
			}(conn)
		}
	}()

	shutdown := func() {
		closeMu.Lock()
		if closed {
			closeMu.Unlock()
			return
		}
		closed = true
		closeMu.Unlock()
		_ = ln.Close()
		// Best-effort drain; do not block test cleanup indefinitely.
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
	return ln.Addr().String(), shutdown
}

// newWSEchoUpstreamTLSConfig builds the TLS config used by the upstream
// echo server: self-signed leaf with SAN=127.0.0.1 + ALPN advertising
// ["h2","http/1.1"]. Mirrors newWSSOverH2TestTLSConfig but advertises
// http/1.1 alongside h2 (vs h2-only) so the strip-h2 → redial path is
// reachable.
func newWSEchoUpstreamTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "usk-839-upstream"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"usk-839-upstream"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}},
		// Advertise h2 AND http/1.1: triggers the proxy's strip-h2 path
		// when EnabledProtocols excludes HTTP/2.
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	}
}

// serveWSEchoOverH1 reads a RFC 6455 §4.1 client handshake from c, writes
// the 101 Switching Protocols response, then loops echoing data frames.
// Control frames terminate the loop on close; ping/pong is implicit (the
// test client never sends ping). MITM principle 5: malformed input never
// panics — every parse failure simply returns and closes the connection.
func serveWSEchoOverH1(c net.Conn, hits *wsEchoHits) {
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)

	// Parse the HTTP/1.1 request line + headers manually. The handshake we
	// need to extract is Sec-WebSocket-Key; everything else is informational.
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	if !strings.HasPrefix(statusLine, "GET ") {
		return
	}
	var wsKey string
	for {
		line, rerr := br.ReadString('\n')
		if rerr != nil {
			return
		}
		if line == "\r\n" {
			break
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "sec-websocket-key:") {
			wsKey = strings.TrimSpace(line[len("sec-websocket-key:"):])
		}
	}
	if wsKey == "" {
		return
	}

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + computeWSAcceptUSK839(wsKey) + "\r\n" +
		"\r\n"
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(resp)); err != nil {
		return
	}
	_ = c.SetWriteDeadline(time.Time{})
	_ = c.SetReadDeadline(time.Time{})

	// Echo loop: copy text/binary frames back to client. Close frame ends
	// the loop. Use the buffered reader so any post-header bytes are not lost.
	for {
		_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
		f, err := ws.ReadFrame(br)
		if err != nil {
			return
		}
		_ = c.SetReadDeadline(time.Time{})

		switch f.Opcode {
		case ws.OpcodeText:
			hits.text.Add(1)
		case ws.OpcodeBinary:
			hits.binary.Add(1)
		case ws.OpcodeClose:
			closeFrame := &ws.Frame{Fin: true, Opcode: ws.OpcodeClose, Payload: append([]byte(nil), f.Payload...)}
			_ = ws.WriteFrame(c, closeFrame)
			return
		default:
			continue
		}

		echo := &ws.Frame{Fin: f.Fin, Opcode: f.Opcode, Masked: false, Payload: append([]byte(nil), f.Payload...)}
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := ws.WriteFrame(c, echo); err != nil {
			return
		}
		_ = c.SetWriteDeadline(time.Time{})
	}
}

// computeWSAcceptUSK839 returns the Sec-WebSocket-Accept header value per
// RFC 6455 §1.3. Suffixed with the issue ID because the helper in
// internal/mcptest/ws_upstream.go has the same name but lives in a
// different package; keeping a local copy avoids cross-package coupling
// for this gap-closure test.
func computeWSAcceptUSK839(key string) string {
	const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New() //nolint:gosec // RFC 6455 mandates SHA-1
	_, _ = io.WriteString(h, key)
	_, _ = io.WriteString(h, magic)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------------------
// Proxy: production wiring via proxybuild.BuildLiveStack with
// EnabledProtocols filter excluding HTTP/2.
// ---------------------------------------------------------------------------

// startWSH1H2AdvertProxy builds the proxy via the production
// proxybuild.BuildLiveStack entry point, configures the EnabledProtocols
// filter on both the listener and BuildConfig, and starts the listener.
// Returns the proxy address, the recorder store, and a shutdown closure.
//
// EnabledProtocols=["HTTP/1.x","HTTPS","WebSocket","TCP"] excludes both
// "HTTP/2" and "gRPC", so alpnOffersAllowedByEnabledProtocols strips h2
// from the proxy's outgoing upstream ALPN offer regardless of what the
// upstream advertises. This is the strip-h2 → upstream redial gate the
// Issue calls out (USK-839 design context).
func startWSH1H2AdvertProxy(t *testing.T, ctx context.Context) (string, *testStore, func()) {
	t.Helper()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}

	enabledProtocols := []string{"HTTP/1.x", "HTTPS", "WebSocket", "TCP"}

	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
	}
	// USK-808 wiring: SetEnabledProtocols on BuildConfig drives
	// alpnOffersAllowedByEnabledProtocols at MITM TLS handshake time so
	// "h2" never reaches the client- or upstream-facing ALPN extension.
	buildCfg.SetEnabledProtocols(enabledProtocols)

	store := &testStore{}

	deps := proxybuild.Deps{
		Logger:       testutil.DiscardLogger(),
		ListenerName: "usk-839-h1-h2advert",
		ListenAddr:   "127.0.0.1:0",
		FlowStore:    store,
		BuildConfig:  buildCfg,
	}

	stack, err := proxybuild.BuildLiveStack(ctx, deps)
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	// USK-732 wiring: peek-time gate applied at the listener so a h2c
	// preface (PRI * HTTP/2.0) — not used by this test but a defense-in-depth
	// guard — is rejected before any handler runs.
	stack.Listener.SetEnabledProtocols(enabledProtocols)

	go func() { _ = stack.Listener.Start(ctx) }()
	select {
	case <-stack.Listener.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("listener not ready in 5s")
	}

	proxyAddr := stack.Listener.Addr()
	if proxyAddr == "" {
		t.Fatal("listener has no addr")
	}

	// Listener shutdown is driven by ctx cancellation
	// (connector.FullListener has no Close — Start(ctx) returns once ctx
	// is done; matches the existing onhttp1_integration_test.go pattern).
	shutdown := func() {}
	return proxyAddr, store, shutdown
}

// ---------------------------------------------------------------------------
// Client driver: CONNECT + TLS(http/1.1) + WS Upgrade + text frame round-trip.
// ---------------------------------------------------------------------------

// driveWSEchoThroughProxyH1 opens a CONNECT tunnel to upstreamAddr via the
// proxy at proxyAddr, TLS-handshakes inside the tunnel with
// NextProtos=["http/1.1"] (matching what a default Chrome wss:// dial
// offers — USK-763 note in wss_over_h2_integration_test.go), performs the
// RFC 6455 §4.1 WS handshake against /usk839, sends one masked text frame
// containing payload, and verifies the echoed frame matches.
//
// Returns nil on success; an error on any wire mismatch or timeout.
func driveWSEchoThroughProxyH1(ctx context.Context, proxyAddr, upstreamAddr, payload string) error {
	// 1. Open CONNECT tunnel.
	raw, err := dialCONNECTH1(ctx, proxyAddr, upstreamAddr)
	if err != nil {
		return fmt.Errorf("dial CONNECT: %w", err)
	}
	defer raw.Close()

	// 2. TLS handshake inside the tunnel. ALPN offer is http/1.1-only so
	//    the proxy's MITM ALPN selection lands on http/1.1; if the filter
	//    were broken the proxy could still offer h2 from upstream's cache
	//    and the client would refuse with no_application_protocol.
	tlsCfg := &tls.Config{
		ServerName:         hostFromHostPort(upstreamAddr),
		InsecureSkipVerify: true, //nolint:gosec // proxy MITM cert is ephemeral
		NextProtos:         []string{"http/1.1"},
		MinVersion:         tls.VersionTLS12,
	}
	tlsConn := tls.Client(raw, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("inner TLS handshake: %w", err)
	}
	if got := tlsConn.ConnectionState().NegotiatedProtocol; got != "" && got != "http/1.1" {
		return fmt.Errorf("inner TLS NegotiatedProtocol = %q, want %q (filter did not strip h2)", got, "http/1.1")
	}

	// 3. RFC 6455 client handshake.
	if err := writeWSClientHandshakeUSK839(tlsConn, upstreamAddr); err != nil {
		return fmt.Errorf("WS client handshake: %w", err)
	}
	br := bufio.NewReader(tlsConn)
	if err := readWS101StatusUSK839(br); err != nil {
		return fmt.Errorf("read WS 101: %w", err)
	}

	// 4. Send one masked text frame.
	frame := &ws.Frame{
		Fin:     true,
		Opcode:  ws.OpcodeText,
		Masked:  true,
		MaskKey: [4]byte{0xa1, 0xb2, 0xc3, 0xd4},
		Payload: []byte(payload),
	}
	if err := tlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	if err := ws.WriteFrame(tlsConn, frame); err != nil {
		return fmt.Errorf("write WS frame: %w", err)
	}
	_ = tlsConn.SetWriteDeadline(time.Time{})

	// 5. Read echo.
	if err := tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return fmt.Errorf("set read deadline: %w", err)
	}
	echo, err := ws.ReadFrame(br)
	if err != nil {
		return fmt.Errorf("read echo frame: %w", err)
	}
	_ = tlsConn.SetReadDeadline(time.Time{})
	if echo.Opcode != ws.OpcodeText {
		return fmt.Errorf("echo opcode = %#x, want %#x", echo.Opcode, ws.OpcodeText)
	}
	if string(echo.Payload) != payload {
		return fmt.Errorf("echo payload = %q, want %q", string(echo.Payload), payload)
	}
	return nil
}

// dialCONNECTH1 dials the proxy at proxyAddr and issues a CONNECT request
// targeting upstreamAddr. Returns the raw net.Conn positioned right after
// the "200 Connection Established" headers. The response is bounded to
// 16 KiB to avoid unbounded reads on a misbehaving proxy.
func dialCONNECTH1(ctx context.Context, proxyAddr, upstreamAddr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}
	dl := time.Now().Add(5 * time.Second)
	if ctxDL, ok := ctx.Deadline(); ok && ctxDL.Before(dl) {
		dl = ctxDL
	}
	if err := conn.SetDeadline(dl); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set deadline: %w", err)
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamAddr, upstreamAddr)
	if _, err := conn.Write([]byte(req)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write CONNECT: %w", err)
	}
	var buf bytes.Buffer
	tmp := make([]byte, 256)
	for {
		n, rerr := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if rerr != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("read CONNECT response: %w", rerr)
		}
		if bytes.Contains(buf.Bytes(), []byte("\r\n\r\n")) {
			break
		}
		if buf.Len() > 16<<10 {
			_ = conn.Close()
			return nil, fmt.Errorf("CONNECT response exceeds 16 KiB")
		}
	}
	if !bytes.Contains(buf.Bytes(), []byte(" 200 ")) {
		_ = conn.Close()
		return nil, fmt.Errorf("CONNECT failed: %q", buf.String())
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("clear deadline: %w", err)
	}
	return conn, nil
}

// writeWSClientHandshakeUSK839 writes a compliant RFC 6455 §4.1 client
// handshake to conn targeting /usk839. host is "host:port" — the Host
// header carries this verbatim so the upstream test server (which only
// checks Sec-WebSocket-Key) accepts the request regardless of port
// canonicalisation.
func writeWSClientHandshakeUSK839(conn net.Conn, host string) error {
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return fmt.Errorf("generate Sec-WebSocket-Key: %w", err)
	}
	wsKey := base64.StdEncoding.EncodeToString(keyBytes)

	req := "GET /usk839 HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + wsKey + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"
	if err := conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()
	if _, err := io.WriteString(conn, req); err != nil {
		return fmt.Errorf("write handshake: %w", err)
	}
	return nil
}

// readWS101StatusUSK839 reads the HTTP/1.1 101 Switching Protocols response
// line plus the trailing header block from br. Returns an error on any
// non-101 status, malformed headers, or read error. Does not validate
// Sec-WebSocket-Accept against the request key — the upstream owns its
// own validation; the proxy is wire-faithful so any Accept value the
// upstream sends back must arrive verbatim.
func readWS101StatusUSK839(br *bufio.Reader) error {
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read status line: %w", err)
	}
	if !strings.HasPrefix(statusLine, "HTTP/1.1 101") {
		preview := make([]byte, 0, 512)
		preview = append(preview, statusLine...)
		for len(preview) < 512 {
			line, rerr := br.ReadString('\n')
			preview = append(preview, line...)
			if rerr != nil || line == "\r\n" {
				break
			}
		}
		return fmt.Errorf("unexpected handshake response: %q", string(preview))
	}
	for {
		line, rerr := br.ReadString('\n')
		if rerr != nil {
			return fmt.Errorf("read header: %w", rerr)
		}
		if line == "\r\n" {
			return nil
		}
	}
}

// hostFromHostPort returns the host portion of a "host:port" string. Used
// to populate tls.Config.ServerName which must not include the port.
func hostFromHostPort(hostPort string) string {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return host
}
