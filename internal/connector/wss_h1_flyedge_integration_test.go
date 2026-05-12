//go:build e2e && !e2e_smoke

package connector_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6455 mandates SHA-1 for the WS handshake
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
)

// ---------------------------------------------------------------------------
// USK-841 Phase A: Fly.io-edge-shaped reproduction harness.
//
// Live-wire testing on 2026-05-11 against wss://httpbingo.org/websocket/echo
// surfaced a recording gap: although the browser receives the echo (wire-
// level WS frames pass through the proxy), the proxy records:
//
//   - flow.protocol = "http" (no retag to "ws")
//   - flow.state    = "active" (stuck — never transitions to complete/error)
//   - message_count = 2 (handshake + 101 only; zero WS frames)
//
// PR #834 (USK-839) added an in-process e2e test that drives the same
// production wiring (proxybuild.BuildLiveStack + connector.FullListener
// with SetEnabledProtocols) but passes against an upstream that completes
// the 101 in a SINGLE TCP write and never pushes bytes before the client
// sends the first frame. The live failure differs only in:
//
//   (1) the 101 response is fragmented across multiple TCP writes
//       (TLS-edge buffering behavior), AND
//   (2) the upstream may push bytes (typically a control / padding frame)
//       immediately after 101 is fully flushed, BEFORE the client sends
//       its first WS frame.
//
// This file reproduces those two shape variants in-process. Per CLAUDE.md
// MITM Principle #6, Phase A does NOT fix the underlying bug — it makes
// the bug observable via slog.Debug instrumentation (see
// internal/session/session.go runUpgradeWS + internal/layer/ws/channel.go
// wsChannel.Next) plus this deterministic reproduction harness.
//
// Expected outcome on main: the test cases below are EXPECTED TO FAIL —
// they reproduce the live bug. Phase B (a follow-up commit) will read the
// runtime trace from a live repro, identify the root cause, apply the
// minimal fix, and flip the test to passing.
//
// e2e tier: exhaustive (//go:build e2e && !e2e_smoke). Promote to smoke
// after Phase B lands AND the test deterministically passes per USK-728.
// ---------------------------------------------------------------------------

// flyedgeOpts shape-tunes the test upstream. Three knobs:
//
//   - fragmentHandshake: split the 101 Switching Protocols response across
//     at least 2 TCP writes (status line + first header → flush →
//     remaining headers + trailing CRLFCRLF). Mimics TLS edge buffering.
//   - pushPaddingPostHandshake: immediately after the 101 is fully
//     flushed, write one unmasked empty text frame (0x81 0x00) on the
//     same conn — server-initiated pre-client-traffic data. This
//     stresses the "upstream byte-tap continuity across the swap"
//     hypothesis (H4): if the upstream-side http1.Layer's bufio.Reader
//     consumed these bytes before DetachStream was invoked, they would
//     be sitting in bufio's buffer at swap time; the post-swap ws.Layer
//     must inherit them.
//   - separateInnerEcho: reserved for v2 — route post-handshake frame
//     echo to a separate goroutine. v1 echoes in the same goroutine that
//     wrote the 101; this preserves byte-order determinism on the wire.
type flyedgeOpts struct {
	fragmentHandshake        bool
	pushPaddingPostHandshake bool
	separateInnerEcho        bool
}

// TestWSS_FlyEdge_H1Listener_FlowPersistence drives a WS round-trip through
// the proxy against a Fly.io-edge-shaped upstream. Variant table:
//
//   - baseline: fragmented 101 only (no pre-frame push).
//   - push-padding: fragmented 101 + empty text frame pushed immediately
//     after 101, BEFORE the client sends its first WS frame.
//
// Each case asserts the same four USK-839 acceptance criteria the per-case
// helpers re-implement:
//
//	(a) Stream with Protocol="ws" recorded (>= 1)
//	(b) Send + Receive flows recorded (>= 1 each) under the ws Stream
//	(c) Flow.RawBytes non-empty for at least one ws-direction-flow
//	    pair (L4-capable principle)
//	(d) Upstream durably observed the WS frame (hits.totalText >= 1)
//
// Cases are wrapped in t.Run so a single failure surface contains the
// variant identity, and on success/failure the full case set runs (helping
// Phase B see which variants the fix flips).
func TestWSS_FlyEdge_H1Listener_FlowPersistence(t *testing.T) {
	cases := []struct {
		name string
		opts flyedgeOpts
	}{
		{
			name: "baseline_fragmented_101",
			opts: flyedgeOpts{fragmentHandshake: true},
		},
		{
			name: "fragmented_101_plus_push_padding",
			opts: flyedgeOpts{fragmentHandshake: true, pushPaddingPostHandshake: true},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			runFlyEdgeCase(t, tc.opts)
		})
	}
}

// runFlyEdgeCase exercises one (upstream shape, proxy config) tuple end-
// to-end. Acceptance assertions mirror USK-839 — see
// TestFullListener_CONNECT_WS_H1Listener_H2AdvertisingUpstream_FlowPersistence
// in wss_h1_h1upstream_integration_test.go for the spec source.
//
// The helper deliberately reports failures via t.Errorf (continue-on-fail)
// rather than t.Fatalf at the per-assertion level so a single test run
// surfaces ALL four acceptance gaps for Phase B's analysis — knowing only
// the first failure makes triage harder when multiple invariants fail in
// concert.
func runFlyEdgeCase(t *testing.T, opts flyedgeOpts) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Upstream: Fly.io-edge-shaped — fragmented 101 + optional padding push.
	hits := newWSEchoHits()
	upstreamAddr, upstreamShutdown := startFlyedgeWSUpstream(t, opts, hits)
	defer upstreamShutdown()

	// 2. Proxy: same production wiring as USK-839 (proxybuild.BuildLiveStack
	//    + SetEnabledProtocols filter excluding HTTP/2).
	proxyAddr, store, shutdown := startWSH1H2AdvertProxy(t, ctx)
	defer shutdown()

	// 3. Client: CONNECT tunnel + TLS NextProtos=["http/1.1"] + RFC 6455
	//    handshake + masked text frame round-trip.
	const payload = "usk-841-hello"
	driverErr := driveWSEchoThroughProxyH1(ctx, proxyAddr, upstreamAddr, payload)
	if driverErr != nil {
		// The client driver can fail if the upstream's fragmented 101 path
		// fails to deliver bytes to the proxy before the proxy's swap
		// orchestrator detaches the stream, OR if the proxy mis-routes
		// frames (e.g., delivers the upstream's pushed padding frame to
		// the client as the "echo" while losing the actual echo). Record
		// the error but CONTINUE to the store assertions so Phase B can
		// see the full failure signal (wire + recording) in a single run.
		// t.Errorf (not t.Fatalf) keeps subsequent invariants alive.
		t.Errorf("WS echo through proxy (variant=%+v): %v", opts, driverErr)
	}

	// (d) Upstream durably observed the frame.
	if got := hits.totalText(); got < 1 {
		t.Errorf("upstream WS echo handler text-frame hits = %d, want >= 1 (proxy never delivered the frame)", got)
	}

	// Allow asynchronous Stream/Flow recording to settle. The recorder
	// runs in-band with the session goroutine, but OnComplete finalisation
	// fires after RunSession returns; poll briefly.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if hasWSStreamWithFlows(store) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// (a) Stream recording: a Stream with Protocol="ws" must exist after
	//     the post-Upgrade ws.Layer retag fires.
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
		t.Errorf("expected at least one Stream with Protocol=ws; got streams=%+v (USK-841 reproduction: WS retag never landed)",
			summarizeStreams(streams))
	}

	// (b) Flow recording: at least one Send and one Receive flow under the
	//     WS protocol tag — the Phase A bug symptom is "message_count = 2"
	//     i.e. only handshake + 101 are recorded, ZERO frame envelopes.
	sendFlows := store.flowsByDirection("send")
	recvFlows := store.flowsByDirection("receive")
	if len(sendFlows) == 0 {
		t.Errorf("no send-direction flows recorded for the WS exchange (USK-841 reproduction)")
	}
	if len(recvFlows) == 0 {
		t.Errorf("no receive-direction flows recorded for the WS exchange (USK-841 reproduction)")
	}

	// (c) Raw bytes: each direction must carry at least one ws-protocol
	//     flow with non-empty RawBytes (L4-capable principle).
	if !wsFlowHasNonEmptyRaw(sendFlows) {
		t.Errorf("no ws-protocol send flow with non-empty RawBytes (L4-capable principle violated; USK-841 reproduction)")
	}
	if !wsFlowHasNonEmptyRaw(recvFlows) {
		t.Errorf("no ws-protocol receive flow with non-empty RawBytes (L4-capable principle violated; USK-841 reproduction)")
	}
}

// ---------------------------------------------------------------------------
// Fly.io-edge-shaped upstream
// ---------------------------------------------------------------------------

// startFlyedgeWSUpstream binds a TLS listener that emulates a Fly.io edge:
//
//   - Advertises NextProtos=["h2","http/1.1"]. The proxy strips "h2" from
//     its upstream-facing ALPN offer per the SetEnabledProtocols filter,
//     so the negotiated protocol observed by the upstream is "http/1.1".
//   - Reads the RFC 6455 client handshake via a bare bufio.Reader (no
//     net/http server — wire-fidelity convention).
//   - Writes the 101 Switching Protocols response as either:
//     fragmentHandshake=false → single Write call.
//     fragmentHandshake=true  → two Write calls separated by a short
//     pause; the first carries the status
//     line + Upgrade/Connection headers, the
//     second carries Sec-WebSocket-Accept +
//     the trailing CRLFCRLF terminator.
//   - When pushPaddingPostHandshake is true, immediately after the 101
//     flush completes the upstream writes an unmasked empty text frame
//     (0x81 0x00) — one server-initiated WS frame BEFORE the client
//     transmits anything. This is the wire-shape that surfaces when an
//     edge intermediation layer pushes liveness/ping bytes immediately
//     after handshake completion.
//   - Then enters the standard echo loop (same as serveWSEchoOverH1).
//
// Returns (host:port, shutdown). shutdown is idempotent and bounds drain
// to 2 seconds so a test cleanup cannot wedge.
//
// MITM principle 5 (parser robustness) applies: every parse failure
// simply returns without panic — the handler closes its conn and the
// proxy observes a half-close.
func startFlyedgeWSUpstream(t *testing.T, opts flyedgeOpts, hits *wsEchoHits) (string, func()) {
	t.Helper()
	tlsCfg := newFlyedgeUpstreamTLSConfig(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("flyedge upstream listen: %v", err)
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
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
					if herr := tc.HandshakeContext(context.Background()); herr != nil {
						return
					}
					_ = tc.SetDeadline(time.Time{})
					if got := tc.ConnectionState().NegotiatedProtocol; got != "" && got != "http/1.1" {
						// The proxy should have stripped h2 from its
						// outgoing offer. Land here only on a strip-h2
						// regression — close and let the test-level
						// assertion observe the symptom via the flow store.
						return
					}
				}
				serveFlyedgeWS(c, opts, hits)
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
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
	return ln.Addr().String(), shutdown
}

// newFlyedgeUpstreamTLSConfig builds the TLS config for the flyedge
// upstream: self-signed leaf with SAN=127.0.0.1, NextProtos advertising
// both h2 and http/1.1. Mirrors newWSEchoUpstreamTLSConfig in
// wss_h1_h1upstream_integration_test.go but kept local so this file
// remains self-contained.
func newFlyedgeUpstreamTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "usk-841-flyedge-upstream"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"usk-841-flyedge-upstream"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}
}

// serveFlyedgeWS parses the WS client handshake from c, writes the 101
// (fragmented per opts), optionally pushes a padding frame, then echoes
// data frames until a close frame arrives or the conn closes. The handler
// is intentionally hand-rolled — no net/http server is involved per the
// project's wire-fidelity convention.
func serveFlyedgeWS(c net.Conn, opts flyedgeOpts, hits *wsEchoHits) {
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)

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

	// Compose the 101 response. We split it into two chunks regardless of
	// fragmentHandshake so that the only difference between baseline and
	// fragmented modes is the single Write vs two-Write boundary.
	accept := computeWSAcceptUSK841(wsKey)
	firstChunk := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n"
	secondChunk := "Sec-WebSocket-Accept: " + accept + "\r\n" +
		"\r\n"

	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if opts.fragmentHandshake {
		if _, werr := c.Write([]byte(firstChunk)); werr != nil {
			return
		}
		// Brief pause to ensure the kernel has flushed the first chunk and
		// the proxy's bufio.Reader has consumed it before the second
		// chunk arrives. Without this pause the kernel could coalesce the
		// two writes into one packet, defeating the fragmentation shape.
		time.Sleep(5 * time.Millisecond)
		if _, werr := c.Write([]byte(secondChunk)); werr != nil {
			return
		}
	} else {
		if _, werr := c.Write([]byte(firstChunk + secondChunk)); werr != nil {
			return
		}
	}

	// Optional: push padding bytes (an empty unmasked text frame) BEFORE
	// the client sends its first frame. This stresses the upstream byte-
	// tap continuity hypothesis: any bytes the upstream's http1 bufio.Reader
	// consumed past the 101's trailing CRLFCRLF would otherwise be lost at
	// DetachStream time (no PrepareSwap on the upstream side).
	if opts.pushPaddingPostHandshake {
		// Briefly wait so the proxy has time to observe the 101 and begin
		// its swap orchestration before the padding frame lands on wire.
		// Too short → padding races the proxy's 101 forward; too long →
		// the proxy may consider the swap stable. 2ms empirically
		// reproduces the race window on a Linux loopback under -race.
		time.Sleep(2 * time.Millisecond)
		// 0x81 = FIN + text opcode; 0x00 = unmasked + zero payload length.
		// Server frames in RFC 6455 are unmasked. The empty frame is the
		// minimal valid WS frame that mimics edge-pushed liveness traffic.
		if _, werr := c.Write([]byte{0x81, 0x00}); werr != nil {
			return
		}
	}
	_ = c.SetWriteDeadline(time.Time{})
	_ = c.SetReadDeadline(time.Time{})

	// Echo loop: identical shape to serveWSEchoOverH1 in
	// wss_h1_h1upstream_integration_test.go. opts.separateInnerEcho is a
	// v2 hook — currently v1 reuses the same goroutine for determinism.
	for {
		_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
		f, ferr := ws.ReadFrame(br)
		if ferr != nil {
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
		if werr := ws.WriteFrame(c, echo); werr != nil {
			return
		}
		_ = c.SetWriteDeadline(time.Time{})
	}
}

// computeWSAcceptUSK841 returns the Sec-WebSocket-Accept header value per
// RFC 6455 §1.3. Local copy mirroring computeWSAcceptUSK839 — keeping a
// per-issue copy avoids cross-issue coupling when one of these files
// retires or moves to a shared helper module.
func computeWSAcceptUSK841(key string) string {
	const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New() //nolint:gosec // RFC 6455 mandates SHA-1
	_, _ = io.WriteString(h, key)
	_, _ = io.WriteString(h, magic)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------------------
// Shared scaffolding: cross-file dependencies on USK-839's per-test plumbing.
// ---------------------------------------------------------------------------
//
// The test re-uses startWSH1H2AdvertProxy, driveWSEchoThroughProxyH1,
// summarizeStreams, hasWSStreamWithFlows, wsFlowHasNonEmptyRaw, wsEchoHits,
// and newWSEchoHits from wss_h1_h1upstream_integration_test.go (same
// package). Both files build under //go:build e2e — the smoke file (the
// USK-839 one) carries plain `e2e` and the exhaustive file (this one)
// carries `e2e && !e2e_smoke`. Under `make test-e2e` both are linked; under
// `make test-e2e-smoke` only the USK-839 file is linked, and this file's
// symbols are absent from the binary — that is the intended exclusion.
// The USK-839 file does NOT depend on this file, so the smoke tier
// remains a strict subset of the full tier per USK-728.
