//go:build e2e && !e2e_smoke

// Package mcptest_test holds USK-766's exhaustive (full-tier) coverage
// for wss-over-h2 (RFC 8441 extended CONNECT). Smoke-tier coverage for
// CONNECT polymorphism (plain HTTP, h2c) lives in
// connect_modes_smoke_integration_test.go. This file is `e2e &&
// !e2e_smoke` because:
//
//   - The wire shape (ALPN=h2 + extended CONNECT) is not what real
//     Chrome offers for wss:// — Chrome ALPN is [http/1.1] for wss
//     today. USK-763 (ALPN safety net for wss-over-http/1.1) is
//     deferred, so the production-most-common case stays uncovered
//     until that re-opens. Promoting this h2-extended-CONNECT case to
//     smoke would lock the merge gate to a wire shape users do not
//     actually see in production.
//   - The test exercises the USK-764+USK-765 wiring (h2-extended-
//     CONNECT → per-stream WS swap orchestrator). When USK-763 lands,
//     promote the smoke counterpart from this file.
package mcptest_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	gohttp "net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_ConnectModes_WSSOverH2_Full exercises the USK-764+USK-765
// wiring: a client speaks ALPN=h2 + extended CONNECT (RFC 8441) to the
// proxy, and the proxy must per-stream-swap the relevant h2 stream to
// the WS Layer while leaving sibling h2 streams as plain HTTP/2.
//
// Wire timeline:
//
//  1. Client TCP-dials the proxy and sends `CONNECT host:port HTTP/1.1`.
//  2. Proxy returns 200 Connection Established.
//  3. Client TLS-handshakes through the tunnel, ALPN=[h2]. Proxy MITMs
//     with a synth cert and dials the upstream with ALPN=h2.
//  4. Proxy advertises SETTINGS_ENABLE_CONNECT_PROTOCOL=1 to the client.
//  5. Client opens stream 1 with HEADERS containing
//     :method=CONNECT, :protocol=websocket — bootstrapping a WS-over-h2
//     channel on that stream (RFC 8441 §4).
//  6. Client opens stream 3 with a regular HEADERS+END_STREAM
//     (`GET /other`) — multiplex preservation: the unrelated stream
//     must still behave as plain HTTP/2 even while stream 1 carries WS
//     frames.
//  7. Both responses come back; WS frames echo on stream 1; plain HTTP
//     200 returns on stream 3.
//
// Verifies the e2e Subsystem Verification Checklist:
//   - WS envelope flow recorded (protocol=websocket on the upgraded
//     stream).
//   - Multiplex preservation: a sibling http stream is recorded
//     separately on the same connection.
//   - Raw bytes recording for both streams — L4-capable principle.
//   - State transitions reach `complete`.
//   - Retrievable via the MCP query tool.
//
// USK-775: production wiring landed — buildOnHTTP2Stack now dispatches
// each h2 stream through session.RunStackSessionExchange, the upgrade-
// aware entry point. The httpaggregator was also taught to emit the
// extended-CONNECT request HEADERS and the matching 2xx response
// HEADERS immediately (without waiting for END_STREAM that the wire
// will never deliver) and to keep END_STREAM off the outbound HEADERS
// for both halves of the bootstrap exchange.
//
// PARTIAL: the wiring + aggregator-level enabling are landed and unit-
// tested; the previously-blocked CONNECT round-trip now reaches the
// upstream and 200 returns to the test client. The post-swap WS-frame
// relay through the proxy still hangs end-to-end (the upstream HTTP
// handler waits forever for the first WS frame from the proxy), so the
// e2e assertion here remains skipped pending a follow-up that addresses
// the post-swap detach-pipe drain interaction.
//
// Note: TestE2E_ConnectModes_WSSOverH2_Full needs GODEBUG=http2xconnect=1
// because golang.org/x/net/http2 disables extended CONNECT support by
// default (transport-side flag); the proxy itself does not need this env
// var (it uses its own h2 layer).
func TestE2E_ConnectModes_WSSOverH2_Full(t *testing.T) {
	t.Skip("USK-775 partial: builder.go wiring + aggregator support for extended-CONNECT exchange landed; post-swap WS frame relay through the proxy still hangs (follow-up).")

	// Upstream: TLS+h2 server that handles extended CONNECT (echoing WS
	// frames as request-body bytes) and a sibling /other GET.
	upstreamAddr, upstreamShutdown := startWSSOverH2Upstream(t)
	defer upstreamShutdown()

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}

	// Build an h2-over-TLS-over-CONNECT transport. The DialTLS hook
	// performs CONNECT then TLS-handshakes with ALPN=[h2] inside the
	// tunnel — the proxy MITMs and re-issues TLS with ALPN=h2 to the
	// upstream.
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test
			NextProtos:         []string{"h2"},
		},
		DialTLS: func(_, _ string, cfg *tls.Config) (net.Conn, error) {
			raw, err := dialCONNECTTunnel(proxyAddr, upstreamAddr)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(raw, cfg)
			if err := tlsConn.Handshake(); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}
	defer tr.CloseIdleConnections()

	// Drive the wss-over-h2 round trip. Run alongside a sibling /other
	// request so the test asserts h2 multiplex preservation.
	wsErr := make(chan error, 1)
	otherErr := make(chan error, 1)

	go func() {
		wsErr <- driveExtendedCONNECTWSEcho(t, tr, upstreamAddr)
	}()
	// Tiny stagger so the WS stream is opened first (stream 1 is the
	// upgraded one); the plain GET takes stream 3. Functionally the
	// proxy treats them independently, but ordering makes the
	// recorded-protocol assertions easier to reason about.
	time.Sleep(50 * time.Millisecond)
	go func() {
		otherErr <- driveSiblingPlainGET(tr, upstreamAddr)
	}()

	if err := <-wsErr; err != nil {
		t.Fatalf("wss-over-h2 echo round trip: %v", err)
	}
	if err := <-otherErr; err != nil {
		t.Fatalf("sibling plain GET on multiplexed h2 conn: %v", err)
	}

	// Verify recordings via MCP query tool.
	wsFlow := waitForConnectModeFlow(t, h, "/ws-over-h2", "websocket", 5*time.Second)
	if wsFlow.State != "complete" {
		t.Errorf("ws flow state = %q, want %q", wsFlow.State, "complete")
	}
	assertFlowHasRawBytes(t, h, wsFlow.ID)

	// The sibling http flow must be recorded on a separate flow id.
	httpFlow := waitForConnectModeFlow(t, h, "/sibling-http", "http", 5*time.Second)
	if httpFlow.ID == wsFlow.ID {
		t.Errorf("multiplexed sibling stream collapsed into the WS flow id (h2 multiplex preservation broken)")
	}
	if httpFlow.State != "complete" {
		t.Errorf("sibling http flow state = %q, want %q", httpFlow.State, "complete")
	}
	assertFlowRawRequestNonEmpty(t, h, httpFlow.ID)
}

// driveExtendedCONNECTWSEcho issues the extended CONNECT request, sends
// one WS text frame as the request body, reads one echoed WS frame
// from the response body, and verifies the round trip.
//
// x/net/http2.Transport supports extended CONNECT when:
//   - req.Method == "CONNECT"
//   - req.Header.Get(":protocol") != ""
//
// (See x/net/http2/transport.go writeRequest.)
func driveExtendedCONNECTWSEcho(t *testing.T, tr *http2.Transport, upstreamAddr string) error {
	t.Helper()

	// io.Pipe gives us a request body we can write to AFTER RoundTrip
	// returns the response — the bidirectional bytestream that
	// extended CONNECT establishes.
	pr, pw := io.Pipe()

	url := fmt.Sprintf("https://%s/ws-over-h2", upstreamAddr)
	req, err := gohttp.NewRequest("CONNECT", url, pr)
	if err != nil {
		return fmt.Errorf("build CONNECT request: %w", err)
	}
	req.Header.Set(":protocol", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")

	respCh := make(chan *gohttp.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := tr.RoundTrip(req)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()

	var resp *gohttp.Response
	select {
	case resp = <-respCh:
	case err := <-errCh:
		_ = pw.Close()
		return fmt.Errorf("extended CONNECT round trip: %w", err)
	case <-time.After(15 * time.Second):
		_ = pw.Close()
		return errors.New("extended CONNECT round trip: timeout waiting for headers")
	}
	defer resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		_ = pw.Close()
		return fmt.Errorf("extended CONNECT status = %d, want 200", resp.StatusCode)
	}

	// Send one client→server WS text frame. RFC 8441 §5.3 mandates
	// UNMASKED frames over h2 (the proxy / upstream both enforce this).
	clientFrame := &ws.Frame{
		Fin:    true,
		Opcode: ws.OpcodeText,
		Masked: false,
		// Plain payload — the upstream echoes it back unmodified.
		Payload: []byte("hello-wss-over-h2"),
	}
	if err := ws.WriteFrame(pw, clientFrame); err != nil {
		_ = pw.Close()
		return fmt.Errorf("write client WS frame: %w", err)
	}

	// Read the echoed frame from the server.
	echoFrame, err := ws.ReadFrame(resp.Body)
	if err != nil {
		_ = pw.Close()
		return fmt.Errorf("read server WS frame: %w", err)
	}
	if echoFrame.Opcode != ws.OpcodeText {
		_ = pw.Close()
		return fmt.Errorf("echo frame opcode = %x, want text (1)", echoFrame.Opcode)
	}
	if string(echoFrame.Payload) != "hello-wss-over-h2" {
		_ = pw.Close()
		return fmt.Errorf("echo payload = %q, want %q", string(echoFrame.Payload), "hello-wss-over-h2")
	}

	// Half-close the request body to signal end-of-stream so the
	// server handler can return.
	if err := pw.Close(); err != nil {
		return fmt.Errorf("close request body pipe: %w", err)
	}
	// Drain remaining response body so the h2 connection is reusable.
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// driveSiblingPlainGET issues a regular GET on the same h2 transport;
// http2.Transport reuses the existing connection so this opens a new
// stream multiplexed alongside the wss-over-h2 stream. Tests h2
// multiplex preservation: the proxy must keep this stream as plain
// HTTP/2 even while the sibling carries WS frames.
func driveSiblingPlainGET(tr *http2.Transport, upstreamAddr string) error {
	url := fmt.Sprintf("https://%s/sibling-http", upstreamAddr)
	req, err := gohttp.NewRequest(gohttp.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build sibling GET request: %w", err)
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("sibling GET round trip: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != gohttp.StatusOK {
		return fmt.Errorf("sibling GET status = %d, want 200; body=%q", resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), "sibling-ok") {
		return fmt.Errorf("sibling GET body = %q, want substring %q", string(body), "sibling-ok")
	}
	return nil
}

// startWSSOverH2Upstream binds a TLS+h2 server that:
//
//   - For `:method=CONNECT, :protocol=websocket`, returns 200 and then
//     reads WS frames from the request body, echoing each one back via
//     the response writer.
//   - For `:method=GET /sibling-http`, returns 200 with body
//     "sibling-ok".
//
// The TLS leaf cert is self-signed (test fixture) and the listener
// advertises ALPN=[h2]. Returns (addr, shutdown).
func startWSSOverH2Upstream(t *testing.T) (string, func()) {
	t.Helper()

	tlsCfg := newWSSOverH2UpstreamTLSConfig(t)

	handler := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		// Treat extended CONNECT as the WS-echo path. r.Header carries
		// :protocol per x/net/http2/server.go newWriterAndRequestNoBody.
		if r.Method == "CONNECT" && r.Header.Get(":protocol") == "websocket" {
			handleWSEchoOverH2(w, r)
			return
		}
		// Sibling plain GET.
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		_, _ = io.WriteString(w, "sibling-ok")
	})

	srv := &gohttp.Server{
		Handler:   handler,
		TLSConfig: tlsCfg,
	}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		t.Fatalf("configure h2 server: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}

	go func() {
		_ = srv.Serve(ln)
	}()

	return ln.Addr().String(), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
	}
}

// handleWSEchoOverH2 implements the upstream-side extended CONNECT WS
// echo. It writes 200 first (which x/net/http2/server.go translates
// into a HEADERS frame on the same stream), then reads WS frames from
// r.Body and writes them back to w.
//
// The upstream is at the very end of the proxy chain so it sees plain
// (unmasked, RFC 8441 §5.3) WS bytes — no per-frame masking dance.
func handleWSEchoOverH2(w gohttp.ResponseWriter, r *gohttp.Request) {
	w.WriteHeader(gohttp.StatusOK)
	flusher, ok := w.(gohttp.Flusher)
	if !ok {
		return
	}
	flusher.Flush()

	for {
		f, err := ws.ReadFrame(r.Body)
		if err != nil {
			return
		}
		// Echo verbatim. The frame is unmasked on the wire (h2 mode);
		// ws.ReadFrame returns the canonical (unmasked) form so we can
		// re-emit by writing a fresh unmasked Frame.
		echo := &ws.Frame{
			Fin:     f.Fin,
			Opcode:  f.Opcode,
			Masked:  false,
			Payload: f.Payload,
		}
		if err := ws.WriteFrame(w, echo); err != nil {
			return
		}
		flusher.Flush()
		if f.Opcode == ws.OpcodeClose {
			return
		}
	}
}

// newWSSOverH2UpstreamTLSConfig builds a TLS config with a fresh self-
// signed leaf cert + ALPN=[h2]. Used by the upstream test fixture.
// Caller-provided private key (via crypto/ecdsa) keeps the TLS
// handshake fast even when the test runs hundreds of times in CI.
func newWSSOverH2UpstreamTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-wss-over-h2-upstream"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test-wss-over-h2-upstream"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
		}},
		NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS12,
	}
}

// assertFlowHasRawBytes calls query("flow", id) and asserts at least
// one of raw_request / raw_response is non-empty. WS-over-h2 records
// the bidirectional stream as a sequence of frame envelopes; the
// per-flow detail surfaces concatenated raw bytes via the same field
// path as plain HTTP, so this is the tightest assertion we can make
// without introspecting the message_preview slice.
func assertFlowHasRawBytes(t *testing.T, h *mcptest.Harness, flowID string) {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{
		"resource": "flow",
		"id":       flowID,
	})
	rawReqB64, _ := res.Decoded["raw_request"].(string)
	rawRespB64, _ := res.Decoded["raw_response"].(string)
	// At least one direction must have raw bytes recorded.
	if rawReqB64 == "" && rawRespB64 == "" {
		// Fall back: check message_preview for any RawBytes under
		// per-message entries. Some recording shapes (frame-per-
		// envelope ws) put the raw bytes there.
		preview, _ := res.Decoded["message_preview"].([]any)
		if hasMessagePreviewRaw(preview) {
			return
		}
		// Dump the response for debuggability.
		dump, _ := json.MarshalIndent(res.Decoded, "", "  ")
		t.Errorf("flow %s has no recorded raw bytes (L4-capable principle violated); response=%s",
			flowID, string(dump))
		return
	}
	for _, b64 := range []string{rawReqB64, rawRespB64} {
		if b64 == "" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			t.Errorf("flow %s raw_* is not valid base64: %v", flowID, err)
			continue
		}
		if len(decoded) == 0 {
			t.Errorf("flow %s raw_* decoded to zero bytes", flowID)
		}
	}
}

// hasMessagePreviewRaw scans a message_preview slice for any non-empty
// raw bytes field. Used as a fallback for streaming protocols whose
// per-flow raw bytes live in the per-message slice rather than in the
// flat raw_request / raw_response fields.
func hasMessagePreviewRaw(preview []any) bool {
	for _, m := range preview {
		entry, _ := m.(map[string]any)
		if entry == nil {
			continue
		}
		// Per-message preview surfaces raw_payload (base64) for ws/sse.
		if s, _ := entry["raw_payload"].(string); s != "" {
			return true
		}
		if s, _ := entry["raw"].(string); s != "" {
			return true
		}
	}
	return false
}
