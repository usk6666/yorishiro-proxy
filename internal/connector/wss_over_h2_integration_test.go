//go:build e2e && !e2e_smoke

package connector_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"os"
	"strings"
	"testing"
	"time"

	xhttp2 "golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
)

// ---------------------------------------------------------------------------
// USK-781: wss-over-h2 swap path coverage
//
// The mcptest harness covers the full MCP-tool surface; this connector-
// level test exists so the FullListener wiring for the post-swap WS
// frame relay is exercised independently of the MCP server. The shape
// mirrors TestFullListener_CONNECT_HTTPS_MITM (single CONNECT + bridged
// MITM round-trip) but the inner protocol is HTTP/2 with an RFC 8441
// extended CONNECT (`:method=CONNECT, :protocol=websocket`) on stream 1.
//
// Tagged `e2e && !e2e_smoke` (exhaustive tier) per the USK-781 issue
// and the e2e tier policy in CLAUDE.md: the smoke tier targets the
// most-common production wire shapes; wss-over-h2 with ALPN=[h2] is
// exercised on the operator-flagged path (curl --http2, wscat,
// Chrome with --enable-features=WebSocketsOverH2) — Chrome's default
// wss:// ALPN is [http/1.1] today (USK-763, deferred).
// ---------------------------------------------------------------------------

// TestFullListener_CONNECT_WSS_OverH2_MITM verifies the wss-over-h2 swap
// path through FullListener: client opens an h2 stream with extended
// CONNECT inside a CONNECT tunnel, the proxy MITMs both halves and
// runs the per-stream WS swap (USK-781), bidirectional WS frames flow,
// and the upstream HTTP handler observes EOF on r.Body when the client
// half-closes (END_STREAM cascade).
//
// e2e Subsystem Verification Checklist coverage (CLAUDE.md):
//   - Communication success: client sends "hi-ws" -> upstream echoes ->
//     client receives the echo.
//   - Stream recording: at least one Stream with Protocol="ws" exists
//     after the swap, demonstrating RecordStep's protocol retag fired.
//   - Flow recording: send + receive flows are recorded for the WS
//     frames under the same StreamID as the pre-swap CONNECT pair, with
//     non-empty Raw bytes (L4-capable principle).
//   - Error path coverage is exercised separately via session-package
//     unit tests; this connector-level test asserts the positive path
//     only.
func TestFullListener_CONNECT_WSS_OverH2_MITM(t *testing.T) {
	// golang.org/x/net/http2 disables extended CONNECT (RFC 8441) by
	// default; the test driver and the upstream test fixture both rely
	// on it. The flag is read at package init, so it must be in the
	// process environment BEFORE `go test` starts — the Makefile's
	// `test-e2e` target sets it (see Makefile USK-781 note). Skip
	// gracefully when the env var is missing so a developer running
	// `go test` directly gets a useful diagnostic instead of a CANCEL
	// stream error. The proxy itself does not need GODEBUG.
	if !strings.Contains(os.Getenv("GODEBUG"), "http2xconnect=1") {
		t.Skip("requires GODEBUG=http2xconnect=1 (Makefile test-e2e sets it; run via `make test-e2e` or export the env var)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, upstreamShutdown := startWSSOverH2Upstream(t)
	defer upstreamShutdown()

	proxyAddr, store, wg := startFullListenerProxyWithH2(t, ctx)

	// One session goroutine per inbound TCP conn. The h2 transport
	// reuses a single conn for both the WS stream and the half-close
	// END_STREAM, so wg only sees one Done.
	wg.Add(1)

	if err := driveWSSOverH2EchoThroughProxy(proxyAddr, upstreamAddr, "hi-ws"); err != nil {
		t.Fatalf("wss-over-h2 echo through FullListener: %v", err)
	}
	waitSessionDone(t, wg)

	// --- Verify stream recording: post-swap retag landed Protocol="ws". ---
	streams := store.getStreams()
	wsStreams := 0
	for _, st := range streams {
		if st.Protocol == "ws" {
			wsStreams++
		}
	}
	if wsStreams == 0 {
		t.Fatalf("expected at least one Stream with Protocol=ws after wss-over-h2 swap; got streams=%+v", streams)
	}

	// --- Verify flow recording: send + receive flows for the WS frames. ---
	sendFlows := store.flowsByDirection("send")
	recvFlows := store.flowsByDirection("receive")
	if len(sendFlows) == 0 {
		t.Fatal("expected at least one send flow recorded for the wss-over-h2 exchange")
	}
	if len(recvFlows) == 0 {
		t.Fatal("expected at least one receive flow recorded for the wss-over-h2 exchange")
	}

	// --- L4-capable principle: the WS-frame flow MUST carry RawBytes. ---
	// Locate one ws-protocol flow on each direction and assert RawBytes
	// is non-empty - the wire snapshot must survive Pipeline + recorder.
	if !flowHasNonEmptyRawForProtocol(sendFlows, "ws") {
		t.Errorf("no ws-protocol send flow with non-empty RawBytes (L4-capable principle violated)")
	}
	if !flowHasNonEmptyRawForProtocol(recvFlows, "ws") {
		t.Errorf("no ws-protocol receive flow with non-empty RawBytes (L4-capable principle violated)")
	}
}

// flowHasNonEmptyRawForProtocol reports whether any flow in flows
// matches the supplied envelope.Protocol string AND carries non-empty
// RawBytes. The Metadata["protocol"] tag is what RecordStep stamps in
// envelopeToFlow so it is the canonical per-flow protocol marker.
func flowHasNonEmptyRawForProtocol(flows []*flow.Flow, protocol string) bool {
	for _, f := range flows {
		if f == nil {
			continue
		}
		if f.Metadata == nil {
			continue
		}
		if f.Metadata["protocol"] != protocol {
			continue
		}
		if len(f.RawBytes) > 0 {
			return true
		}
	}
	return false
}

// startWSSOverH2Upstream binds a TLS+h2 server that handles RFC 8441
// extended CONNECT by reading WS frames from r.Body and writing them
// back via the response writer. Returns (addr, shutdown). The returned
// shutdown is idempotent.
func startWSSOverH2Upstream(t *testing.T) (string, func()) {
	t.Helper()

	tlsCfg := newWSSOverH2TestTLSConfig(t)

	handler := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		if r.Method != "CONNECT" || r.Header.Get(":protocol") != "websocket" {
			gohttp.Error(w, "not extended CONNECT", gohttp.StatusBadRequest)
			return
		}
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
			echo := &ws.Frame{Fin: f.Fin, Opcode: f.Opcode, Masked: false, Payload: f.Payload}
			if err := ws.WriteFrame(w, echo); err != nil {
				return
			}
			flusher.Flush()
			if f.Opcode == ws.OpcodeClose {
				return
			}
		}
	})

	srv := &gohttp.Server{
		Handler:   handler,
		TLSConfig: tlsCfg,
	}
	if err := xhttp2.ConfigureServer(srv, &xhttp2.Server{}); err != nil {
		t.Fatalf("configure h2 server: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()

	return ln.Addr().String(), func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutdownCancel()
		_ = srv.Shutdown(shutdownCtx)
		_ = ln.Close()
	}
}

// driveWSSOverH2EchoThroughProxy opens a CONNECT tunnel to upstreamAddr
// via proxyAddr, TLS-handshakes with ALPN=[h2] inside the tunnel, opens
// an extended CONNECT request on the resulting h2 transport, sends one
// WS frame containing payload, and verifies the echoed WS frame
// matches. Returns nil on success; an error on any wire mismatch or
// timeout.
func driveWSSOverH2EchoThroughProxy(proxyAddr, upstreamAddr, payload string) error {
	tr := &xhttp2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test
			NextProtos:         []string{"h2"},
		},
		DialTLS: func(_, _ string, cfg *tls.Config) (net.Conn, error) {
			raw, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			if err != nil {
				return nil, err
			}
			req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamAddr, upstreamAddr)
			if _, err := raw.Write([]byte(req)); err != nil {
				_ = raw.Close()
				return nil, err
			}
			buf := make([]byte, 256)
			n, rerr := raw.Read(buf)
			if rerr != nil {
				_ = raw.Close()
				return nil, rerr
			}
			if !strings.Contains(string(buf[:n]), "200") {
				_ = raw.Close()
				return nil, fmt.Errorf("CONNECT failed: %q", string(buf[:n]))
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

	pr, pw := io.Pipe()
	url := fmt.Sprintf("https://%s/", upstreamAddr)
	req, err := gohttp.NewRequest("CONNECT", url, pr)
	if err != nil {
		return fmt.Errorf("build CONNECT request: %w", err)
	}
	req.Header.Set(":protocol", "websocket")

	respCh := make(chan *gohttp.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, rerr := tr.RoundTrip(req)
		if rerr != nil {
			errCh <- rerr
			return
		}
		respCh <- resp
	}()

	var resp *gohttp.Response
	select {
	case resp = <-respCh:
	case rterr := <-errCh:
		_ = pw.Close()
		return fmt.Errorf("extended CONNECT round trip: %w", rterr)
	case <-time.After(15 * time.Second):
		_ = pw.Close()
		return errors.New("extended CONNECT round trip: timeout waiting for headers")
	}
	defer resp.Body.Close()
	if resp.StatusCode != gohttp.StatusOK {
		_ = pw.Close()
		return fmt.Errorf("extended CONNECT status = %d, want 200", resp.StatusCode)
	}

	// Send one client->server WS frame (RFC 8441 5.3 mandates UNMASKED
	// frames over h2).
	out := &ws.Frame{Fin: true, Opcode: ws.OpcodeText, Masked: false, Payload: []byte(payload)}
	if err := ws.WriteFrame(pw, out); err != nil {
		_ = pw.Close()
		return fmt.Errorf("write client WS frame: %w", err)
	}
	echo, err := ws.ReadFrame(resp.Body)
	if err != nil {
		_ = pw.Close()
		return fmt.Errorf("read echoed WS frame: %w", err)
	}
	if string(echo.Payload) != payload {
		_ = pw.Close()
		return fmt.Errorf("echo payload = %q, want %q", string(echo.Payload), payload)
	}
	if err := pw.Close(); err != nil {
		return fmt.Errorf("close request body pipe: %w", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

// startFullListenerProxyWithH2 and newWSSOverH2TestTLSConfig were moved to
// h2_test_helpers_test.go (build tag e2e) so the SSE-over-h2 smoke-tier
// test (USK-888) can consume them without duplicating ~150 LOC. The
// behavior is unchanged.
