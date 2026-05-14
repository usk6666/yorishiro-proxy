//go:build e2e

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

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-888 happy-path e2e: SSE-over-h2 detection + per-stream sub-stack
// overlay route the upstream's text/event-stream DATA frames to the SSE
// Layer so each event surfaces as its own Envelope. After the fix the
// Stream is retagged Protocol="sse" and the analyst sees one Send (GET)
// + one Receive (response HEADERS) + one Receive per SSE event in the
// flow store.
//
// The smoke-tier assertion focuses on:
//   - driver round-trip success (h2 GET → SSE events read end-to-end),
//   - Stream rows tagged with Protocol="sse" (RecordStep's protocol
//     retag fired in the SSE swap path).

// TestFullListener_CONNECT_SSE_OverH2_HappyPath drives an h2-over-TLS
// upstream that emits SSE events and asserts the post-USK-888 wiring:
// the proxy detects text/event-stream at HEADERS time, runs the per-
// stream SSE sub-stack overlay, and projects one Stream tagged
// Protocol="sse".
func TestFullListener_CONNECT_SSE_OverH2_HappyPath(t *testing.T) {
	if !strings.Contains(os.Getenv("GODEBUG"), "http2xconnect=1") {
		// Not strictly required for this test path (we do not use extended
		// CONNECT) but kept aligned with TestFullListener_CONNECT_WSS_OverH2_MITM
		// so the same `make test-e2e` env applies to both.
		t.Logf("note: GODEBUG=http2xconnect=1 not set (only required for extended CONNECT; SSE-over-h2 runs fine without it)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, upstreamShutdown := startSSEOverH2Upstream(t)
	defer upstreamShutdown()

	proxyAddr, store, wg := startFullListenerProxyWithH2(t, ctx)

	wg.Add(1)

	if err := driveSSEOverH2ThroughProxy(proxyAddr, upstreamAddr, 3); err != nil {
		t.Fatalf("sse-over-h2 through FullListener: %v", err)
	}
	waitSessionDone(t, wg)

	// --- Stream recording: post-swap retag landed Protocol=sse.
	streams := store.getStreams()
	sseStreams := 0
	for _, st := range streams {
		if st.Protocol == string(envelope.ProtocolSSE) {
			sseStreams++
		}
	}
	if sseStreams == 0 {
		t.Fatalf("expected at least one Stream with Protocol=sse after SSE-over-h2 swap; got streams=%+v", streams)
	}

	// --- Flow recording: at least one Receive flow on the SSE protocol
	// must be projected so plugins / intercept / record observe the
	// per-event envelopes.
	recvFlows := store.flowsByDirection("receive")
	sseRecv := 0
	for _, f := range recvFlows {
		if f == nil || f.Metadata == nil {
			continue
		}
		if f.Metadata["protocol"] == string(envelope.ProtocolSSE) {
			sseRecv++
		}
	}
	if sseRecv == 0 {
		t.Errorf("expected at least one SSE Receive flow; recvFlows=%d", len(recvFlows))
	}
}

// startSSEOverH2Upstream binds a TLS+h2 server that streams a few SSE events
// then closes the stream. Returns (addr, shutdown).
func startSSEOverH2Upstream(t *testing.T) (string, func()) {
	t.Helper()

	tlsCfg := newWSSOverH2TestTLSConfig(t)

	handler := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		if r.URL.Path != "/events" {
			gohttp.Error(w, "not found", gohttp.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(gohttp.StatusOK)
		flusher, ok := w.(gohttp.Flusher)
		if !ok {
			return
		}
		flusher.Flush()
		for i := 0; i < 3; i++ {
			fmt.Fprintf(w, "id: %d\ndata: event-%d\n\n", i, i)
			flusher.Flush()
		}
		// Server closes stream; client should observe end-of-stream.
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

// driveSSEOverH2ThroughProxy opens a CONNECT tunnel via the proxy, then runs
// an h2 GET /events through it. Reads up to numEvents from the response body
// (line-oriented; SSE events are separated by blank lines). Returns nil on
// success.
func driveSSEOverH2ThroughProxy(proxyAddr, upstreamAddr string, numEvents int) error {
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

	url := fmt.Sprintf("https://%s/events", upstreamAddr)
	req, err := gohttp.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("build GET request: %w", err)
	}
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
		return fmt.Errorf("h2 GET round trip: %w", rterr)
	case <-time.After(15 * time.Second):
		return errors.New("h2 GET: timeout waiting for headers")
	}
	defer resp.Body.Close()
	if resp.StatusCode != gohttp.StatusOK {
		return fmt.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		return fmt.Errorf("Content-Type = %q, want text/event-stream", ct)
	}

	// Read body until we observe numEvents blank-line separators OR EOF.
	buf := make([]byte, 4096)
	deadline := time.After(10 * time.Second)
	for {
		select {
		case <-deadline:
			return errors.New("driveSSEOverH2ThroughProxy: timeout reading body")
		default:
		}
		// Per-read deadline via the connection is not exposed by h2
		// Transport; the outer deadline above bounds the total wait.
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			events := strings.Count(string(buf[:n]), "\n\n")
			if events >= numEvents {
				return nil
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return nil
			}
			return fmt.Errorf("body read: %w", rerr)
		}
	}
}
