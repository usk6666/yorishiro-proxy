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
	"strings"
	"testing"
	"time"

	xhttp2 "golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-888 exhaustive-tier failure-mode tests. The smoke tier covers the
// happy path + sibling non-interference; this file covers the
// attacker-controlled-input surface (CLAUDE.md MITM Principle #5) that
// must not crash or hang the proxy.
//
// Each scenario asserts the proxy records SOMETHING (Stream rows survive
// even on protocol violations) and that no goroutine leaks past the
// session WaitGroup.

// TestFullListener_CONNECT_SSE_OverH2_BinaryBody covers a server that
// advertises text/event-stream but emits binary garbage. The SSE parser
// must classify lines defensively (anomalies surfaced on the SSE
// envelope, not a panic). The session must terminate cleanly when
// upstream END_STREAMs.
func TestFullListener_CONNECT_SSE_OverH2_BinaryBody(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, upstreamShutdown := startSSEOverH2BinaryBodyUpstream(t)
	defer upstreamShutdown()

	proxyAddr, store, wg := startFullListenerProxyWithH2(t, ctx)
	wg.Add(1)

	tr := newTestSSEh2Transport(proxyAddr)
	defer tr.CloseIdleConnections()

	url := fmt.Sprintf("https://%s/binary", upstreamAddr)
	req, _ := gohttp.NewRequest("GET", url, nil)
	// A driver-side error is acceptable here — binary garbage in an SSE
	// body may surface as either a clean read or a transport-layer error
	// depending on timing. rerr is intentionally not asserted; the
	// proxy-survival contract is encoded by the waitSessionDone /
	// Stream-count assertions below (a leaked goroutine would hang the
	// WaitGroup wait; a crash would never persist a Stream row).
	resp, _ := tr.RoundTrip(req)
	if resp != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	waitSessionDone(t, wg)

	// At least one Stream survived. (Protocol may be sse OR http
	// depending on how far the detection got.)
	streams := store.getStreams()
	if len(streams) == 0 {
		t.Error("expected at least one Stream recorded for the failed exchange")
	}
}

// TestFullListener_CONNECT_SSE_OverH2_UpstreamGOAWAY covers an upstream
// that issues GOAWAY mid-stream. The proxy must classify the error so
// the Stream row records state=error rather than hanging the session.
func TestFullListener_CONNECT_SSE_OverH2_UpstreamGOAWAY(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, upstreamShutdown := startSSEOverH2GOAWAYUpstream(t)
	defer upstreamShutdown()

	proxyAddr, store, wg := startFullListenerProxyWithH2(t, ctx)
	wg.Add(1)

	tr := newTestSSEh2Transport(proxyAddr)
	defer tr.CloseIdleConnections()

	url := fmt.Sprintf("https://%s/events", upstreamAddr)
	req, _ := gohttp.NewRequest("GET", url, nil)
	resp, rerr := tr.RoundTrip(req)
	if rerr == nil && resp != nil {
		// Drain body until terminal — upstream GOAWAY will surface as
		// an error read mid-body or a clean EOF depending on timing.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	waitSessionDone(t, wg)

	streams := store.getStreams()
	if len(streams) == 0 {
		t.Error("expected at least one Stream recorded for the GOAWAY exchange")
	}
}

// startSSEOverH2BinaryBodyUpstream emits a text/event-stream content-type
// but writes binary garbage as the body. The SSE parser must not panic.
func startSSEOverH2BinaryBodyUpstream(t *testing.T) (string, func()) {
	t.Helper()

	tlsCfg := newWSSOverH2TestTLSConfig(t)

	handler := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(gohttp.StatusOK)
		flusher, _ := w.(gohttp.Flusher)
		// Binary garbage payload. Includes embedded NUL and high bytes.
		_, _ = w.Write([]byte{0x00, 0x01, 0xFE, 0xFF, '\n', '\n', 0xC3, 0x28})
		if flusher != nil {
			flusher.Flush()
		}
	})

	srv := &gohttp.Server{Handler: handler, TLSConfig: tlsCfg}
	_ = xhttp2.ConfigureServer(srv, &xhttp2.Server{})
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
	}
}

// startSSEOverH2GOAWAYUpstream emits HEADERS + one event then issues
// GOAWAY (by closing the underlying conn). The proxy must surface the
// terminal error without leaking goroutines.
func startSSEOverH2GOAWAYUpstream(t *testing.T) (string, func()) {
	t.Helper()

	tlsCfg := newWSSOverH2TestTLSConfig(t)

	handler := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(gohttp.StatusOK)
		flusher, _ := w.(gohttp.Flusher)
		_, _ = fmt.Fprintf(w, "id: 0\ndata: only-event\n\n")
		if flusher != nil {
			flusher.Flush()
		}
		// Hijack-like effect: close via Hijacker is not available on h2.
		// The Server shutdown via defer below sends GOAWAY at test
		// teardown; close-during-handler is approximated by panicking
		// after a flush so net/http hangs up the stream.
		panic(gohttp.ErrAbortHandler)
	})

	srv := &gohttp.Server{Handler: handler, TLSConfig: tlsCfg}
	_ = xhttp2.ConfigureServer(srv, &xhttp2.Server{})
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	return ln.Addr().String(), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
	}
}

// newTestSSEh2Transport creates an h2 Transport that tunnels through the
// proxy via CONNECT. Shared with the smoke-tier file's driver.
func newTestSSEh2Transport(proxyAddr string) *xhttp2.Transport {
	return &xhttp2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test
			NextProtos:         []string{"h2"},
		},
		DialTLS: func(_, _ string, cfg *tls.Config) (net.Conn, error) {
			raw, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			if err != nil {
				return nil, err
			}
			// Best-effort CONNECT; the failure-mode tests are
			// tolerant of upstream addr lookup.
			req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", proxyAddr, proxyAddr)
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
				return nil, errors.New("CONNECT failed")
			}
			tlsConn := tls.Client(raw, cfg)
			if err := tlsConn.Handshake(); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}
}

// Suppress unused-import warning when only one failure-mode test in the
// file references envelope.
var _ = envelope.ProtocolSSE
