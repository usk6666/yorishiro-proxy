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
	"strings"
	"sync"
	"testing"
	"time"

	xhttp2 "golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// TestFullListener_CONNECT_SSE_OverH2_SiblingNonInterference exercises the
// RFC-001 §3.4.1 multiplex-isolation MUST in the USK-888 wiring: a single
// h2 connection multiplexing one SSE stream (text/event-stream) AND one
// regular JSON stream (application/json) on the SAME connection must
// record both correctly. Concretely:
//
//   - the JSON stream's response body must round-trip intact,
//   - the SSE stream's events must reach the client and be recorded
//     under Protocol=sse,
//   - releasing the SSE sub-stack at terminal state must not affect
//     the JSON stream's connection-level h2 framing.
func TestFullListener_CONNECT_SSE_OverH2_SiblingNonInterference(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, upstreamShutdown := startSSEOverH2MultiUpstream(t)
	defer upstreamShutdown()

	proxyAddr, store, wg := startFullListenerProxyWithH2(t, ctx)

	// Two streams on the SAME h2 connection through ONE CONNECT, so the
	// onHTTP2Stack callback (which wg.Done()s on connection exit) fires
	// once total.
	wg.Add(1)

	// Capture the underlying TLS conns DialTLS returns so we can force-
	// close them after grp.Wait(). tr.CloseIdleConnections() alone races
	// with xhttp2.Transport's internal "is this conn idle?" bookkeeping
	// — under CI load the two response readers may not have released the
	// conn to the pool by the time the test calls CloseIdleConnections,
	// so the proxy's clientL.Channels() never observes a remote close
	// and the onHTTP2Stack callback hangs until ctx timeout. Closing the
	// underlying conn directly is deterministic.
	var (
		h2ConnsMu sync.Mutex
		h2Conns   []net.Conn
	)
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
			h2ConnsMu.Lock()
			h2Conns = append(h2Conns, tlsConn)
			h2ConnsMu.Unlock()
			return tlsConn, nil
		},
	}
	defer tr.CloseIdleConnections()

	var grp sync.WaitGroup
	grp.Add(2)

	var jsonErr error
	go func() {
		defer grp.Done()
		url := fmt.Sprintf("https://%s/json", upstreamAddr)
		req, err := gohttp.NewRequest("GET", url, nil)
		if err != nil {
			jsonErr = fmt.Errorf("build /json: %w", err)
			return
		}
		resp, rerr := tr.RoundTrip(req)
		if rerr != nil {
			jsonErr = fmt.Errorf("/json RT: %w", rerr)
			return
		}
		defer resp.Body.Close()
		buf, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(buf), "json-ok") {
			jsonErr = fmt.Errorf("/json body = %q, want json-ok", string(buf))
		}
	}()

	var sseErr error
	go func() {
		defer grp.Done()
		url := fmt.Sprintf("https://%s/events", upstreamAddr)
		req, err := gohttp.NewRequest("GET", url, nil)
		if err != nil {
			sseErr = fmt.Errorf("build /events: %w", err)
			return
		}
		resp, rerr := tr.RoundTrip(req)
		if rerr != nil {
			sseErr = fmt.Errorf("/events RT: %w", rerr)
			return
		}
		defer resp.Body.Close()
		// Accumulate the full body before counting "\n\n" boundaries.
		// A per-read strings.Count miscounts when an event terminator
		// straddles two Read returns ("...\n" then "\n..."). Reading
		// until EOF also lets the upstream END_STREAM propagate
		// naturally, so the proxy's SSE goroutine exits via a clean
		// uR EOF rather than via client-initiated RST_STREAM(CANCEL)
		// from defer body.Close on a partially-read stream.
		var collected strings.Builder
		buf := make([]byte, 4096)
		deadline := time.After(10 * time.Second)
		for {
			select {
			case <-deadline:
				sseErr = errors.New("/events read timeout")
				return
			default:
			}
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				collected.Write(buf[:n])
			}
			if rerr != nil {
				if !errors.Is(rerr, io.EOF) {
					sseErr = fmt.Errorf("/events read: %w", rerr)
					return
				}
				break
			}
		}
		events := strings.Count(collected.String(), "\n\n")
		if events < 3 {
			sseErr = fmt.Errorf("/events: read %d events, want 3 (body=%q)", events, collected.String())
		}
	}()

	grp.Wait()
	if jsonErr != nil {
		t.Errorf("json stream: %v", jsonErr)
	}
	if sseErr != nil {
		t.Errorf("sse stream: %v", sseErr)
	}
	// Force-close the captured underlying TLS conns so the proxy's
	// onHTTP2Stack observes the client h2 conn close deterministically
	// and exits its for-select loop, firing the deferred wg.Done().
	// tr.CloseIdleConnections() also runs (deferred above) but is not
	// sufficient on its own under CI scheduling — see h2ConnsMu comment.
	h2ConnsMu.Lock()
	for _, c := range h2Conns {
		_ = c.Close()
	}
	h2ConnsMu.Unlock()
	waitSessionDone(t, wg)

	// Assert recording: at least one Protocol=sse stream AND at least one
	// HTTP Stream that is NOT Protocol=sse (the JSON sibling, recorded
	// under Protocol=http).
	streams := store.getStreams()
	sseStreams, otherStreams := 0, 0
	for _, st := range streams {
		switch st.Protocol {
		case string(envelope.ProtocolSSE):
			sseStreams++
		case string(envelope.ProtocolHTTP), "":
			otherStreams++
		}
	}
	if sseStreams == 0 {
		t.Errorf("expected at least one Protocol=sse stream, got %d", sseStreams)
	}
	if otherStreams == 0 {
		t.Errorf("expected at least one non-sse stream (sibling JSON), got %d", otherStreams)
	}
}

// startSSEOverH2MultiUpstream binds a TLS+h2 server that serves both
// /events (SSE) and /json (regular JSON response) so a single test
// driver can exercise multiplex isolation. Returns (addr, shutdown).
func startSSEOverH2MultiUpstream(t *testing.T) (string, func()) {
	t.Helper()

	tlsCfg := newWSSOverH2TestTLSConfig(t)

	mux := gohttp.NewServeMux()
	mux.HandleFunc("/events", func(w gohttp.ResponseWriter, r *gohttp.Request) {
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
	})
	mux.HandleFunc("/json", func(w gohttp.ResponseWriter, _ *gohttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"json-ok"}`))
	})

	srv := &gohttp.Server{
		Handler:   mux,
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
