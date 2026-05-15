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
	"sync/atomic"
	"testing"
	"time"

	xhttp2 "golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-903 e2e: SSE-over-HTTP/2 client mid-stream cancel must record
// state="complete" + tags["terminated_by"]="client" — symmetric with
// the HTTP/1.1 path covered by TestSSE_ClientCloseBeforeUpstream_StateComplete
// (sse_close_extra_integration_test.go) and the unit-level coverage in
// internal/proxybuild/oncomplete_error_test.go.
//
// This is the production-path regression guard: the chain runs through
// ALPN h2 negotiation → CONNECT tunnel → per-stream sub-stack overlay
// (runUpgradeSSEOverH2) → driveSSEEventLoop → http2.detachWriter.Write
// → http2.ErrWriterClosed. Without the USK-903 fix the recorded Stream
// would have state="error" + tags["error"]="...http2: writer closed".

// TestFullListener_CONNECT_SSE_OverH2_ClientCancel_StateCompleteWithTag
// drives an h2 SSE upstream that streams indefinitely, then cancels the
// client request after one event arrives. The proxy must record the
// flow as state=complete + tags["terminated_by"]="client" — preserving
// the wire-observed cancellation as queryable attribution rather than
// surfacing it as a false-positive error.
func TestFullListener_CONNECT_SSE_OverH2_ClientCancel_StateCompleteWithTag(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, upstreamShutdown := startSSEOverH2InfiniteUpstream(t)
	defer upstreamShutdown()

	proxyAddr, store, wg := startFullListenerProxyWithH2(t, ctx)
	wg.Add(1)

	clientCtx, clientCancel := context.WithCancel(ctx)
	driveErr := driveSSEOverH2ThroughProxyWithCancel(clientCtx, proxyAddr, upstreamAddr, clientCancel)
	// Either RoundTrip-then-context-cancel-mid-Read (clean cancel) or a
	// canceled-context error from the transport are both acceptable —
	// the assertion is on the recorded Stream, not the client driver's
	// return value.
	if driveErr != nil && !errors.Is(driveErr, context.Canceled) {
		// A transport-level error wrapping context.Canceled is normal.
		// Don't fail the test on it; the wire observation is what matters.
		t.Logf("client driver returned (acceptable): %v", driveErr)
	}

	waitSessionDone(t, wg)

	// Locate the SSE Stream produced by the swap.
	streams := store.getStreams()
	var sseStream *struct {
		state string
		tags  map[string]string
	}
	for _, st := range streams {
		if st.Protocol == string(envelope.ProtocolSSE) {
			sseStream = &struct {
				state string
				tags  map[string]string
			}{state: st.State, tags: st.Tags}
			break
		}
	}
	if sseStream == nil {
		t.Fatalf("no SSE Stream recorded after client cancel; streams=%+v", streams)
	}

	if sseStream.state != "complete" {
		t.Errorf("Stream.State = %q, want %q (USK-903: client cancel must project state=complete, matching H/1.1)", sseStream.state, "complete")
	}
	if got := sseStream.tags["terminated_by"]; got != "client" {
		t.Errorf("Stream.Tags[\"terminated_by\"] = %q, want %q (USK-903 attribution)", got, "client")
	}
	// Regression guard: must NOT carry tags["error"] (the bug's symptom).
	if got, present := sseStream.tags["error"]; present {
		t.Errorf("Stream.Tags[\"error\"] = %q present; want absent (client-cancel must not surface as error)", got)
	}
}

// startSSEOverH2InfiniteUpstream binds an h2-over-TLS server that
// streams an SSE event every 50ms indefinitely until the per-stream
// context is canceled. Used by USK-903's client-cancel test so the
// session terminates because the CLIENT closed, not because the upstream
// ended naturally.
func startSSEOverH2InfiniteUpstream(t *testing.T) (string, func()) {
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
		// Stream events every 50ms until the request context terminates.
		// h2 propagates client-side cancellation as RST_STREAM(CANCEL) →
		// the request context fires → this loop exits cleanly.
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for i := 0; ; i++ {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
				if _, werr := fmt.Fprintf(w, "id: %d\ndata: tick-%d\n\n", i, i); werr != nil {
					return
				}
				flusher.Flush()
			}
			if i > 1000 {
				return // safety cap
			}
		}
	})

	srv := &gohttp.Server{Handler: handler, TLSConfig: tlsCfg}
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

// driveSSEOverH2ThroughProxyWithCancel opens a CONNECT tunnel via the
// proxy and runs an h2 GET /events through it. After the first event
// arrives, calls cancel to abort the request mid-stream — exactly
// reproducing the curl --max-time-style scenario in the USK-903 Issue.
//
// Returns whatever the transport surfaces; the caller decides whether to
// fail on it. The wire-observed result (recorded Stream state + tags)
// is the authoritative assertion target.
func driveSSEOverH2ThroughProxyWithCancel(
	ctx context.Context,
	proxyAddr, upstreamAddr string,
	cancel context.CancelFunc,
) error {
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
	req, err := gohttp.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("build GET request: %w", err)
	}

	resp, rerr := tr.RoundTrip(req)
	if rerr != nil {
		return fmt.Errorf("h2 GET round trip: %w", rerr)
	}
	defer resp.Body.Close()
	if resp.StatusCode != gohttp.StatusOK {
		return fmt.Errorf("status = %d, want 200", resp.StatusCode)
	}

	// Read until at least one full event arrives, then cancel the
	// request context to simulate curl --max-time.
	gotEvent := atomic.Bool{}
	go func() {
		// Allow the response body up to 2s to deliver the first event,
		// then trigger the cancel regardless. This bounds the test
		// even if the upstream's first flush is slow.
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			return
		}
		if !gotEvent.Load() {
			cancel() // safety-net cancel after 2s
		}
	}()

	buf := make([]byte, 4096)
	for i := 0; i < 4; i++ {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			gotEvent.Store(true)
		}
		if rerr != nil {
			break
		}
		if i == 0 {
			// First event delivered — cancel mid-stream now.
			cancel()
		}
	}
	// Drain any residual error from Body.Close path.
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}
