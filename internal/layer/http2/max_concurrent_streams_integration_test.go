//go:build e2e && !e2e_smoke

package http2_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	nethttp "net/http"
	"testing"
	"time"

	intHTTP2 "github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	h2frame "github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	h2hpack "github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// USK-713: Cap the per-connection HTTP/2 stream concurrency on the
// client-facing Layer via BuildConfig.MaxConcurrentStreams. This test
// drives a low-level H2 client (raw frame I/O over a CONNECT tunnel)
// to bypass the standard library's automatic adherence to the peer-
// advertised MAX_CONCURRENT_STREAMS limit and force the proxy's
// REFUSED_STREAM enforcement path.

// TestMaxConcurrentStreams_AdvertisedAndEnforced exercises the full
// chain: BuildConfig.MaxConcurrentStreams = 2 → SETTINGS frame
// advertises MAX_CONCURRENT_STREAMS=2 to the client → opening a 3rd
// concurrent stream is rejected with RST_STREAM(REFUSED_STREAM) per
// RFC 9113 §5.1.2.
//
// The first two streams are kept open by withholding END_STREAM on the
// HEADERS so the proxy's stream counter stays at 2 when the third
// HEADERS arrives. The upstream is a long-running TLS HTTP/2 server
// whose handler blocks until the test finishes, so the proxy's
// session-level processing of streams 1 and 2 stays parked (active
// stream count != 0) while the third HEADERS is sent.
func TestMaxConcurrentStreams_AdvertisedAndEnforced(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream: TLS h2 server that blocks each handler invocation until
	// the test signals completion. Keeps every accepted upstream stream
	// alive so the proxy's per-connection active-stream count remains at
	// the advertised cap when the third HEADERS arrives.
	releaseUpstream := make(chan struct{})
	defer close(releaseUpstream)
	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "mcs-cap-marker", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		select {
		case <-releaseUpstream:
		case <-r.Context().Done():
		}
	}))
	defer upShutdown()

	// Build a proxy with MaxConcurrentStreams = 2.
	bcfg := makeBuildCfg(t, nil)
	bcfg.MaxConcurrentStreams = 2
	proxyAddr, _ := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{})

	// Open a CONNECT tunnel to the proxy and wrap it in TLS offering ALPN h2.
	rawConn, err := connectTunnelDialer(proxyAddr, upAddr)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test
		NextProtos:         []string{"h2"},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	defer tlsConn.Close()

	// Send the H2 client preface.
	if _, err := tlsConn.Write([]byte(intHTTP2.ClientPreface)); err != nil {
		t.Fatalf("write preface: %v", err)
	}

	rd := h2frame.NewReader(tlsConn)
	wr := h2frame.NewWriter(tlsConn)

	// Send our (empty) initial SETTINGS so the proxy can finish its
	// preface exchange.
	if err := wr.WriteSettings(nil); err != nil {
		t.Fatalf("write client SETTINGS: %v", err)
	}

	// Read frames until we observe the proxy's SETTINGS frame and verify
	// the advertised SETTINGS_MAX_CONCURRENT_STREAMS = 2. Tolerate any
	// other frames the proxy sends during preface (its own SETTINGS,
	// initial WINDOW_UPDATE, SETTINGS-ACK to ours).
	advertisedMCS := readAdvertisedMaxConcurrentStreams(t, rd, 4*time.Second)
	if advertisedMCS != 2 {
		t.Fatalf("advertised SETTINGS_MAX_CONCURRENT_STREAMS = %d, want 2", advertisedMCS)
	}

	// ACK the proxy's SETTINGS so we are a well-behaved client. The
	// proxy's server-side reader does not strictly require the ACK
	// before processing HEADERS, but sending it keeps the connection
	// state clean.
	if err := wr.WriteSettingsAck(); err != nil {
		t.Fatalf("write SETTINGS ACK: %v", err)
	}

	// Build a HEADERS payload (HPACK-encoded request pseudo-headers).
	// Reuse one encoder so the dynamic-table state is consistent across
	// streams.
	enc := h2hpack.NewEncoder(4096, true)
	headerFragment := func() []byte {
		return enc.Encode([]h2hpack.HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: upAddr},
			{Name: ":path", Value: "/cap-test"},
		})
	}

	// Open streams 1 and 3 (client-initiated stream IDs are odd).
	// Withhold END_STREAM so the proxy's session keeps each stream open.
	// END_HEADERS is set so the HEADERS frame is complete and the proxy's
	// reader transitions the stream into open state.
	for _, sid := range []uint32{1, 3} {
		if err := wr.WriteHeaders(sid, false /*endStream*/, true /*endHeaders*/, headerFragment()); err != nil {
			t.Fatalf("write HEADERS stream %d: %v", sid, err)
		}
	}

	// Allow the proxy to process the first two streams. They are
	// long-running (upstream handler blocks), so the proxy's per-
	// connection active-stream count should hold steady at 2.
	time.Sleep(150 * time.Millisecond)

	// Open stream 5 — the proxy must reject it with REFUSED_STREAM.
	if err := wr.WriteHeaders(5, false /*endStream*/, true /*endHeaders*/, headerFragment()); err != nil {
		t.Fatalf("write HEADERS stream 5: %v", err)
	}

	// Read frames until we see RST_STREAM(REFUSED_STREAM) for stream 5
	// or the deadline fires. The proxy may emit unrelated frames
	// (WINDOW_UPDATE for connection-level flow control, HEADERS or DATA
	// for streams 1/3 if upstream replied) — skip those.
	gotRST := waitForRSTStream(t, tlsConn, rd, 5, intHTTP2.ErrCodeRefusedStream, 4*time.Second)
	if !gotRST {
		t.Fatalf("did not observe RST_STREAM(REFUSED_STREAM) on stream 5 within deadline")
	}
}

// readAdvertisedMaxConcurrentStreams reads frames from rd until a
// non-ACK SETTINGS frame is received, then returns the advertised
// SETTINGS_MAX_CONCURRENT_STREAMS value (or 0 if the frame did not
// include the parameter). Fails the test on read error or timeout.
func readAdvertisedMaxConcurrentStreams(t *testing.T, rd *h2frame.Reader, timeout time.Duration) uint32 {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		f, err := rd.ReadFrame()
		if err != nil {
			t.Fatalf("read frame while waiting for SETTINGS: %v", err)
		}
		if f.Header.Type != h2frame.TypeSettings {
			continue
		}
		if f.Header.Flags.Has(h2frame.FlagAck) {
			continue
		}
		params, perr := f.SettingsParams()
		if perr != nil {
			t.Fatalf("parse SETTINGS: %v", perr)
		}
		for _, p := range params {
			if p.ID == h2frame.SettingMaxConcurrentStreams {
				return p.Value
			}
		}
		// SETTINGS frame without the parameter — treat as "not advertised".
		return 0
	}
	t.Fatalf("did not receive non-ACK SETTINGS frame within %s", timeout)
	return 0
}

// waitForRSTStream reads frames from conn until RST_STREAM is observed
// for streamID with the given error code, or until the timeout fires.
// Returns true on observation, false on timeout. The deadline is applied
// to the underlying conn so a stalled reader does not hang the test
// beyond the requested budget.
func waitForRSTStream(t *testing.T, conn deadlineReader, rd *h2frame.Reader, streamID, wantCode uint32, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	if err := conn.SetReadDeadline(deadline); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	for time.Now().Before(deadline) {
		f, err := rd.ReadFrame()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return false
			}
			// Deadline-induced read error → exited the loop without
			// seeing the expected frame.
			return false
		}
		if f.Header.Type != h2frame.TypeRSTStream || f.Header.StreamID != streamID {
			continue
		}
		gotCode, perr := f.RSTStreamErrorCode()
		if perr != nil {
			t.Fatalf("parse RST_STREAM: %v", perr)
		}
		if gotCode != wantCode {
			t.Fatalf("RST_STREAM stream %d code = %d, want %d (REFUSED_STREAM)", streamID, gotCode, wantCode)
		}
		return true
	}
	return false
}

// deadlineReader is the deadline-capable subset of net.Conn used by the
// helper above; both *tls.Conn and net.Conn satisfy it.
type deadlineReader interface {
	SetReadDeadline(time.Time) error
}
