//go:build e2e && !e2e_smoke

package http2_test

import (
	"context"
	"crypto/tls"
	nethttp "net/http"
	"testing"
	"time"

	intHTTP2 "github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	h2frame "github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	h2hpack "github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/pool"
)

// USK-1144: completed streams must stop counting against
// SETTINGS_MAX_CONCURRENT_STREAMS (client side) and against the upstream
// pool's per-connection capacity (upstream side).

// rawH2TunnelClient is a frame-level HTTP/2 client over a CONNECT tunnel.
// It bypasses the standard library's own concurrency accounting so the
// proxy's stream bookkeeping is what decides the outcome.
type rawH2TunnelClient struct {
	tlsConn *tls.Conn
	rd      *h2frame.Reader
	wr      *h2frame.Writer
	enc     *h2hpack.Encoder
	nextID  uint32
}

func dialRawH2TunnelClient(t *testing.T, ctx context.Context, proxyAddr, upAddr string) *rawH2TunnelClient {
	t.Helper()
	rawConn, err := connectTunnelDialer(proxyAddr, upAddr)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	tlsConn := tls.Client(rawConn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test
		NextProtos:         []string{"h2"},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		t.Fatalf("TLS handshake: %v", err)
	}
	if _, err := tlsConn.Write([]byte(intHTTP2.ClientPreface)); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	c := &rawH2TunnelClient{
		tlsConn: tlsConn,
		rd:      h2frame.NewReader(tlsConn),
		wr:      h2frame.NewWriter(tlsConn),
		enc:     h2hpack.NewEncoder(4096, true),
		nextID:  1,
	}
	if err := c.wr.WriteSettings(nil); err != nil {
		t.Fatalf("write SETTINGS: %v", err)
	}
	return c
}

// get sends a bodyless GET on the next stream id and reads until the
// response's END_STREAM, failing on RST_STREAM / GOAWAY.
func (c *rawH2TunnelClient) get(t *testing.T, n int, authority string) {
	t.Helper()
	sid := c.nextID
	c.nextID += 2
	frag := c.enc.Encode([]h2hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: "/usk1144"},
	})
	if err := c.wr.WriteHeaders(sid, true, true, frag); err != nil {
		t.Fatalf("req #%d (stream %d): write HEADERS: %v", n, sid, err)
	}
	_ = c.tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = c.tlsConn.SetReadDeadline(time.Time{}) }()
	for {
		f, err := c.rd.ReadFrame()
		if err != nil {
			t.Fatalf("req #%d (stream %d): read: %v", n, sid, err)
		}
		if f.Header.Type == h2frame.TypeSettings && !f.Header.Flags.Has(h2frame.FlagAck) {
			_ = c.wr.WriteSettingsAck()
			continue
		}
		if f.Header.Type == h2frame.TypeGoAway {
			_, code, _, _ := f.GoAwayInfo()
			t.Fatalf("req #%d (stream %d): GOAWAY(%s)", n, sid, intHTTP2.ErrCodeString(code))
		}
		if f.Header.StreamID != sid {
			continue
		}
		if f.Header.Type == h2frame.TypeRSTStream {
			code, _ := f.RSTStreamErrorCode()
			t.Fatalf("req #%d (stream %d): RST_STREAM(%s)", n, sid, intHTTP2.ErrCodeString(code))
		}
		if (f.Header.Type == h2frame.TypeHeaders || f.Header.Type == h2frame.TypeData) && f.Header.Flags.Has(h2frame.FlagEndStream) {
			return
		}
	}
}

func (c *rawH2TunnelClient) close() { _ = c.tlsConn.Close() }

// TestStreamRetire_FullProxy_SequentialRequestsBeyondMaxConcurrentStreams
// drives the whole MITM path: with the client-facing MAX_CONCURRENT_STREAMS
// set to 3, sequential (never concurrent) requests on one connection must
// all be answered.
func TestStreamRetire_FullProxy_SequentialRequestsBeyondMaxConcurrentStreams(t *testing.T) {
	const mcs = 3
	const total = mcs + 3
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "usk1144", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		w.WriteHeader(nethttp.StatusNoContent)
	}))
	defer upShutdown()

	bcfg := makeBuildCfg(t, nil)
	bcfg.MaxConcurrentStreams = mcs
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{})

	c := dialRawH2TunnelClient(t, ctx, proxyAddr, upAddr)
	defer c.close()
	for i := 0; i < total; i++ {
		c.get(t, i+1, upAddr)
	}

	// Every exchange is still recorded as its own stream.
	waitForStreams(t, store, total, 5*time.Second)
}

// TestStreamRetire_Pool_SequentiallyReusedConnectionNotFull pins the
// upstream side: a pooled upstream connection that carried more sequential
// streams than MaxStreamsPerConn, all finished, still has capacity, so the
// next CONNECT reuses it instead of dialing a second upstream connection.
func TestStreamRetire_Pool_SequentiallyReusedConnectionNotFull(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, _, accepts, upShutdown := startH2TLSUpstream(t, "usk1144-pool", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, _ *nethttp.Request) {
		w.WriteHeader(nethttp.StatusNoContent)
	}))
	defer upShutdown()

	p := pool.New(pool.PoolOptions{MaxStreamsPerConn: 2})
	defer p.Close()
	bcfg := makeBuildCfg(t, p)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{})

	c1 := dialRawH2TunnelClient(t, ctx, proxyAddr, upAddr)
	for i := 0; i < 3; i++ {
		c1.get(t, i+1, upAddr)
	}
	waitForStreams(t, store, 3, 5*time.Second)
	c1.close()
	// Give the CONNECT handler time to exit and Put the upstream Layer.
	time.Sleep(300 * time.Millisecond)

	c2 := dialRawH2TunnelClient(t, ctx, proxyAddr, upAddr)
	defer c2.close()
	c2.get(t, 1, upAddr)

	if acc := accepts(); acc != 1 {
		t.Fatalf("upstream accept count = %d, want 1 (a sequentially reused upstream connection was judged full by its cumulative stream count)", acc)
	}
}
