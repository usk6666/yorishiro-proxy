//go:build e2e && !e2e_smoke

// USK-1196: on an h2 connection every stream session shares the one live
// connection handle, so the deferred cut of a revoked connection must wait
// until the released hold's 403 was dispatched — not merely until the hold
// resolved. A sibling stream that finishes while that 403 is still on its
// way must not cut the connection under it.
package mcptest_test

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// h2WireStream is what a raw-framer client observed on one stream.
type h2WireStream struct {
	status  string
	body    bytes.Buffer
	ended   bool
	rstCode http2.ErrCode
	reset   bool
}

// h2WireClient is a raw http2.Framer client that reads frames on demand,
// so a test controls exactly when the proxy may send DATA (flow-control
// credit is granted by explicit WINDOW_UPDATEs).
type h2WireClient struct {
	t       *testing.T
	fr      *http2.Framer
	enc     *hpack.Encoder
	encBuf  bytes.Buffer
	dec     *hpack.Decoder
	cur     *h2WireStream
	streams map[uint32]*h2WireStream
	goaway  bool
	connErr error
}

func newH2WireClient(t *testing.T, conn net.Conn, settings ...http2.Setting) *h2WireClient {
	t.Helper()
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	c := &h2WireClient{t: t, fr: http2.NewFramer(conn, conn), streams: map[uint32]*h2WireStream{}}
	c.enc = hpack.NewEncoder(&c.encBuf)
	c.dec = hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		if f.Name == ":status" && c.cur != nil {
			c.cur.status = f.Value
		}
	})
	if err := c.fr.WriteSettings(settings...); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	return c
}

func (c *h2WireClient) stream(id uint32) *h2WireStream {
	s := c.streams[id]
	if s == nil {
		s = &h2WireStream{}
		c.streams[id] = s
	}
	return s
}

func (c *h2WireClient) get(id uint32, authority, path string) {
	c.t.Helper()
	c.encBuf.Reset()
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: path},
	} {
		if err := c.enc.WriteField(f); err != nil {
			c.t.Fatalf("hpack encode: %v", err)
		}
	}
	if err := c.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: id, BlockFragment: c.encBuf.Bytes(), EndStream: true, EndHeaders: true,
	}); err != nil {
		c.t.Fatalf("write headers (stream %d): %v", id, err)
	}
	c.stream(id)
}

func (c *h2WireClient) windowUpdate(id uint32) {
	c.t.Helper()
	if err := c.fr.WriteWindowUpdate(id, 1<<20); err != nil {
		c.t.Fatalf("window update (stream %d): %v", id, err)
	}
}

// readOne reads and records one frame. It returns false once the
// connection ended (GOAWAY or read error).
func (c *h2WireClient) readOne() bool {
	c.t.Helper()
	if c.goaway || c.connErr != nil {
		return false
	}
	f, err := c.fr.ReadFrame()
	if err != nil {
		c.connErr = err
		return false
	}
	switch f := f.(type) {
	case *http2.SettingsFrame:
		if !f.IsAck() {
			_ = c.fr.WriteSettingsAck()
		}
	case *http2.PingFrame:
		if !f.IsAck() {
			_ = c.fr.WritePing(true, f.Data)
		}
	case *http2.HeadersFrame:
		c.cur = c.stream(f.StreamID)
		if _, err := c.dec.Write(f.HeaderBlockFragment()); err != nil {
			c.t.Fatalf("hpack decode: %v", err)
		}
		c.cur = nil
		if f.StreamEnded() {
			c.stream(f.StreamID).ended = true
		}
	case *http2.DataFrame:
		s := c.stream(f.StreamID)
		s.body.Write(f.Data())
		if f.StreamEnded() {
			s.ended = true
		}
	case *http2.RSTStreamFrame:
		s := c.stream(f.StreamID)
		s.reset, s.rstCode = true, f.ErrCode
	case *http2.GoAwayFrame:
		c.goaway = true
		return false
	}
	return true
}

// until reads frames until cond holds. It fails the test when the
// connection ends or stream id is reset first.
func (c *h2WireClient) until(what string, id uint32, cond func() bool) {
	c.t.Helper()
	for !cond() {
		if s := c.streams[id]; s != nil && s.reset {
			c.t.Fatalf("%s: stream %d reset (%v) instead (body so far %q)", what, id, s.rstCode, s.body.String())
		}
		if !c.readOne() {
			c.t.Fatalf("%s: connection ended first (goaway=%v, err=%v; stream %d: %+v)",
				what, c.goaway, c.connErr, id, c.streams[id])
		}
	}
	if s := c.streams[id]; s != nil && s.reset {
		c.t.Fatalf("%s: stream %d reset (%v)", what, id, s.rstCode)
	}
}

func (s *h2WireStream) statusCode(t *testing.T) int {
	t.Helper()
	n, err := strconv.Atoi(s.status)
	if err != nil {
		t.Fatalf(":status %q: %v", s.status, err)
	}
	return n
}

// TestE2E_LiveConnHoldDefer_MITMHTTP2_SiblingSettleDuringReleasedRespond
// is USK-1196 test-plan 1. The client advertises
// SETTINGS_INITIAL_WINDOW_SIZE=0, so the proxy's 403 DATA for each stream
// parks inside the stream's client.Send until the client grants credit.
// Stream A is held; a reload denies the host; A is released and its 403
// HEADERS arrive while its DATA is parked; a sibling stream C is then
// answered and completes (its session Settles) — the connection must stay
// up until A's 403 was fully delivered, and close only afterwards.
func TestE2E_LiveConnHoldDefer_MITMHTTP2_SiblingSettleDuringReleasedRespond(t *testing.T) {
	upstream, hits := h2CountingUpstream(t)
	target := upstream.Listener.Addr().String()
	h, policyPath := bootReloadHarness(t)
	proxyAddr := startProxyWithRules(t, h, holdHeldPathRule, nil)

	raw, err := dialCONNECTTunnel(proxyAddr, target)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	tc := tls.Client(raw, &tls.Config{ //nolint:gosec // the client does not trust the proxy's MITM CA
		InsecureSkipVerify: true,
		ServerName:         "127.0.0.1",
		NextProtos:         []string{"h2"},
	})
	t.Cleanup(func() { _ = tc.Close() })
	_ = tc.SetDeadline(time.Now().Add(30 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatalf("client TLS handshake over tunnel: %v", err)
	}
	if got := tc.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("negotiated ALPN = %q, want h2", got)
	}
	c := newH2WireClient(t, tc, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0})

	c.get(1, target, "/held-a")
	entry := waitForHeldEntry(t, h, 5*time.Second)
	reloadDenyLoopback(t, h, policyPath)
	releaseHeld(t, h, entry)

	a := c.stream(1)
	c.until("stream A's 403 HEADERS", 1, func() bool { return a.status != "" })
	if a.ended || a.body.Len() != 0 {
		t.Fatalf("stream A sent DATA without flow-control credit (ended=%v, body %q)", a.ended, a.body.String())
	}
	// A's 403 DATA is now parked inside A's client.Send.

	c.get(3, target, "/other-c")
	cs := c.stream(3)
	c.windowUpdate(3)
	c.until("sibling stream C's 403", 3, func() bool { return cs.ended })
	assertTargetScope403Body(t, cs.statusCode(t), cs.body.Bytes(), "sibling stream C on the revoked connection")

	c.windowUpdate(1)
	c.until("released stream A's 403 body", 1, func() bool { return a.ended })
	assertTargetScope403Body(t, a.statusCode(t), a.body.Bytes(), "released stream A")

	// Only now is the connection closed.
	_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
	for c.readOne() {
	}
	var ne net.Error
	if c.connErr != nil && errors.As(c.connErr, &ne) && ne.Timeout() {
		t.Fatalf("h2 connection still open 5s after its last hold's Result was delivered")
	}
	time.Sleep(200 * time.Millisecond)
	if got := hits.Load(); got != 0 {
		t.Errorf("upstream hits = %d, want 0", got)
	}
	assertBlockedFlowRecorded(t, h)
}
