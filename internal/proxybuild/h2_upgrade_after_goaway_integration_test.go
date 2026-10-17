//go:build e2e

// USK-1164 smoke-tier coverage: a stream that the proxy opens on a
// redialed upstream connection (USK-991: after upstream GOAWAY, later
// streams of the same CONNECT go to chain[1+]) must still upgrade to
// SSE / WS-over-h2 against THAT connection. HTTP/2 stream ids are
// per-connection (RFC 9113 §5.1.1) and every redialed connection restarts
// at id 1, so detaching "upstream stream 1" on the CONNECT's first pooled
// connection targets an unrelated (stale or still-live) stream.
//
// The origin is an INVENTED frame-level TLS h2 fixture (x/net/http2
// Framer) in the shape of refusingH2Origin
// (h2_upstream_refused_integration_test.go): connection #1 answers the
// first request and then sends GOAWAY(NO_ERROR, last_stream_id=1) while
// staying open; connection #2+ serves the upgrade. It is kept in its own
// file with its own mode names so sibling work on refusingH2Origin does not
// collide with it. The exhaustive variants (still-live chain[0] stream
// hijack, extended-CONNECT WS) live in
// h2_upgrade_after_goaway_exhaustive_integration_test.go.
package proxybuild_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// goAwayUpgradeMode selects what the origin's connections do.
type goAwayUpgradeMode int

const (
	// upgradeModeSSE: conn #1 answers its first request with a complete
	// 200 and sends GOAWAY(NO_ERROR, last=that stream). Conn #2+ answer
	// GET /events with a text/event-stream response of sseEventsPayload
	// and every other request with a plain 200.
	upgradeModeSSE goAwayUpgradeMode = iota
	// upgradeModeLongPollSSE: like upgradeModeSSE, but conn #1 sends only
	// the response HEADERS (no END_STREAM) before its GOAWAY, keeping the
	// stream live. Once conn #2 has sent the /events response HEADERS, the
	// origin finishes conn #1's stream with longPollBody + END_STREAM, and
	// only then sends the SSE events.
	upgradeModeLongPollSSE
	// upgradeModeWS: every connection advertises
	// SETTINGS_ENABLE_CONNECT_PROTOCOL=1 (RFC 8441 §3). Conn #1 behaves as
	// in upgradeModeSSE; conn #2+ accept extended CONNECT
	// (:protocol=websocket) with 200 and echo every DATA payload back.
	upgradeModeWS
)

const (
	sseEventsPath = "/events"
	sseEvent1     = "data: first-event\n\n"
	sseEvent2     = "data: second-event\n\n"
	longPollBody  = "LONGPOLL-BODY"
	// settingEnableConnectProtocol is SETTINGS_ENABLE_CONNECT_PROTOCOL
	// (RFC 8441 §3), spelled out so the fixture does not depend on the
	// x/net constant's availability.
	settingEnableConnectProtocol = http2.SettingID(0x8)
)

// goAwayUpgradeOrigin is a TLS h2 origin driven at the frame level.
type goAwayUpgradeOrigin struct {
	addr string
	ln   net.Listener
	mode goAwayUpgradeMode

	accepts atomic.Int64
	wg      sync.WaitGroup

	mu    sync.Mutex
	conns []net.Conn
	// framesOnConn1AfterGoAway records every non-control frame conn #1
	// read after it sent GOAWAY.
	framesOnConn1AfterGoAway []originFrame

	// sseHeadersSent closes once a conn #2+ wrote the /events response
	// HEADERS (upgradeModeLongPollSSE ordering).
	sseHeadersSent     chan struct{}
	sseHeadersSentOnce sync.Once
	// longPollDone closes once conn #1 finished its long-poll stream.
	longPollDone chan struct{}
	// goAwaySent closes once conn #1 wrote its GOAWAY.
	goAwaySent chan struct{}
}

func startGoAwayUpgradeOrigin(t *testing.T, mode goAwayUpgradeMode) *goAwayUpgradeOrigin {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	o := &goAwayUpgradeOrigin{
		addr:           ln.Addr().String(),
		ln:             ln,
		mode:           mode,
		sseHeadersSent: make(chan struct{}),
		longPollDone:   make(chan struct{}),
		goAwaySent:     make(chan struct{}),
	}
	go o.acceptLoop()
	t.Cleanup(o.close)
	return o
}

func (o *goAwayUpgradeOrigin) acceptLoop() {
	for {
		c, err := o.ln.Accept()
		if err != nil {
			return
		}
		idx := o.accepts.Add(1)
		o.mu.Lock()
		o.conns = append(o.conns, c)
		o.mu.Unlock()
		o.wg.Add(1)
		go func() {
			defer o.wg.Done()
			defer c.Close()
			o.serveConn(c, idx)
		}()
	}
}

func (o *goAwayUpgradeOrigin) close() {
	_ = o.ln.Close()
	o.mu.Lock()
	for _, c := range o.conns {
		_ = c.Close()
	}
	o.mu.Unlock()
	done := make(chan struct{})
	go func() { o.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
}

func (o *goAwayUpgradeOrigin) conn1FramesAfterGoAway() []originFrame {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]originFrame(nil), o.framesOnConn1AfterGoAway...)
}

// lockedOriginConn serialises frame writes: in upgradeModeLongPollSSE the
// conn #1 long-poll finisher writes from a second goroutine.
type lockedOriginConn struct {
	mu sync.Mutex
	oc *originConn
}

func (l *lockedOriginConn) do(f func(oc *originConn) error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return f(l.oc)
}

func (o *goAwayUpgradeOrigin) serveConn(c net.Conn, idx int64) {
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(c, preface); err != nil || string(preface) != http2.ClientPreface {
		return
	}
	oc := &originConn{conn: c, fr: http2.NewFramer(c, c), idx: idx}
	oc.enc = hpack.NewEncoder(&oc.buf)
	oc.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	oc.fr.MaxHeaderListSize = 1 << 20
	var settings []http2.Setting
	if o.mode == upgradeModeWS {
		settings = append(settings, http2.Setting{ID: settingEnableConnectProtocol, Val: 1})
	}
	if err := oc.fr.WriteSettings(settings...); err != nil {
		return
	}
	lc := &lockedOriginConn{oc: oc}

	goneAway := false
	for {
		f, err := oc.fr.ReadFrame()
		if err != nil {
			return
		}
		var handled bool
		werr := lc.do(func(oc *originConn) error {
			var cerr error
			handled, cerr = oc.handleControl(f)
			return cerr
		})
		if werr != nil {
			return
		}
		if handled {
			continue
		}
		if goneAway {
			o.recordConn1Frame(f)
			continue
		}
		switch ff := f.(type) {
		case *http2.MetaHeadersFrame:
			if idx == 1 {
				if err := o.conn1FirstRequest(lc, ff.StreamID); err != nil {
					return
				}
				goneAway = true
				continue
			}
			if err := o.serveUpgradeRequest(lc, ff); err != nil {
				return
			}
		case *http2.DataFrame:
			if idx != 1 && o.mode == upgradeModeWS {
				if err := o.echoData(lc, ff); err != nil {
					return
				}
			}
		}
	}
}

func (o *goAwayUpgradeOrigin) recordConn1Frame(f http2.Frame) {
	of := originFrame{streamID: f.Header().StreamID, typ: f.Header().Type}
	if rst, ok := f.(*http2.RSTStreamFrame); ok {
		of.rstCode = rst.ErrCode
	}
	o.mu.Lock()
	o.framesOnConn1AfterGoAway = append(o.framesOnConn1AfterGoAway, of)
	o.mu.Unlock()
}

// conn1FirstRequest answers conn #1's first stream and sends GOAWAY naming
// it as the last processed stream (RFC 9113 §6.8), keeping the conn open.
func (o *goAwayUpgradeOrigin) conn1FirstRequest(lc *lockedOriginConn, id uint32) error {
	defer close(o.goAwaySent)
	if o.mode != upgradeModeLongPollSSE {
		return lc.do(func(oc *originConn) error {
			if err := oc.writeOK(id); err != nil {
				return err
			}
			return oc.fr.WriteGoAway(id, http2.ErrCodeNo, nil)
		})
	}
	if err := lc.do(func(oc *originConn) error {
		if err := oc.writeHeaders(id, false,
			hpack.HeaderField{Name: ":status", Value: "200"},
			hpack.HeaderField{Name: "content-type", Value: "text/plain"},
			hpack.HeaderField{Name: "x-origin-conn", Value: "1"},
		); err != nil {
			return err
		}
		return oc.fr.WriteGoAway(id, http2.ErrCodeNo, nil)
	}); err != nil {
		return err
	}
	go func() {
		defer close(o.longPollDone)
		select {
		case <-o.sseHeadersSent:
		case <-time.After(10 * time.Second):
			return
		}
		// Give the proxy time to act on the /events response HEADERS
		// (UpgradeStep → DetachStream) before the long-poll body lands.
		time.Sleep(200 * time.Millisecond)
		_ = lc.do(func(oc *originConn) error {
			return oc.fr.WriteData(id, true, []byte(longPollBody))
		})
	}()
	return nil
}

func (o *goAwayUpgradeOrigin) serveUpgradeRequest(lc *lockedOriginConn, mh *http2.MetaHeadersFrame) error {
	id := mh.StreamID
	switch {
	case o.mode == upgradeModeWS && mh.PseudoValue("method") == "CONNECT" && mh.PseudoValue("protocol") == "websocket":
		return lc.do(func(oc *originConn) error {
			return oc.writeHeaders(id, false, hpack.HeaderField{Name: ":status", Value: "200"})
		})
	case o.mode != upgradeModeWS && mh.PseudoValue("path") == sseEventsPath:
		if err := lc.do(func(oc *originConn) error {
			return oc.writeHeaders(id, false,
				hpack.HeaderField{Name: ":status", Value: "200"},
				hpack.HeaderField{Name: "content-type", Value: "text/event-stream"},
				hpack.HeaderField{Name: "cache-control", Value: "no-cache"},
				hpack.HeaderField{Name: "x-origin-conn", Value: strconv.FormatInt(oc.idx, 10)},
			)
		}); err != nil {
			return err
		}
		if o.mode == upgradeModeLongPollSSE {
			o.sseHeadersSentOnce.Do(func() { close(o.sseHeadersSent) })
			select {
			case <-o.longPollDone:
			case <-time.After(10 * time.Second):
			}
		}
		go func() {
			// Events are written off the read loop so WINDOW_UPDATE /
			// SETTINGS keep being serviced meanwhile.
			_ = lc.do(func(oc *originConn) error { return oc.fr.WriteData(id, false, []byte(sseEvent1)) })
			time.Sleep(50 * time.Millisecond)
			_ = lc.do(func(oc *originConn) error { return oc.fr.WriteData(id, true, []byte(sseEvent2)) })
		}()
		return nil
	default:
		return lc.do(func(oc *originConn) error { return oc.writeOK(id) })
	}
}

// echoData writes every DATA payload back on the same stream. Over RFC
// 8441 WS frames are unmasked in both directions (§5.3), so a byte-for-byte
// echo of a client frame is a valid server frame.
func (o *goAwayUpgradeOrigin) echoData(lc *lockedOriginConn, df *http2.DataFrame) error {
	payload := append([]byte(nil), df.Data()...)
	return lc.do(func(oc *originConn) error {
		if len(payload) > 0 {
			if err := oc.fr.WriteWindowUpdate(0, uint32(len(payload))); err != nil {
				return err
			}
			if err := oc.fr.WriteWindowUpdate(df.StreamID, uint32(len(payload))); err != nil {
				return err
			}
		}
		return oc.fr.WriteData(df.StreamID, df.StreamEnded(), payload)
	})
}

// upgradeStreamResult is what the raw client observed on one stream.
type upgradeStreamResult struct {
	statuses []string
	body     bytes.Buffer
	ended    bool
	rst      bool
	rstCode  http2.ErrCode
}

func (r *upgradeStreamResult) done() bool { return r.ended || r.rst }

// upgradeClient wraps rawH2Client with per-stream body capture.
type upgradeClient struct {
	*rawH2Client
	res map[uint32]*upgradeStreamResult
}

func newUpgradeClient(t *testing.T, proxyAddr, target string) *upgradeClient {
	t.Helper()
	return &upgradeClient{
		rawH2Client: dialRawH2ThroughProxy(t, proxyAddr, target),
		res:         make(map[uint32]*upgradeStreamResult),
	}
}

func (c *upgradeClient) result(id uint32) *upgradeStreamResult {
	r, ok := c.res[id]
	if !ok {
		r = &upgradeStreamResult{}
		c.res[id] = r
	}
	return r
}

// sendHeaders writes one request HEADERS frame.
func (c *upgradeClient) sendHeaders(t *testing.T, id uint32, endStream bool, fields ...hpack.HeaderField) {
	t.Helper()
	c.result(id)
	c.buf.Reset()
	for _, f := range fields {
		if err := c.enc.WriteField(f); err != nil {
			t.Fatalf("hpack: %v", err)
		}
	}
	if err := c.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      id,
		BlockFragment: c.buf.Bytes(),
		EndStream:     endStream,
		EndHeaders:    true,
	}); err != nil {
		t.Fatalf("write HEADERS on stream %d: %v", id, err)
	}
}

func (c *upgradeClient) sendGET(t *testing.T, id uint32, authority, path string) {
	t.Helper()
	c.sendHeaders(t, id, true,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":scheme", Value: "https"},
		hpack.HeaderField{Name: ":authority", Value: authority},
		hpack.HeaderField{Name: ":path", Value: path},
	)
}

// readUntil reads frames, updating per-stream results, until pred holds or
// timeout elapses. Returns pred's final value.
func (c *upgradeClient) readUntil(timeout time.Duration, pred func() bool) bool {
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = c.conn.SetReadDeadline(time.Time{}) }()
	for !pred() {
		f, err := c.fr.ReadFrame()
		if err != nil {
			return pred()
		}
		switch ff := f.(type) {
		case *http2.SettingsFrame:
			if !ff.IsAck() {
				_ = c.fr.WriteSettingsAck()
			}
		case *http2.PingFrame:
			if !ff.IsAck() {
				_ = c.fr.WritePing(true, ff.Data)
			}
		case *http2.MetaHeadersFrame:
			r := c.result(ff.StreamID)
			if st := ff.PseudoValue("status"); st != "" {
				r.statuses = append(r.statuses, st)
			}
			if ff.StreamEnded() {
				r.ended = true
			}
		case *http2.DataFrame:
			r := c.result(ff.StreamID)
			r.body.Write(ff.Data())
			if n := len(ff.Data()); n > 0 {
				_ = c.fr.WriteWindowUpdate(0, uint32(n))
				_ = c.fr.WriteWindowUpdate(ff.StreamID, uint32(n))
			}
			if ff.StreamEnded() {
				r.ended = true
			}
		case *http2.RSTStreamFrame:
			r := c.result(ff.StreamID)
			r.rst = true
			r.rstCode = ff.ErrCode
		}
	}
	return true
}

// waitGoAwaySent waits until the origin's conn #1 wrote its GOAWAY.
func waitGoAwaySent(t *testing.T, o *goAwayUpgradeOrigin) {
	t.Helper()
	select {
	case <-o.goAwaySent:
	case <-time.After(10 * time.Second):
		t.Fatal("origin conn #1 never sent GOAWAY")
	}
}

// openWithRefusedRetry sends a request via send on firstID and, like a
// browser, retries on the next client stream id when the proxy answers
// RST_STREAM(REFUSED_STREAM) — which it does (USK-1157) when the request
// raced onto the GOAWAY'd connection before the proxy processed the
// GOAWAY. Returns the client stream id that got a response.
func (c *upgradeClient) openWithRefusedRetry(t *testing.T, firstID uint32, send func(id uint32)) uint32 {
	t.Helper()
	id := firstID
	for attempt := 0; attempt < 3; attempt++ {
		send(id)
		r := c.result(id)
		c.readUntil(10*time.Second, func() bool { return len(r.statuses) > 0 || r.done() })
		if r.rst && r.rstCode == http2.ErrCodeRefusedStream && len(r.statuses) == 0 {
			id += 2
			continue
		}
		return id
	}
	t.Fatalf("stream refused %d times in a row", 3)
	return 0
}

// assertRedialed checks that the upgrade was served by a redialed upstream
// connection.
func assertRedialed(t *testing.T, o *goAwayUpgradeOrigin) {
	t.Helper()
	if n := o.accepts.Load(); n < 2 {
		t.Errorf("origin accepted %d connections, want >= 2 (the upgrade must run on the redialed connection)", n)
	}
}

// effectiveStreamProtocol is the Stream's protocol after any retag
// UpdateStream (RecordStep.maybeRetagProtocol); flowStoreForH2Pool keeps
// the retag only in its update log.
func effectiveStreamProtocol(s *flowStoreForH2Pool, st *flow.Stream) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	proto := st.Protocol
	for _, upd := range s.updates[st.ID] {
		if upd.Protocol != "" {
			proto = upd.Protocol
		}
	}
	return proto
}

// streamsWithProtocol returns the recorded Streams whose effective protocol
// is proto.
func streamsWithProtocol(s *flowStoreForH2Pool, proto string) []*flow.Stream {
	var out []*flow.Stream
	for _, st := range s.Streams() {
		if effectiveStreamProtocol(s, st) == proto {
			out = append(out, st)
		}
	}
	return out
}

// semanticFlows returns the semantic-level flows of streamID in direction.
func semanticFlows(s *flowStoreForH2Pool, streamID, direction string) []*flow.Flow {
	var out []*flow.Flow
	for _, f := range s.Flows() {
		if f.StreamID != streamID || f.Direction != direction {
			continue
		}
		if f.WireLevel != "" && f.WireLevel != "semantic" {
			continue
		}
		out = append(out, f)
	}
	return out
}

// waitRecorded polls until cond holds or timeout, then reports via t.Errorf.
func waitRecorded(t *testing.T, timeout time.Duration, what string, cond func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		ok, detail := cond()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("%s: %s", what, detail)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// assertSSEEventsRecorded checks that exactly one Stream was retagged to
// sse and that it carries a receive flow per event with the event data.
func assertSSEEventsRecorded(t *testing.T, store *flowStoreForH2Pool) {
	t.Helper()
	waitRecorded(t, 5*time.Second, "SSE recording", func() (bool, string) {
		sse := streamsWithProtocol(store, "sse")
		if len(sse) != 1 {
			return false, "Protocol=sse streams = " + strconv.Itoa(len(sse)) + ", want 1"
		}
		var datas []string
		for _, f := range semanticFlows(store, sse[0].ID, "receive") {
			if f.StatusCode != 0 {
				continue // the 200 response-headers flow
			}
			datas = append(datas, string(f.Body))
		}
		want := []string{"first-event", "second-event"}
		if strings.Join(datas, "|") != strings.Join(want, "|") {
			return false, "recorded SSE event bodies = " + strings.Join(datas, "|") + ", want " + strings.Join(want, "|")
		}
		return true, ""
	})
}

// TestH2UpstreamGoAway_SSEOnRedialedConnectionReachesClient: stream 1 is
// served by upstream conn #1, which then GOAWAYs. Stream 3 (GET /events)
// is opened on the redialed conn #2 — where it is upstream stream 1 — and
// its text/event-stream response must reach the client with every event,
// recorded as a Protocol=sse Stream with one receive flow per event.
func TestH2UpstreamGoAway_SSEOnRedialedConnectionReachesClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origin := startGoAwayUpgradeOrigin(t, upgradeModeSSE)
	store := &flowStoreForH2Pool{}
	proxyAddr := startProxyForRefusedTest(t, ctx, store)

	cli := newUpgradeClient(t, proxyAddr, origin.addr)
	cli.sendGET(t, 1, origin.addr, "/plain")
	if !cli.readUntil(10*time.Second, cli.result(1).done) {
		t.Fatalf("stream 1 did not complete: %+v", cli.result(1))
	}
	if r := cli.result(1); !r.ended || len(r.statuses) != 1 || r.statuses[0] != "200" {
		t.Fatalf("stream 1: statuses=%v ended=%v rst=%v; want 200 + END_STREAM", r.statuses, r.ended, r.rst)
	}
	waitGoAwaySent(t, origin)

	id := cli.openWithRefusedRetry(t, 3, func(id uint32) { cli.sendGET(t, id, origin.addr, sseEventsPath) })
	r := cli.result(id)
	cli.readUntil(10*time.Second, r.done)
	want := sseEvent1 + sseEvent2
	if len(r.statuses) == 0 || r.statuses[0] != "200" || r.body.String() != want || !r.ended {
		t.Fatalf("stream %d (/events on redialed conn): statuses=%v body=%q ended=%v rst=%v(%v); want 200, body %q, END_STREAM",
			id, r.statuses, r.body.String(), r.ended, r.rst, r.rstCode, want)
	}
	assertRedialed(t, origin)

	assertSSEEventsRecorded(t, store)
}
