//go:build e2e

// USK-1157 smoke-tier coverage: an upstream that declares streams
// unprocessed (GOAWAY with last_stream_id below them, RFC 9113 §6.8) must
// surface to the client as RST_STREAM(REFUSED_STREAM), so a browser retries
// them transparently the way it does against the origin directly — instead
// of RST_STREAM(CANCEL), which Chrome reports as ERR_HTTP2_PROTOCOL_ERROR.
//
// Reported in https://github.com/usk6666/yorishiro-proxy/issues/152. The
// origin below is an INVENTED fixture reconstructed from that report's
// repro description (a frame-level TLS h2 origin that waits for four
// requests, answers the first with 200, sends GOAWAY(NO_ERROR) naming only
// that stream, and keeps the connection open briefly). It is a raw
// x/net/http2 Framer server rather than http2.Server because no standard
// server emits that frame sequence on demand.
//
// Client-side RST codes are asserted with a raw Framer client: an
// x/net/http2.Transport retries REFUSED_STREAM itself and therefore cannot
// tell CANCEL from REFUSED_STREAM. The Transport client is used separately
// to prove the end-to-end outcome a retrying client sees (4/4 succeed).
//
// Smoke tier (`//go:build e2e`): this is browser-parity behaviour on the
// merge gate. The exhaustive variants (RST_STREAM(REFUSED_STREAM) origin,
// 1xx-already-forwarded guard, no-RST-upstream-after-GOAWAY) live in
// h2_upstream_refused_exhaustive_integration_test.go and reuse the fixture
// defined here.
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
	"fmt"
	"io"
	"math/big"
	"net"
	gohttp "net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	h2pool "github.com/usk6666/yorishiro-proxy/internal/layer/http2/pool"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// refusingOriginMode selects what the origin's FIRST connection does with
// the batch of requests it waits for. Every later connection answers every
// request with 200.
type refusingOriginMode int

const (
	// originGoAwayAfterFirst: wait for batch requests, answer the lowest
	// stream id with 200, send GOAWAY(NO_ERROR, last_stream_id=lowest),
	// keep reading for refusalHold, then close the connection.
	originGoAwayAfterFirst refusingOriginMode = iota
	// originRSTLast: wait for batch requests, answer all but the highest
	// stream id with 200, send RST_STREAM(REFUSED_STREAM) on the highest,
	// then keep serving the connection normally.
	originRSTLast
	// originEarlyHintsThenRST: on the first request send a 103 Early Hints
	// HEADERS, then RST_STREAM(REFUSED_STREAM) on the same stream; keep
	// serving the connection normally.
	originEarlyHintsThenRST
)

const refusalHold = 500 * time.Millisecond

// originFrame is a frame the origin received on its first connection after
// it refused streams.
type originFrame struct {
	streamID uint32
	typ      http2.FrameType
	rstCode  http2.ErrCode
}

// refusingH2Origin is a TLS h2 origin driven at the frame level.
type refusingH2Origin struct {
	addr  string
	ln    net.Listener
	mode  refusingOriginMode
	batch int

	accepts atomic.Int64
	wg      sync.WaitGroup

	mu sync.Mutex
	// conns is every accepted connection, closed on shutdown so serving
	// goroutines exit promptly.
	conns []net.Conn
	// refused is the set of stream ids the first connection refused.
	refused map[uint32]bool
	// afterRefusal is every frame the first connection read after it
	// refused streams.
	afterRefusal []originFrame
	// firstConnDone closes when the first connection's handler returns.
	firstConnDone chan struct{}
}

func startRefusingH2Origin(t *testing.T, mode refusingOriginMode, batch int) *refusingH2Origin {
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
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}},
		NextProtos:   []string{"h2"},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	o := &refusingH2Origin{
		addr:          ln.Addr().String(),
		ln:            ln,
		mode:          mode,
		batch:         batch,
		refused:       make(map[uint32]bool),
		firstConnDone: make(chan struct{}),
	}
	go o.acceptLoop()
	t.Cleanup(o.close)
	return o
}

func (o *refusingH2Origin) acceptLoop() {
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
			if idx == 1 {
				defer close(o.firstConnDone)
			}
			o.serveConn(c, idx)
		}()
	}
}

func (o *refusingH2Origin) close() {
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

func (o *refusingH2Origin) refusedIDs() map[uint32]bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make(map[uint32]bool, len(o.refused))
	for id := range o.refused {
		out[id] = true
	}
	return out
}

func (o *refusingH2Origin) framesAfterRefusal() []originFrame {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]originFrame(nil), o.afterRefusal...)
}

// originConn is the per-connection frame state. All writes happen on the
// connection's single serve goroutine.
type originConn struct {
	conn net.Conn
	fr   *http2.Framer
	idx  int64
	enc  *hpack.Encoder
	buf  bytes.Buffer
}

func (oc *originConn) writeHeaders(streamID uint32, endStream bool, fields ...hpack.HeaderField) error {
	oc.buf.Reset()
	for _, f := range fields {
		if err := oc.enc.WriteField(f); err != nil {
			return err
		}
	}
	return oc.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: oc.buf.Bytes(),
		EndStream:     endStream,
		EndHeaders:    true,
	})
}

func (oc *originConn) writeOK(streamID uint32) error {
	body := []byte("ok from origin conn " + strconv.FormatInt(oc.idx, 10))
	if err := oc.writeHeaders(streamID, false,
		hpack.HeaderField{Name: ":status", Value: "200"},
		hpack.HeaderField{Name: "content-type", Value: "text/plain"},
		hpack.HeaderField{Name: "content-length", Value: strconv.Itoa(len(body))},
		hpack.HeaderField{Name: "x-origin-conn", Value: strconv.FormatInt(oc.idx, 10)},
	); err != nil {
		return err
	}
	return oc.fr.WriteData(streamID, true, body)
}

// handleControl answers SETTINGS / PING; returns true when f was a control
// frame.
func (oc *originConn) handleControl(f http2.Frame) (bool, error) {
	switch ff := f.(type) {
	case *http2.SettingsFrame:
		if !ff.IsAck() {
			return true, oc.fr.WriteSettingsAck()
		}
		return true, nil
	case *http2.PingFrame:
		if !ff.IsAck() {
			return true, oc.fr.WritePing(true, ff.Data)
		}
		return true, nil
	}
	return false, nil
}

func (o *refusingH2Origin) serveConn(c net.Conn, idx int64) {
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(c, preface); err != nil || string(preface) != http2.ClientPreface {
		return
	}
	oc := &originConn{conn: c, fr: http2.NewFramer(c, c), idx: idx}
	oc.enc = hpack.NewEncoder(&oc.buf)
	oc.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	oc.fr.MaxHeaderListSize = 1 << 20
	if err := oc.fr.WriteSettings(); err != nil {
		return
	}

	if idx == 1 {
		if !o.runScenario(oc) {
			return
		}
	}
	o.serveAll(oc)
}

// serveAll answers every request HEADERS with 200 until the conn closes.
func (o *refusingH2Origin) serveAll(oc *originConn) {
	for {
		f, err := oc.fr.ReadFrame()
		if err != nil {
			return
		}
		if ok, werr := oc.handleControl(f); ok {
			if werr != nil {
				return
			}
			continue
		}
		if o.recordAfterRefusal(oc, f) {
			continue
		}
		if mh, ok := f.(*http2.MetaHeadersFrame); ok {
			if err := oc.writeOK(mh.StreamID); err != nil {
				return
			}
		}
	}
}

// recordAfterRefusal records f when it was read on the first connection
// after the scenario refused streams. Returns true when f targets a refused
// stream (the caller must not answer it).
func (o *refusingH2Origin) recordAfterRefusal(oc *originConn, f http2.Frame) bool {
	if oc.idx != 1 {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.refused) == 0 {
		return false
	}
	of := originFrame{streamID: f.Header().StreamID, typ: f.Header().Type}
	if rst, ok := f.(*http2.RSTStreamFrame); ok {
		of.rstCode = rst.ErrCode
	}
	o.afterRefusal = append(o.afterRefusal, of)
	return o.refused[of.streamID]
}

// runScenario collects the request batch and performs the mode's refusal.
// Returns false when the connection must close afterwards.
func (o *refusingH2Origin) runScenario(oc *originConn) bool {
	want := o.batch
	if o.mode == originEarlyHintsThenRST {
		want = 1
	}
	var ids []uint32
	_ = oc.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for len(ids) < want {
		f, err := oc.fr.ReadFrame()
		if err != nil {
			if len(ids) == 0 {
				return false
			}
			break // proceed with what arrived
		}
		if ok, werr := oc.handleControl(f); ok {
			if werr != nil {
				return false
			}
			continue
		}
		if mh, ok := f.(*http2.MetaHeadersFrame); ok {
			ids = append(ids, mh.StreamID)
		}
	}
	_ = oc.conn.SetReadDeadline(time.Time{})
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	switch o.mode {
	case originGoAwayAfterFirst:
		if err := oc.writeOK(ids[0]); err != nil {
			return false
		}
		o.markRefused(ids[1:]...)
		if err := oc.fr.WriteGoAway(ids[0], http2.ErrCodeNo, nil); err != nil {
			return false
		}
		// Keep the connection open briefly (as the reporter's origin did)
		// and record whatever the proxy still sends on it.
		_ = oc.conn.SetReadDeadline(time.Now().Add(refusalHold))
		for {
			f, err := oc.fr.ReadFrame()
			if err != nil {
				return false
			}
			if ok, _ := oc.handleControl(f); ok {
				continue
			}
			o.recordAfterRefusal(oc, f)
		}
	case originRSTLast:
		last := ids[len(ids)-1]
		for _, id := range ids[:len(ids)-1] {
			if err := oc.writeOK(id); err != nil {
				return false
			}
		}
		o.markRefused(last)
		if err := oc.fr.WriteRSTStream(last, http2.ErrCodeRefusedStream); err != nil {
			return false
		}
		return true
	case originEarlyHintsThenRST:
		id := ids[0]
		if err := oc.writeHeaders(id, false,
			hpack.HeaderField{Name: ":status", Value: "103"},
			hpack.HeaderField{Name: "link", Value: "</style.css>; rel=preload; as=style"},
		); err != nil {
			return false
		}
		o.markRefused(id)
		if err := oc.fr.WriteRSTStream(id, http2.ErrCodeRefusedStream); err != nil {
			return false
		}
		return true
	}
	return false
}

func (o *refusingH2Origin) markRefused(ids ...uint32) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, id := range ids {
		o.refused[id] = true
	}
}

// rawStreamResult is what the raw client observed on one stream.
type rawStreamResult struct {
	statuses []string // :status of every response HEADERS (1xx included)
	ended    bool     // END_STREAM observed
	rst      bool
	rstCode  http2.ErrCode
}

func (r *rawStreamResult) done() bool { return r.ended || r.rst }

// rawH2Client is a frame-level h2 client speaking through a CONNECT tunnel.
type rawH2Client struct {
	conn *tls.Conn
	fr   *http2.Framer
	enc  *hpack.Encoder
	buf  bytes.Buffer
}

func dialRawH2ThroughProxy(t *testing.T, proxyAddr, target string) *rawH2Client {
	t.Helper()
	raw, err := connectTunnelDialerForPoolTest(proxyAddr, target)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	tc := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test
		ServerName:         "localhost",
		NextProtos:         []string{"h2"},
	})
	if err := tc.Handshake(); err != nil {
		raw.Close()
		t.Fatalf("TLS handshake through proxy: %v", err)
	}
	if got := tc.ConnectionState().NegotiatedProtocol; got != "h2" {
		tc.Close()
		t.Fatalf("negotiated ALPN = %q, want h2", got)
	}
	if _, err := tc.Write([]byte(http2.ClientPreface)); err != nil {
		tc.Close()
		t.Fatalf("write preface: %v", err)
	}
	c := &rawH2Client{conn: tc, fr: http2.NewFramer(tc, tc)}
	c.enc = hpack.NewEncoder(&c.buf)
	c.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	c.fr.MaxHeaderListSize = 1 << 20
	if err := c.fr.WriteSettings(); err != nil {
		tc.Close()
		t.Fatalf("write SETTINGS: %v", err)
	}
	t.Cleanup(func() { _ = tc.Close() })
	return c
}

// sendGETs writes one GET HEADERS (END_STREAM) per stream id.
func (c *rawH2Client) sendGETs(t *testing.T, authority string, ids ...uint32) {
	t.Helper()
	for _, id := range ids {
		c.buf.Reset()
		for _, f := range []hpack.HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: authority},
			{Name: ":path", Value: fmt.Sprintf("/req-%d", id)},
		} {
			if err := c.enc.WriteField(f); err != nil {
				t.Fatalf("hpack: %v", err)
			}
		}
		if err := c.fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      id,
			BlockFragment: c.buf.Bytes(),
			EndStream:     true,
			EndHeaders:    true,
		}); err != nil {
			t.Fatalf("write HEADERS on stream %d: %v", id, err)
		}
	}
}

// collect reads frames until every stream in ids is done (END_STREAM or
// RST_STREAM) or timeout elapses.
func (c *rawH2Client) collect(t *testing.T, timeout time.Duration, ids ...uint32) map[uint32]*rawStreamResult {
	t.Helper()
	res := make(map[uint32]*rawStreamResult, len(ids))
	for _, id := range ids {
		res[id] = &rawStreamResult{}
	}
	allDone := func() bool {
		for _, r := range res {
			if !r.done() {
				return false
			}
		}
		return true
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = c.conn.SetReadDeadline(time.Time{}) }()
	for !allDone() {
		f, err := c.fr.ReadFrame()
		if err != nil {
			return res
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
			if r, ok := res[ff.StreamID]; ok {
				r.statuses = append(r.statuses, ff.PseudoValue("status"))
				if ff.StreamEnded() {
					r.ended = true
				}
			}
		case *http2.DataFrame:
			if r, ok := res[ff.StreamID]; ok && ff.StreamEnded() {
				r.ended = true
			}
		case *http2.RSTStreamFrame:
			if r, ok := res[ff.StreamID]; ok {
				r.rst = true
				r.rstCode = ff.ErrCode
			}
		}
	}
	return res
}

// startProxyForRefusedTest builds a production-shaped live stack (HTTP2Pool
// wired, empty intercept engine) recording into store.
func startProxyForRefusedTest(t *testing.T, ctx context.Context, store *flowStoreForH2Pool) string {
	t.Helper()
	return startProxyForH2PoolInterceptTest(t, ctx, store,
		httprules.NewInterceptEngine(), common.NewHoldQueue(), h2pool.New(h2pool.PoolOptions{}))
}

// streamOutcomes tallies recorded Streams by (State, FailureReason).
func streamOutcomes(streams []*flow.Stream) map[string]int {
	out := make(map[string]int)
	for _, st := range streams {
		out[st.State+"/"+st.FailureReason]++
	}
	return out
}

// waitStreamOutcomes polls store until the tally equals want or timeout.
func waitStreamOutcomes(t *testing.T, store *flowStoreForH2Pool, want map[string]int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var got map[string]int
	for {
		got = streamOutcomes(store.Streams())
		if fmt.Sprint(got) == fmt.Sprint(want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("recorded stream outcomes = %v, want %v", got, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestH2UpstreamGoAway_RefusedStreamsResetWithRefusedStream is the
// reporter's scenario at the wire: four parallel GETs, the origin processes
// one and GOAWAYs the rest. The three unprocessed streams must reach the
// client as RST_STREAM(REFUSED_STREAM) (RFC 9113 §8.7: safe to retry), not
// CANCEL; the processed stream completes with 200. Recording keeps the
// truth: one complete Stream, three state=error / failure_reason=refused.
func TestH2UpstreamGoAway_RefusedStreamsResetWithRefusedStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origin := startRefusingH2Origin(t, originGoAwayAfterFirst, 4)
	store := &flowStoreForH2Pool{}
	proxyAddr := startProxyForRefusedTest(t, ctx, store)

	cli := dialRawH2ThroughProxy(t, proxyAddr, origin.addr)
	ids := []uint32{1, 3, 5, 7}
	cli.sendGETs(t, origin.addr, ids...)
	res := cli.collect(t, 10*time.Second, ids...)

	var ok, refused int
	for _, id := range ids {
		r := res[id]
		switch {
		case r.ended && len(r.statuses) == 1 && r.statuses[0] == "200":
			ok++
		case r.rst && r.rstCode == http2.ErrCodeRefusedStream && len(r.statuses) == 0:
			refused++
		default:
			t.Errorf("stream %d: statuses=%v ended=%v rst=%v code=%v; want 200 or RST_STREAM(REFUSED_STREAM)",
				id, r.statuses, r.ended, r.rst, r.rstCode)
		}
	}
	if ok != 1 || refused != 3 {
		t.Errorf("client outcomes: %d x 200, %d x REFUSED_STREAM; want 1 and 3", ok, refused)
	}

	waitStreamOutcomes(t, store, map[string]int{"complete/": 1, "error/refused": 3}, 5*time.Second)

	// Every refused Stream still carries the request the proxy forwarded
	// (recording reflects what happened on the wire).
	sends := make(map[string]int)
	for _, f := range store.Flows() {
		if f.Direction == "send" {
			sends[f.StreamID]++
		}
	}
	for _, st := range store.Streams() {
		if st.Protocol != "http" {
			t.Errorf("stream %s protocol = %q, want http", st.ID, st.Protocol)
		}
		if sends[st.ID] == 0 {
			t.Errorf("stream %s (%s/%s) has no send flow recorded", st.ID, st.State, st.FailureReason)
		}
	}
}

// TestH2UpstreamGoAway_RetryingClientSucceeds proves the outcome a retrying
// client (x/net/http2.Transport, like Chrome) sees for the same origin: all
// four requests succeed, the three retries are served by a fresh upstream
// connection (the proxy redials once the GOAWAY'd Layer is stale), and the
// refused first attempts remain recorded as their own error Streams.
func TestH2UpstreamGoAway_RetryingClientSucceeds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origin := startRefusingH2Origin(t, originGoAwayAfterFirst, 4)
	store := &flowStoreForH2Pool{}
	proxyAddr := startProxyForRefusedTest(t, ctx, store)

	client := newH2ClientThroughProxyForPoolTest(proxyAddr, origin.addr)
	defer client.CloseIdleConnections()

	type result struct {
		status int
		conn   string
		err    error
	}
	results := make([]result, 4)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, _ := gohttp.NewRequestWithContext(ctx, gohttp.MethodGet,
				fmt.Sprintf("https://%s/req-%d", origin.addr, i), nil)
			resp, err := client.Do(req)
			if err != nil {
				results[i] = result{err: err}
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			results[i] = result{status: resp.StatusCode, conn: resp.Header.Get("x-origin-conn")}
		}(i)
	}
	wg.Wait()

	byConn := make(map[string]int)
	for i, r := range results {
		if r.err != nil || r.status != gohttp.StatusOK {
			t.Errorf("request %d: status=%d err=%v; want 200", i, r.status, r.err)
			continue
		}
		byConn[r.conn]++
	}
	if byConn["1"] != 1 {
		t.Errorf("responses served by origin conn 1 = %d, want 1 (only the processed stream); by conn = %v", byConn["1"], byConn)
	}
	if n := origin.accepts.Load(); n < 2 {
		t.Errorf("origin accepted %d connections, want >= 2 (retries go to a fresh upstream connection)", n)
	}

	waitStreamOutcomes(t, store, map[string]int{"complete/": 4, "error/refused": 3}, 5*time.Second)
}
