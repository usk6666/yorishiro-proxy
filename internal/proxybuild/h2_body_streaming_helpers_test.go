//go:build e2e

// Shared helpers for the USK-1401 HTTP/2 body-streaming integration tests
// (smoke: h2_body_streaming_smoke_integration_test.go; exhaustive:
// h2_body_streaming_integration_test.go). Both sides of the proxy can be
// driven at the frame level so DATA boundaries, END_STREAM placement and
// RST_STREAM codes are observed exactly as they cross the wire.
package proxybuild_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	h2pool "github.com/usk6666/yorishiro-proxy/internal/layer/http2/pool"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// h2StreamProxyOpts configures startH2StreamProxy. Zero values are the
// production defaults (no rule, no plugin: every body streams).
type h2StreamProxyOpts struct {
	transform *httprules.TransformEngine
	intercept *httprules.InterceptEngine
	holdQueue *common.HoldQueue
	safety    *httprules.SafetyEngine
	scope     *connector.TargetScope
	// recordCap is max_record_body_size (Deps + BuildConfig).
	recordCap int64
	// maxBody is max_body_size.
	maxBody        int64
	spillDir       string
	spillThreshold int64
}

// startH2StreamProxy boots a production-shaped BuildLiveStack listener
// (HTTP2Pool wired, the body-mode predicate built by BuildLiveStack from the
// engines) recording into store, and returns its address.
func startH2StreamProxy(t *testing.T, ctx context.Context, store flow.Writer, o h2StreamProxyOpts) string {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	bc := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
		HTTP2Pool:          h2pool.New(h2pool.PoolOptions{}),
		MaxBodySize:        o.maxBody,
		BodySpillDir:       o.spillDir,
		BodySpillThreshold: o.spillThreshold,
		RecordMaxBodySize:  o.recordCap,
	}
	stack, err := proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
		Logger:              testutil.DiscardLogger(),
		ListenerName:        "h2-body-streaming",
		ListenAddr:          "127.0.0.1:0",
		FlowStore:           store,
		BuildConfig:         bc,
		Scope:               o.scope,
		HTTPSafetyEngine:    o.safety,
		HTTPInterceptEngine: o.intercept,
		HTTPTransformEngine: o.transform,
		HoldQueue:           o.holdQueue,
		RecordMaxBodySize:   o.recordCap,
	})
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	go func() { _ = stack.Listener.Start(ctx) }()
	select {
	case <-stack.Listener.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("listener not ready in 5s")
	}
	return stack.Listener.Addr()
}

// h2Ev is one non-control frame a frame peer read, copied out of the
// Framer's reused buffers.
type h2Ev struct {
	kind   string // "headers", "data", "rst", "goaway"
	stream uint32
	data   []byte
	end    bool
	code   http2.ErrCode
	fields []hpack.HeaderField
}

func (e h2Ev) String() string {
	switch e.kind {
	case "data":
		return fmt.Sprintf("DATA(%d bytes end=%v)", len(e.data), e.end)
	case "rst":
		return fmt.Sprintf("RST(%v)", e.code)
	case "headers":
		return fmt.Sprintf("HEADERS(%v end=%v)", e.fields, e.end)
	default:
		return e.kind
	}
}

// field returns the value of name in a HEADERS event.
func (e h2Ev) field(name string) string {
	for _, f := range e.fields {
		if f.Name == name {
			return f.Value
		}
	}
	return ""
}

// h2Peer is a frame-level HTTP/2 endpoint (client or origin). One reader
// goroutine answers SETTINGS / PING and routes every other frame to the
// per-stream event channel; writes are serialised by wmu.
type h2Peer struct {
	conn net.Conn
	fr   *http2.Framer

	wmu sync.Mutex
	enc *hpack.Encoder
	buf bytes.Buffer

	mu      sync.Mutex
	streams map[uint32]chan h2Ev
	// onNewStream, when set, is called (on its own goroutine) for the first
	// HEADERS of a stream the peer did not open.
	onNewStream func(ev h2Ev)
	done        chan struct{}
}

func newH2Peer(conn net.Conn) *h2Peer {
	p := &h2Peer{
		conn:    conn,
		fr:      http2.NewFramer(conn, conn),
		streams: make(map[uint32]chan h2Ev),
		done:    make(chan struct{}),
	}
	p.enc = hpack.NewEncoder(&p.buf)
	p.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	p.fr.MaxHeaderListSize = 1 << 20
	return p
}

// stream returns the event channel of id, creating it.
func (p *h2Peer) stream(id uint32) chan h2Ev {
	p.mu.Lock()
	defer p.mu.Unlock()
	ch, ok := p.streams[id]
	if !ok {
		ch = make(chan h2Ev, 1024)
		p.streams[id] = ch
	}
	return ch
}

func (p *h2Peer) readLoop() {
	defer close(p.done)
	for {
		f, err := p.fr.ReadFrame()
		if err != nil {
			return
		}
		var ev h2Ev
		switch ff := f.(type) {
		case *http2.SettingsFrame:
			if !ff.IsAck() {
				p.wmu.Lock()
				_ = p.fr.WriteSettingsAck()
				p.wmu.Unlock()
			}
			continue
		case *http2.PingFrame:
			if !ff.IsAck() {
				p.wmu.Lock()
				_ = p.fr.WritePing(true, ff.Data)
				p.wmu.Unlock()
			}
			continue
		case *http2.MetaHeadersFrame:
			ev = h2Ev{kind: "headers", stream: ff.StreamID, end: ff.StreamEnded(),
				fields: append([]hpack.HeaderField(nil), ff.Fields...)}
		case *http2.DataFrame:
			ev = h2Ev{kind: "data", stream: ff.StreamID, end: ff.StreamEnded(),
				data: append([]byte(nil), ff.Data()...)}
			// Return the credit at once: the tests observe the proxy's
			// framing, not this peer's flow control.
			if n := uint32(len(ff.Data())); n > 0 {
				p.wmu.Lock()
				_ = p.fr.WriteWindowUpdate(0, n)
				if !ff.StreamEnded() {
					_ = p.fr.WriteWindowUpdate(ff.StreamID, n)
				}
				p.wmu.Unlock()
			}
		case *http2.RSTStreamFrame:
			ev = h2Ev{kind: "rst", stream: ff.StreamID, code: ff.ErrCode}
		case *http2.GoAwayFrame:
			ev = h2Ev{kind: "goaway", code: ff.ErrCode}
		default:
			continue
		}
		p.mu.Lock()
		_, known := p.streams[ev.stream]
		p.mu.Unlock()
		ch := p.stream(ev.stream)
		if !known && ev.kind == "headers" && p.onNewStream != nil {
			go p.onNewStream(ev)
		}
		select {
		case ch <- ev:
		default:
		}
	}
}

// writeHeaders writes one HEADERS frame (END_HEADERS) carrying fields.
// The write methods return errors instead of failing a test so origin
// scripts, which may outlive their test, never touch testing.T.
func (p *h2Peer) writeHeaders(id uint32, end bool, fields ...hpack.HeaderField) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	p.buf.Reset()
	for _, f := range fields {
		if err := p.enc.WriteField(f); err != nil {
			return err
		}
	}
	return p.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: id, BlockFragment: p.buf.Bytes(), EndStream: end, EndHeaders: true,
	})
}

func (p *h2Peer) writeData(id uint32, end bool, b []byte) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	return p.fr.WriteData(id, end, b)
}

func (p *h2Peer) writeRST(id uint32, code http2.ErrCode) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	return p.fr.WriteRSTStream(id, code)
}

func (p *h2Peer) writeGoAway(lastID uint32) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	return p.fr.WriteGoAway(lastID, http2.ErrCodeNo, nil)
}

// mustWrite fails t when a test-side write failed.
func mustWrite(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("frame write: %v", err)
	}
}

// next waits for the next event on stream id.
func (p *h2Peer) next(t *testing.T, id uint32, timeout time.Duration) (h2Ev, bool) {
	t.Helper()
	select {
	case ev := <-p.stream(id):
		return ev, true
	case <-time.After(timeout):
		return h2Ev{}, false
	}
}

// collectUntilEnd reads events of stream id until END_STREAM or RST_STREAM
// (or timeout) and returns them.
func (p *h2Peer) collectUntilEnd(t *testing.T, id uint32, timeout time.Duration) []h2Ev {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var out []h2Ev
	for {
		left := time.Until(deadline)
		if left <= 0 {
			return out
		}
		ev, ok := p.next(t, id, left)
		if !ok {
			return out
		}
		out = append(out, ev)
		if ev.kind == "rst" || ev.end {
			return out
		}
	}
}

// dialH2PeerThroughProxy opens a CONNECT tunnel + TLS(h2) to target through
// proxyAddr and returns a client frame peer (preface and SETTINGS sent).
func dialH2PeerThroughProxy(t *testing.T, proxyAddr, target string) *h2Peer {
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
	if _, err := tc.Write([]byte(http2.ClientPreface)); err != nil {
		tc.Close()
		t.Fatalf("write preface: %v", err)
	}
	p := newH2Peer(tc)
	if err := p.fr.WriteSettings(); err != nil {
		tc.Close()
		t.Fatalf("write SETTINGS: %v", err)
	}
	go p.readLoop()
	t.Cleanup(func() { _ = tc.Close() })
	return p
}

// dialH2PeerDirect dials a cleartext h2 (prior knowledge) listener and
// returns a client frame peer.
func dialH2PeerDirect(t *testing.T, addr string) *h2Peer {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	if _, err := c.Write([]byte(http2.ClientPreface)); err != nil {
		c.Close()
		t.Fatalf("write preface: %v", err)
	}
	p := newH2Peer(c)
	if err := p.fr.WriteSettings(); err != nil {
		c.Close()
		t.Fatalf("write SETTINGS: %v", err)
	}
	go p.readLoop()
	t.Cleanup(func() { _ = c.Close() })
	return p
}

// requestFields returns the pseudo-headers of a request to authority.
func requestFields(method, authority, path string, extra ...hpack.HeaderField) []hpack.HeaderField {
	out := []hpack.HeaderField{
		{Name: ":method", Value: method},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: path},
	}
	return append(out, extra...)
}

// scriptedH2Origin is a TLS h2 origin driven at the frame level: script runs
// on its own goroutine for every request stream the proxy opens, with the
// origin-side peer and the request HEADERS event.
type scriptedH2Origin struct {
	addr string
	ln   net.Listener

	mu    sync.Mutex
	peers []*h2Peer
	wg    sync.WaitGroup
}

func startScriptedH2Origin(t *testing.T, script func(conn int, p *h2Peer, req h2Ev)) *scriptedH2Origin {
	t.Helper()
	return startScriptedH2OriginOn(t, listenTLSH2Origin(t), script)
}

// startScriptedH2OriginH2C is startScriptedH2Origin over cleartext h2
// (prior knowledge), for tcp_forwards without upstream_tls.
func startScriptedH2OriginH2C(t *testing.T, script func(conn int, p *h2Peer, req h2Ev)) *scriptedH2Origin {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return startScriptedH2OriginOn(t, ln, script)
}

func startScriptedH2OriginOn(t *testing.T, ln net.Listener, script func(conn int, p *h2Peer, req h2Ev)) *scriptedH2Origin {
	t.Helper()
	o := &scriptedH2Origin{ln: ln}
	o.addr = o.ln.Addr().String()
	go func() {
		idx := 0
		for {
			c, err := o.ln.Accept()
			if err != nil {
				return
			}
			idx++
			connIdx := idx
			o.wg.Add(1)
			go func() {
				defer o.wg.Done()
				defer c.Close()
				preface := make([]byte, len(http2.ClientPreface))
				if _, err := io.ReadFull(c, preface); err != nil {
					return
				}
				p := newH2Peer(c)
				p.onNewStream = func(ev h2Ev) { script(connIdx, p, ev) }
				o.mu.Lock()
				o.peers = append(o.peers, p)
				o.mu.Unlock()
				p.wmu.Lock()
				_ = p.fr.WriteSettings()
				p.wmu.Unlock()
				p.readLoop()
			}()
		}
	}()
	t.Cleanup(func() {
		_ = o.ln.Close()
		o.mu.Lock()
		for _, p := range o.peers {
			_ = p.conn.Close()
		}
		o.mu.Unlock()
		done := make(chan struct{})
		go func() { o.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	})
	return o
}

// gateCh is a one-shot signal.
type gateCh struct {
	ch   chan struct{}
	once sync.Once
}

func newGateCh() *gateCh { return &gateCh{ch: make(chan struct{})} }

func (g *gateCh) open() { g.once.Do(func() { close(g.ch) }) }

// wait reports whether the gate opened within timeout.
func (g *gateCh) wait(timeout time.Duration) bool {
	select {
	case <-g.ch:
		return true
	case <-time.After(timeout):
		return false
	}
}

// streamingSemanticFlows returns the semantic (non-overlay) flows of direction.
func streamingSemanticFlows(store *flowStoreForH2Pool, direction string) []*flow.Flow {
	var out []*flow.Flow
	for _, f := range store.Flows() {
		if f.Direction == direction && (f.WireLevel == "" || f.WireLevel == flow.WireLevelSemantic) {
			out = append(out, f)
		}
	}
	return out
}

// waitSemanticFlow polls until a semantic flow of direction is recorded.
func waitSemanticFlow(t *testing.T, store *flowStoreForH2Pool, direction string, timeout time.Duration) *flow.Flow {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if fs := streamingSemanticFlows(store, direction); len(fs) > 0 {
			return fs[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s flow recorded within %v", direction, timeout)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// dataPayloads concatenates the DATA payloads of evs and reports their
// frame sizes.
func dataPayloads(evs []h2Ev) (body []byte, sizes []int) {
	for _, ev := range evs {
		if ev.kind == "data" {
			body = append(body, ev.data...)
			sizes = append(sizes, len(ev.data))
		}
	}
	return body, sizes
}
