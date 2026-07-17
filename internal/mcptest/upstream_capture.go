package mcptest

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// h2ClientPreface is the fixed 24-byte HTTP/2 connection preface every h2
// client sends before its first frame (RFC 9113 §3.4). Defined locally so
// the capture upstream does not import the whole internal/layer/http2 Layer
// package for a single constant.
const h2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// captureConnDeadline bounds every read/write on a captured upstream
// connection so a stalled proxy dial can never wedge the accept goroutine
// or a per-connection handler past test teardown (Concurrency Checklist:
// explicit termination for every goroutine).
const captureConnDeadline = 10 * time.Second

// UpstreamCapture is the wire-observing upstream stood up by
// HarnessOptions.UpstreamProto == "capture". Unlike the GREASE-sniffing
// FingerprintObserver (which only inspects crypto/tls's parsed
// *tls.ClientHelloInfo), UpstreamCapture records the *raw* proxy→upstream
// ClientHello record bytes plus the proxy's HTTP/2 send-shape (SETTINGS in
// wire order, the stream-0 WINDOW_UPDATE increment, and the request
// pseudo-header order). This is the artifact USK-1011 asserts Firefox
// coherence against.
//
// Capture strategy (USK-1011 design decision #2/#3):
//   - Peek-then-replay the initial TLS record(s) off the raw net.Conn so
//     the exact ClientHello bytes are retained (tlsfingerprint.Compute needs
//     raw bytes; GetConfigForClient only exposes a parsed struct), then hand
//     a prefix-wrapped conn to tls.Server to finish the handshake.
//   - After ALPN=h2, read the client preface and parse frames with
//     internal/layer/http2/frame + hpack, capturing the first non-ACK
//     SETTINGS, the first stream-0 WINDOW_UPDATE, and the first HEADERS
//     block's pseudo-header order.
//   - Send a minimal SETTINGS + HEADERS(:status 200) + DATA(end_stream)
//     response so the proxy relays a complete response and the flow records
//     State=complete.
//
// Concurrency: all captured fields are guarded by mu. The done channel is
// closed exactly once (via doneOnce) when every H2 artifact has been
// captured, so WaitH2 has a single-writer close owner. Close() stops the
// accept goroutine, force-closes any in-flight connections, and joins every
// goroutine.
type UpstreamCapture struct {
	ln     net.Listener
	tlsCfg *tls.Config

	mu            sync.Mutex
	clientHello   []byte
	alpn          string
	settings      []frame.Setting
	haveSettings  bool
	connWindowInc uint32
	haveWindow    bool
	pseudoOrder   []string
	havePseudo    bool

	done     chan struct{}
	doneOnce sync.Once

	connMu    sync.Mutex
	conns     []net.Conn
	closed    bool
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// CaptureResult is an atomic snapshot of everything UpstreamCapture has
// observed at the moment Snapshot is called. Slice fields are deep copies so
// the caller may read them without holding the capture's lock.
type CaptureResult struct {
	// ClientHelloRecord is the raw proxy→upstream TLS ClientHello record,
	// including the 5-byte TLS record header — ready to hand to
	// tlsfingerprint.Compute.
	ClientHelloRecord []byte
	// ALPN is the protocol the upstream TLS handshake negotiated. The
	// capture upstream advertises only "h2", so anything else means the
	// proxy did not offer h2 upstream.
	ALPN string
	// Settings is the proxy's first non-ACK SETTINGS frame params in wire
	// order.
	Settings []frame.Setting
	// ConnWindowIncrement is the proxy's first stream-0 WINDOW_UPDATE
	// increment (the connection-level window bump after the preface).
	ConnWindowIncrement uint32
	// PseudoOrder is the request pseudo-header order (":"-prefixed field
	// names) from the proxy's first HEADERS block, in wire order.
	PseudoOrder []string
}

// Addr returns the capture upstream's loopback listen address
// (127.0.0.1:port). Tests derive the CONNECT target and TLS ServerName from
// it.
func (c *UpstreamCapture) Addr() string {
	return c.ln.Addr().String()
}

// Snapshot returns an atomic copy of the captured artifacts.
func (c *UpstreamCapture) Snapshot() CaptureResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	res := CaptureResult{
		ALPN:                c.alpn,
		ConnWindowIncrement: c.connWindowInc,
	}
	if c.clientHello != nil {
		res.ClientHelloRecord = append([]byte(nil), c.clientHello...)
	}
	if c.settings != nil {
		res.Settings = append([]frame.Setting(nil), c.settings...)
	}
	if c.pseudoOrder != nil {
		res.PseudoOrder = append([]string(nil), c.pseudoOrder...)
	}
	return res
}

// WaitH2 blocks until every HTTP/2 artifact (ALPN=h2, SETTINGS, conn
// WINDOW_UPDATE, and the request pseudo-header order) has been captured, or
// the timeout elapses. It reports whether the full set was captured in time.
func (c *UpstreamCapture) WaitH2(timeout time.Duration) bool {
	select {
	case <-c.done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// Close stops the accept loop, force-closes any in-flight connections, and
// waits for every goroutine to exit. Idempotent.
func (c *UpstreamCapture) Close() error {
	c.closeOnce.Do(func() {
		c.connMu.Lock()
		c.closed = true
		conns := c.conns
		c.conns = nil
		c.connMu.Unlock()

		_ = c.ln.Close()
		for _, conn := range conns {
			_ = conn.Close()
		}
		c.wg.Wait()
	})
	return nil
}

// trackConn registers conn for force-close on teardown. It returns false if
// the capture is already closing, in which case the caller must abandon the
// connection immediately.
func (c *UpstreamCapture) trackConn(conn net.Conn) bool {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	if c.closed {
		return false
	}
	c.conns = append(c.conns, conn)
	return true
}

// maybeSignalDone closes done once the full H2 artifact set is present. Must
// be called with c.mu held.
func (c *UpstreamCapture) maybeSignalDone() {
	if c.alpn == "h2" && c.haveSettings && c.haveWindow && c.havePseudo {
		c.doneOnce.Do(func() { close(c.done) })
	}
}

// acceptLoop accepts connections until the listener is closed, handing each
// to a per-connection handler goroutine.
func (c *UpstreamCapture) acceptLoop() {
	defer c.wg.Done()
	for {
		conn, err := c.ln.Accept()
		if err != nil {
			return // listener closed
		}
		if !c.trackConn(conn) {
			_ = conn.Close()
			return
		}
		c.wg.Add(1)
		go c.handleConn(conn)
	}
}

// handleConn drives one upstream connection: peek+replay the ClientHello,
// finish the TLS handshake, then (if h2) capture the proxy's H2 send-shape
// and answer with a minimal response so the proxy's flow completes.
func (c *UpstreamCapture) handleConn(raw net.Conn) {
	defer c.wg.Done()
	defer raw.Close()

	_ = raw.SetDeadline(time.Now().Add(captureConnDeadline))

	record, err := readFirstTLSRecord(raw)
	if err != nil {
		return
	}

	tlsConn := tls.Server(&prefixConn{Conn: raw, prefix: record}, c.tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	alpn := tlsConn.ConnectionState().NegotiatedProtocol

	// Commit the ClientHello + ALPN immediately so a non-h2 negotiation is
	// still observable (the test guards on ALPN and fails loudly rather
	// than silently skipping the H2 assertions).
	c.mu.Lock()
	c.clientHello = record
	c.alpn = alpn
	c.mu.Unlock()

	if alpn != "h2" {
		return
	}
	c.serveH2(tlsConn)
}

// serveH2 reads the proxy's H2 preface + frames, captures the send-shape,
// and writes a minimal response. It returns when the peer closes or a read
// deadline fires.
func (c *UpstreamCapture) serveH2(conn net.Conn) {
	if err := readClientPreface(conn); err != nil {
		return
	}

	rd := frame.NewReader(conn)
	wr := frame.NewWriter(conn)

	// The server preface SETTINGS must be the first frame we send. An empty
	// SETTINGS frame is valid and keeps our advertised limits at the RFC
	// defaults.
	if err := wr.WriteSettings(nil); err != nil {
		return
	}

	responded := false
	for {
		_ = conn.SetReadDeadline(time.Now().Add(captureConnDeadline))
		f, err := rd.ReadFrame()
		if err != nil {
			return
		}
		if !c.handleFrame(f, rd, wr, &responded) {
			return
		}
	}
}

// handleFrame captures the send-shape carried by one frame and, on the first
// HEADERS, writes the minimal response. It returns false when the caller
// should stop serving (a fatal frame error).
func (c *UpstreamCapture) handleFrame(f *frame.Frame, rd *frame.Reader, wr *frame.Writer, responded *bool) bool {
	switch f.Header.Type {
	case frame.TypeSettings:
		return c.handleSettings(f, rd, wr)
	case frame.TypeWindowUpdate:
		return c.handleWindowUpdate(f)
	case frame.TypeHeaders:
		return c.handleHeaders(f, wr, responded)
	default:
		return true
	}
}

// handleSettings records the peer's first non-ACK SETTINGS, applies its
// MAX_FRAME_SIZE to the reader, and ACKs it.
func (c *UpstreamCapture) handleSettings(f *frame.Frame, rd *frame.Reader, wr *frame.Writer) bool {
	if f.Header.Flags.Has(frame.FlagAck) {
		return true
	}
	params, err := f.SettingsParams()
	if err != nil {
		return false
	}
	c.mu.Lock()
	c.settings = params
	c.haveSettings = true
	c.maybeSignalDone()
	c.mu.Unlock()
	for _, s := range params {
		if s.ID == frame.SettingMaxFrameSize {
			_ = rd.SetMaxFrameSize(s.Value)
		}
	}
	return wr.WriteSettingsAck() == nil
}

// handleWindowUpdate records the FIRST stream-0 WINDOW_UPDATE increment —
// the connection-window bump the client sends right after its preface
// SETTINGS. Later stream-0 updates (e.g. the proxy replenishing the window
// after relaying our response body) must not clobber it.
func (c *UpstreamCapture) handleWindowUpdate(f *frame.Frame) bool {
	if f.Header.StreamID != 0 {
		return true
	}
	inc, err := f.WindowUpdateIncrement()
	if err != nil {
		return false
	}
	c.mu.Lock()
	if !c.haveWindow {
		c.connWindowInc = inc
		c.haveWindow = true
		c.maybeSignalDone()
	}
	c.mu.Unlock()
	return true
}

// handleHeaders records the first HEADERS block's pseudo-header order and
// answers the request.
func (c *UpstreamCapture) handleHeaders(f *frame.Frame, wr *frame.Writer, responded *bool) bool {
	if *responded {
		return true
	}
	order, ok := decodePseudoOrder(f)
	if !ok {
		return false
	}
	c.mu.Lock()
	c.pseudoOrder = order
	c.havePseudo = true
	c.maybeSignalDone()
	c.mu.Unlock()
	if err := writeMinimalResponse(wr, f.Header.StreamID); err != nil {
		return false
	}
	*responded = true
	return true
}

// decodePseudoOrder HPACK-decodes a HEADERS frame's block and returns the
// leading pseudo-header names (":"-prefixed) in wire order.
func decodePseudoOrder(f *frame.Frame) ([]string, bool) {
	block, err := f.HeaderBlockFragment()
	if err != nil {
		return nil, false
	}
	// A 65536-byte decoder table matches the Firefox encoder's larger table
	// so a table-size update never trips the decoder.
	dec := hpack.NewDecoder(65536)
	fields, err := dec.Decode(block)
	if err != nil {
		return nil, false
	}
	var out []string
	for _, hf := range fields {
		if len(hf.Name) == 0 || hf.Name[0] != ':' {
			break
		}
		out = append(out, hf.Name)
	}
	return out, true
}

// writeMinimalResponse answers streamID with :status 200 and a short
// end-stream DATA frame so the proxy relays a complete response.
func writeMinimalResponse(wr *frame.Writer, streamID uint32) error {
	enc := hpack.NewEncoder(4096, false)
	block := enc.Encode([]hpack.HeaderField{{Name: ":status", Value: "200"}})
	if err := wr.WriteHeaders(streamID, false, true, block); err != nil {
		return err
	}
	return wr.WriteData(streamID, true, []byte("fingerprint-coherence-ok"))
}

// readFirstTLSRecord reads exactly one TLS record (5-byte header + payload)
// and returns the full record bytes. The proxy's ClientHello fits in the
// first record for every profile under test, so this is the raw ClientHello
// record tlsfingerprint.Compute consumes.
func readFirstTLSRecord(r io.Reader) ([]byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("read TLS record header: %w", err)
	}
	recLen := int(hdr[3])<<8 | int(hdr[4])
	if recLen <= 0 || recLen > 1<<16 {
		return nil, fmt.Errorf("implausible TLS record length %d", recLen)
	}
	rec := make([]byte, 5+recLen)
	copy(rec, hdr[:])
	if _, err := io.ReadFull(r, rec[5:]); err != nil {
		return nil, fmt.Errorf("read TLS record body: %w", err)
	}
	return rec, nil
}

// readClientPreface consumes and validates the 24-byte HTTP/2 client
// preface.
func readClientPreface(r io.Reader) error {
	buf := make([]byte, len(h2ClientPreface))
	if _, err := io.ReadFull(r, buf); err != nil {
		return fmt.Errorf("read h2 preface: %w", err)
	}
	if !bytes.Equal(buf, []byte(h2ClientPreface)) {
		return fmt.Errorf("bad h2 preface: %q", buf)
	}
	return nil
}

// prefixConn is a net.Conn that first serves buffered prefix bytes (the
// peeked TLS record) before reading from the underlying conn, so tls.Server
// re-parses the original ClientHello from the wire bytes we retained.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// buildCaptureUpstream stands up the wire-observing upstream and returns a
// *httptest.Server shell (URL + Listener + Config, matching the gRPC
// upstream pattern) alongside the *UpstreamCapture handle the test asserts
// against. The listener advertises ALPN "h2" ONLY so the upstream leg
// negotiates HTTP/2 (or fails the ALPN guard loudly).
func buildCaptureUpstream() (*httptest.Server, *UpstreamCapture, error) {
	leaf, err := newSelfSignedLeaf("localhost", "127.0.0.1")
	if err != nil {
		return nil, nil, fmt.Errorf("self-signed leaf: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, fmt.Errorf("listen: %w", err)
	}

	capture := &UpstreamCapture{
		ln:     ln,
		tlsCfg: tlsCfg,
		done:   make(chan struct{}),
	}
	capture.wg.Add(1)
	go capture.acceptLoop()

	srv := &httptest.Server{
		Listener: &captureListener{cap: capture},
		Config:   &http.Server{},
		URL:      "https://" + ln.Addr().String(),
		TLS:      tlsCfg,
	}
	return srv, capture, nil
}

// captureListener adapts UpstreamCapture to the net.Listener the harness's
// httptest.Server shell holds: the harness cleanup path calls
// srv.Listener.Close, which we route to UpstreamCapture.Close for a clean,
// goroutine-joining teardown. Accept is never called on this adapter (the
// capture owns its own accept loop); it exists only to satisfy the
// interface.
type captureListener struct {
	cap *UpstreamCapture
}

func (l *captureListener) Accept() (net.Conn, error) {
	return nil, fmt.Errorf("captureListener.Accept: not used")
}

func (l *captureListener) Close() error { return l.cap.Close() }

func (l *captureListener) Addr() net.Addr { return l.cap.ln.Addr() }
