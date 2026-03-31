package http2

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	gohttp "net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

// clientPreface is the HTTP/2 connection preface that a client must send
// before any frames per RFC 9113 Section 3.4.
const clientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// Transport is an HTTP/2 upstream transport that uses the custom frame engine.
// It manages connection pooling and supports uTLS/mTLS through httputil.TLSTransport.
//
// Transport is safe for concurrent use.
type Transport struct {
	// TLSTransport provides TLS connection establishment (standard or uTLS).
	// If nil, the standard crypto/tls library is used with InsecureSkipVerify.
	TLSTransport httputil.TLSTransport

	// Logger is the structured logger. If nil, slog.Default() is used.
	Logger *slog.Logger

	// DialTimeout is the timeout for TCP connection establishment.
	// Defaults to 30 seconds if zero.
	DialTimeout time.Duration

	// pool manages persistent HTTP/2 connections keyed by host:port.
	pool connPool
}

// connPool manages a pool of HTTP/2 upstream connections keyed by host:port.
type connPool struct {
	mu    sync.Mutex
	conns map[string]*transportConn
}

// RoundTripResult holds the result of an HTTP/2 round trip.
type RoundTripResult struct {
	// Response is the parsed HTTP response.
	Response *gohttp.Response
	// ServerAddr is the remote address of the upstream server.
	ServerAddr string
	// RawFrames contains the raw response frame bytes for L4 recording.
	RawFrames [][]byte

	// StatusCode is the HTTP status code from the :status pseudo-header.
	// Set by RoundTripOnConn; RoundTrip also populates Response.StatusCode.
	StatusCode int
	// Headers contains the decoded response HPACK header fields (including
	// pseudo-headers). Set by RoundTripOnConn to avoid lossy net/http.Header
	// conversion.
	Headers []hpack.HeaderField
	// Body is a reader over the response DATA frame payloads.
	// Set by RoundTripOnConn.
	Body io.Reader
}

// RoundTrip sends an HTTP request to the upstream server using the custom
// HTTP/2 frame engine and returns the response.
func (t *Transport) RoundTrip(ctx context.Context, req *gohttp.Request) (*RoundTripResult, error) {
	host := req.URL.Host
	if !strings.Contains(host, ":") {
		if req.URL.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	tc, err := t.getOrDialConn(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("transport round trip: %w", err)
	}

	result, err := tc.roundTrip(ctx, req)
	if err != nil {
		// Remove broken connections from pool.
		t.removeConn(host, tc)
		return nil, fmt.Errorf("transport round trip: %w", err)
	}
	return result, nil
}

// SendRawFrames writes pre-formed HTTP/2 frame bytes to the upstream server
// and waits for the response. This is used for raw mode intercept forwarding
// where the AI agent has edited the raw frame bytes directly.
//
// The rawBytes are written to the upstream connection after allocating a stream
// ID and rewriting stream IDs in the raw frames. The response is read via the
// normal frame read loop.
//
// HPACK note: Since raw bytes may contain HEADERS frames with HPACK-encoded
// header blocks, the upstream HPACK decoder state may become inconsistent with
// the encoder state used by the client. The transport's HPACK encoder is NOT
// used for raw frames — they are forwarded as-is. This is intentional: raw
// mode is a diagnostic tool where the operator accepts responsibility for
// protocol-level consequences.
func (t *Transport) SendRawFrames(ctx context.Context, req *gohttp.Request, rawBytes []byte) (*RoundTripResult, error) {
	host := req.URL.Host
	if !strings.Contains(host, ":") {
		if req.URL.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	tc, err := t.getOrDialConn(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("transport send raw frames: %w", err)
	}

	result, err := tc.sendRawFrames(ctx, rawBytes)
	if err != nil {
		t.removeConn(host, tc)
		return nil, fmt.Errorf("transport send raw frames: %w", err)
	}
	return result, nil
}

// RoundTripOnConn performs an HTTP/2 round trip on a pre-established connection.
// The connection must already have negotiated "h2" via ALPN. This method handles
// the HTTP/2 handshake (connection preface + settings exchange), sends the
// request headers and body as HTTP/2 frames, and returns the raw response
// without converting through net/http types.
//
// The headers parameter must include HTTP/2 pseudo-headers (:method, :scheme,
// :authority, :path) and any regular headers. The body parameter may be nil.
//
// RoundTripOnConn takes ownership of conn and closes it before returning.
// The caller must NOT close conn after calling this method.
func (t *Transport) RoundTripOnConn(ctx context.Context, conn net.Conn, headers []hpack.HeaderField, body io.Reader) (*RoundTripResult, error) {
	logger := t.logger()

	tc := newTransportConn(conn, logger)
	defer tc.close()

	if err := tc.handshake(ctx); err != nil {
		return nil, fmt.Errorf("h2 handshake: %w", err)
	}

	result, err := tc.roundTripRaw(ctx, headers, body)
	if err != nil {
		return nil, fmt.Errorf("h2 round trip on conn: %w", err)
	}
	return result, nil
}

// CloseIdleConnections closes all idle connections in the pool.
func (t *Transport) CloseIdleConnections() {
	t.pool.mu.Lock()
	conns := t.pool.conns
	t.pool.conns = nil
	t.pool.mu.Unlock()

	for _, tc := range conns {
		tc.close()
	}
}

// logger returns the configured logger or slog.Default().
func (t *Transport) logger() *slog.Logger {
	if t.Logger != nil {
		return t.Logger
	}
	return slog.Default()
}

// dialTimeout returns the configured dial timeout or the default.
func (t *Transport) dialTimeout() time.Duration {
	if t.DialTimeout > 0 {
		return t.DialTimeout
	}
	return 30 * time.Second
}

// getOrDialConn returns an existing pooled connection or dials a new one.
func (t *Transport) getOrDialConn(ctx context.Context, hostPort string) (*transportConn, error) {
	t.pool.mu.Lock()
	if t.pool.conns != nil {
		if tc, ok := t.pool.conns[hostPort]; ok {
			if !tc.conn.IsClosed() {
				t.pool.mu.Unlock()
				return tc, nil
			}
			delete(t.pool.conns, hostPort)
		}
	}
	t.pool.mu.Unlock()

	tc, err := t.dialConn(ctx, hostPort)
	if err != nil {
		return nil, err
	}

	t.pool.mu.Lock()
	if t.pool.conns == nil {
		t.pool.conns = make(map[string]*transportConn)
	}
	// If another goroutine raced and added a conn, prefer the existing one.
	if existing, ok := t.pool.conns[hostPort]; ok && !existing.conn.IsClosed() {
		t.pool.mu.Unlock()
		tc.close()
		return existing, nil
	}
	t.pool.conns[hostPort] = tc
	t.pool.mu.Unlock()

	return tc, nil
}

// removeConn removes a specific connection from the pool.
func (t *Transport) removeConn(hostPort string, tc *transportConn) {
	t.pool.mu.Lock()
	if t.pool.conns != nil && t.pool.conns[hostPort] == tc {
		delete(t.pool.conns, hostPort)
	}
	t.pool.mu.Unlock()
	tc.close()
}

// dialConn establishes a new HTTP/2 connection to the upstream server.
func (t *Transport) dialConn(ctx context.Context, hostPort string) (*transportConn, error) {
	logger := t.logger()

	rawConn, err := (&net.Dialer{Timeout: t.dialTimeout()}).DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", hostPort, err)
	}

	serverName, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("parse host port %s: %w", hostPort, err)
	}

	var netConn net.Conn
	if t.TLSTransport != nil {
		tlsConn, proto, tlsErr := t.TLSTransport.TLSConnect(ctx, rawConn, serverName)
		if tlsErr != nil {
			rawConn.Close()
			return nil, fmt.Errorf("TLS connect to %s: %w", hostPort, tlsErr)
		}
		if proto != "h2" {
			tlsConn.Close()
			return nil, fmt.Errorf("ALPN negotiation failed for %s: got %q, want \"h2\"", hostPort, proto)
		}
		netConn = tlsConn
	} else {
		tlsCfg := &tls.Config{
			ServerName:         serverName,
			NextProtos:         []string{"h2"},
			InsecureSkipVerify: true, //nolint:gosec // proxy requires MITM
			MinVersion:         tls.VersionTLS12,
		}
		tlsConn := tls.Client(rawConn, tlsCfg)
		if tlsErr := tlsConn.HandshakeContext(ctx); tlsErr != nil {
			rawConn.Close()
			return nil, fmt.Errorf("TLS handshake with %s: %w", hostPort, tlsErr)
		}
		if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
			tlsConn.Close()
			return nil, fmt.Errorf("ALPN negotiation failed for %s: got %q, want \"h2\"",
				hostPort, tlsConn.ConnectionState().NegotiatedProtocol)
		}
		netConn = tlsConn
	}

	tc := newTransportConn(netConn, logger)
	if err := tc.handshake(ctx); err != nil {
		netConn.Close()
		return nil, fmt.Errorf("HTTP/2 handshake with %s: %w", hostPort, err)
	}

	logger.Debug("HTTP/2 upstream connection established", "host", hostPort)
	return tc, nil
}

// transportConn manages a single HTTP/2 upstream connection.
// It handles frame I/O, stream multiplexing, and flow control.
type transportConn struct {
	netConn net.Conn
	conn    *Conn
	writer  *frame.Writer
	reader  *frame.Reader
	encoder *hpack.Encoder
	decoder *hpack.Decoder
	logger  *slog.Logger

	// writeMu serializes frame writes to the connection.
	writeMu sync.Mutex

	// nextStreamID is the next client-initiated stream ID (odd numbers).
	nextStreamID atomic.Uint32

	// streams maps stream IDs to their pending response channels.
	streamsMu sync.Mutex
	streams   map[uint32]*streamState

	// streamingStreams maps stream IDs to streaming handlers.
	// Used by RoundTripStream for pipe-based response body delivery.
	streamingStreams map[uint32]*streamingStreamState

	// readLoopDone is closed when the background read loop exits.
	readLoopDone chan struct{}
	// closeOnce ensures the connection is closed exactly once.
	closeOnce sync.Once
}

// streamState tracks the state of an in-flight request on a stream.
type streamState struct {
	// headers collects decoded response header fields.
	headers []hpack.HeaderField
	// data collects response DATA payloads.
	data []byte
	// headerBuf accumulates HEADERS/CONTINUATION fragments before END_HEADERS.
	// Kept separate from data to prevent trailer header fragments from
	// overwriting accumulated response body bytes.
	headerBuf []byte
	// rawFrames collects raw frame bytes for L4 recording.
	rawFrames [][]byte
	// done is sent the completed response (or an error).
	done chan streamResult
	// headersDone is closed when the response HEADERS have been fully received.
	headersDone chan struct{}
	// endStream indicates END_STREAM has been received.
	endStream bool
	// trailers collects decoded trailer header fields.
	trailers []hpack.HeaderField
}

// streamResult is sent on streamState.done when the stream completes.
type streamResult struct {
	err error
}

// frameReadResult holds a frame or error from a background reader goroutine.
type frameReadResult struct {
	f   *frame.Frame
	err error
}

// newTransportConn creates a new transport connection.
func newTransportConn(netConn net.Conn, logger *slog.Logger) *transportConn {
	tc := &transportConn{
		netConn:      netConn,
		conn:         NewConn(),
		writer:       frame.NewWriter(netConn),
		reader:       frame.NewReader(netConn),
		encoder:      hpack.NewEncoder(defaultHeaderTableSize, true),
		decoder:      hpack.NewDecoder(defaultHeaderTableSize),
		logger:       logger,
		streams:      make(map[uint32]*streamState),
		readLoopDone: make(chan struct{}),
	}
	tc.nextStreamID.Store(1)
	return tc
}

// handshake performs the HTTP/2 connection preface and settings exchange.
//
// The handshake uses a background goroutine to read the server's initial
// SETTINGS frame while the client sends its preface and SETTINGS. This avoids
// deadlocks on synchronous transports (e.g. net.Pipe) where both sides must
// read in order for writes to complete.
func (tc *transportConn) handshake(ctx context.Context) error {
	// Start reading server frames in the background to avoid deadlocks
	// on synchronous connections (e.g. net.Pipe).
	serverFrames := make(chan frameReadResult, 4)
	go tc.readFramesIntoChannel(serverFrames)

	// Send client connection preface and initial SETTINGS.
	if err := tc.sendClientPreface(); err != nil {
		return err
	}

	// Read and process server's initial SETTINGS from the background reader.
	if err := tc.receiveServerSettings(ctx, serverFrames); err != nil {
		return err
	}

	// Send SETTINGS ACK for server's settings.
	if err := tc.writer.WriteSettingsAck(); err != nil {
		return fmt.Errorf("send SETTINGS ACK: %w", err)
	}

	// Update reader and writer max frame size from peer settings. This must
	// happen before the readLoop goroutine processes new frames from the
	// background reader, since readFramesIntoChannel accesses the reader's
	// maxFrameSize field concurrently. The frame channel buffer (capacity 4)
	// ensures the background reader has room to enqueue frames without
	// blocking, allowing applyPeerFrameSize to complete before the readLoop
	// starts consuming.
	tc.applyPeerFrameSize()

	// The handshake reader goroutine continues reading from tc.reader and
	// feeding frames into the channel. The readLoop consumes from the same
	// channel, so no goroutine transition is needed.
	go tc.readLoopFromChannel(serverFrames)

	return nil
}

// readFramesIntoChannel reads frames from the connection and sends them into
// the provided channel. It runs until an error occurs or readLoopDone is closed.
func (tc *transportConn) readFramesIntoChannel(ch chan<- frameReadResult) {
	for {
		f, err := tc.reader.ReadFrame()
		select {
		case ch <- frameReadResult{f, err}:
		case <-tc.readLoopDone:
			return
		}
		if err != nil {
			return
		}
	}
}

// sendClientPreface sends the HTTP/2 client connection preface and initial
// SETTINGS frame to the server.
func (tc *transportConn) sendClientPreface() error {
	if _, err := tc.netConn.Write([]byte(clientPreface)); err != nil {
		return fmt.Errorf("send client preface: %w", err)
	}
	if err := tc.writer.WriteSettings([]frame.Setting{
		{ID: frame.SettingEnablePush, Value: 0},
		{ID: frame.SettingMaxConcurrentStreams, Value: defaultMaxConcurrentStreams},
		{ID: frame.SettingInitialWindowSize, Value: defaultInitialWindowSize},
	}); err != nil {
		return fmt.Errorf("send initial SETTINGS: %w", err)
	}
	return nil
}

// receiveServerSettings reads frames from the background reader channel until
// the server's initial SETTINGS frame is received and processed.
func (tc *transportConn) receiveServerSettings(ctx context.Context, serverFrames <-chan frameReadResult) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case r := <-serverFrames:
			if r.err != nil {
				return fmt.Errorf("read server SETTINGS: %w", r.err)
			}
			done, err := tc.processHandshakeFrame(r.f)
			if err != nil {
				return err
			}
			if done {
				return nil
			}
		}
	}
}

// processHandshakeFrame handles a single frame during the handshake phase.
// It returns true when the server's initial SETTINGS has been received.
func (tc *transportConn) processHandshakeFrame(f *frame.Frame) (bool, error) {
	switch {
	case f.Header.Type == frame.TypeSettings && !f.Header.Flags.Has(frame.FlagAck):
		if _, err := tc.conn.HandleSettings(f); err != nil {
			return false, fmt.Errorf("apply server SETTINGS: %w", err)
		}
		return true, nil
	case f.Header.Type == frame.TypeSettings && f.Header.Flags.Has(frame.FlagAck):
		tc.conn.AckLocalSettings()
	case f.Header.Type == frame.TypeWindowUpdate:
		tc.conn.HandleWindowUpdate(f) //nolint:errcheck
	}
	return false, nil
}

// applyPeerFrameSize updates the writer and reader max frame size based on
// the peer's SETTINGS if it differs from the default.
func (tc *transportConn) applyPeerFrameSize() {
	peerSettings := tc.conn.PeerSettings()
	if peerSettings.MaxFrameSize != frame.DefaultMaxFrameSize {
		tc.writer.SetMaxFrameSize(peerSettings.MaxFrameSize) //nolint:errcheck
		tc.reader.SetMaxFrameSize(peerSettings.MaxFrameSize) //nolint:errcheck
	}
}

// allocStreamID returns the next available client-initiated stream ID.
func (tc *transportConn) allocStreamID() uint32 {
	for {
		id := tc.nextStreamID.Load()
		next := id + 2
		if tc.nextStreamID.CompareAndSwap(id, next) {
			return id
		}
	}
}

// roundTrip sends a request and waits for the response on this connection.
func (tc *transportConn) roundTrip(ctx context.Context, req *gohttp.Request) (*RoundTripResult, error) {
	if tc.conn.IsClosed() {
		return nil, fmt.Errorf("connection closed")
	}

	// Check for GOAWAY.
	if received, _, _ := tc.conn.GoAwayReceived(); received {
		return nil, fmt.Errorf("connection received GOAWAY")
	}

	streamID := tc.allocStreamID()

	ss := &streamState{
		done:        make(chan streamResult, 1),
		headersDone: make(chan struct{}),
	}

	tc.streamsMu.Lock()
	tc.streams[streamID] = ss
	tc.streamsMu.Unlock()

	defer func() {
		tc.streamsMu.Lock()
		delete(tc.streams, streamID)
		tc.streamsMu.Unlock()
	}()

	// Transition to open state.
	tc.conn.Streams().Transition(streamID, EventSendHeaders) //nolint:errcheck

	// Send request.
	if err := tc.sendRequest(ctx, streamID, req); err != nil {
		return nil, fmt.Errorf("send request on stream %d: %w", streamID, err)
	}

	// Wait for response.
	select {
	case <-ctx.Done():
		tc.sendReset(streamID, ErrCodeCancel)
		return nil, ctx.Err()
	case result := <-ss.done:
		if result.err != nil {
			return nil, result.err
		}
	}

	// Build response.
	resp, err := tc.buildResponse(req, ss)
	if err != nil {
		return nil, fmt.Errorf("build response for stream %d: %w", streamID, err)
	}

	return &RoundTripResult{
		Response:   resp,
		ServerAddr: tc.netConn.RemoteAddr().String(),
		RawFrames:  ss.rawFrames,
	}, nil
}

// roundTripRaw sends an HTTP/2 request using raw HPACK header fields and an
// optional body reader, returning the response as raw header fields and body
// data without converting through net/http types.
func (tc *transportConn) roundTripRaw(ctx context.Context, headers []hpack.HeaderField, body io.Reader) (*RoundTripResult, error) {
	if tc.conn.IsClosed() {
		return nil, fmt.Errorf("connection closed")
	}
	if received, _, _ := tc.conn.GoAwayReceived(); received {
		return nil, fmt.Errorf("connection received GOAWAY")
	}

	streamID := tc.allocStreamID()

	ss := &streamState{
		done:        make(chan streamResult, 1),
		headersDone: make(chan struct{}),
	}

	tc.streamsMu.Lock()
	tc.streams[streamID] = ss
	tc.streamsMu.Unlock()

	defer func() {
		tc.streamsMu.Lock()
		delete(tc.streams, streamID)
		tc.streamsMu.Unlock()
	}()

	// Transition to open state.
	tc.conn.Streams().Transition(streamID, EventSendHeaders) //nolint:errcheck

	// Send request headers and body.
	if err := tc.sendRequestRaw(ctx, streamID, headers, body); err != nil {
		return nil, fmt.Errorf("send request on stream %d: %w", streamID, err)
	}

	// Wait for response.
	select {
	case <-ctx.Done():
		tc.sendReset(streamID, ErrCodeCancel)
		return nil, ctx.Err()
	case result := <-ss.done:
		if result.err != nil {
			return nil, result.err
		}
	}

	// Extract status code from response headers.
	var statusCode int
	for _, hf := range ss.headers {
		if hf.Name == ":status" {
			code, err := strconv.Atoi(hf.Value)
			if err != nil {
				return nil, fmt.Errorf("invalid :status %q: %w", hf.Value, err)
			}
			statusCode = code
			break
		}
	}
	if statusCode == 0 {
		return nil, fmt.Errorf("no :status pseudo-header in response")
	}

	return &RoundTripResult{
		StatusCode: statusCode,
		Headers:    ss.headers,
		Body:       bytes.NewReader(ss.data),
		ServerAddr: tc.netConn.RemoteAddr().String(),
		RawFrames:  ss.rawFrames,
	}, nil
}

// sendRequestRaw encodes HPACK header fields and an optional body as HTTP/2
// frames on the given stream.
func (tc *transportConn) sendRequestRaw(ctx context.Context, streamID uint32, headers []hpack.HeaderField, body io.Reader) error {
	fragment := tc.encodeHeaders(headers)

	// Read body if present.
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = io.ReadAll(body)
		if err != nil {
			return fmt.Errorf("read request body: %w", err)
		}
	}

	endStream := len(bodyBytes) == 0

	// Send HEADERS frame(s).
	tc.writeMu.Lock()
	err := tc.writeHeaderFrames(streamID, endStream, fragment)
	tc.writeMu.Unlock()
	if err != nil {
		return err
	}

	// Send DATA frame(s) if there's a body.
	if len(bodyBytes) > 0 {
		if err := tc.writeDataFrames(ctx, streamID, bodyBytes); err != nil {
			return err
		}
		tc.conn.Streams().Transition(streamID, EventSendEndStream) //nolint:errcheck
	} else {
		tc.conn.Streams().Transition(streamID, EventSendEndStream) //nolint:errcheck
	}

	return nil
}

// sendRequest serializes and sends the HTTP request as HTTP/2 frames.
func (tc *transportConn) sendRequest(ctx context.Context, streamID uint32, req *gohttp.Request) error {
	headers := tc.buildRequestHeaders(req)
	fragment := tc.encodeHeaders(headers)

	// Read request body if present.
	var body []byte
	if req.Body != nil {
		defer req.Body.Close()
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("read request body: %w", err)
		}
	}

	endStream := len(body) == 0

	// Send HEADERS frame(s) under writeMu.
	tc.writeMu.Lock()
	err := tc.writeHeaderFrames(streamID, endStream, fragment)
	tc.writeMu.Unlock()
	if err != nil {
		return err
	}

	// Send DATA frame(s) if there's a body. writeDataFrames acquires
	// writeMu per-chunk so that flow control waits do not block other writes.
	if len(body) > 0 {
		if err := tc.writeDataFrames(ctx, streamID, body); err != nil {
			return err
		}
		// Transition to half-closed (local) after sending END_STREAM.
		tc.conn.Streams().Transition(streamID, EventSendEndStream) //nolint:errcheck
	} else {
		// END_STREAM was sent with HEADERS.
		tc.conn.Streams().Transition(streamID, EventSendEndStream) //nolint:errcheck
	}

	return nil
}

// buildRequestHeaders converts an HTTP request into HPACK header fields.
func (tc *transportConn) buildRequestHeaders(req *gohttp.Request) []hpack.HeaderField {
	path := req.URL.RequestURI()
	if path == "" {
		path = "/"
	}

	scheme := req.URL.Scheme
	if scheme == "" {
		scheme = "https"
	}

	authority := req.URL.Host
	if authority == "" {
		authority = req.Host
	}

	headers := []hpack.HeaderField{
		{Name: ":method", Value: req.Method},
		{Name: ":scheme", Value: scheme},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: path},
	}

	for name, values := range req.Header {
		lower := strings.ToLower(name)
		// Skip hop-by-hop and HTTP/2 forbidden headers.
		if lower == "host" {
			continue
		}
		if isHopByHopHeader(lower) {
			// te: trailers is allowed in HTTP/2 (RFC 9113 Section 8.2.2) and required for gRPC.
			if lower == "te" {
				for _, v := range values {
					if strings.EqualFold(v, "trailers") {
						headers = append(headers, hpack.HeaderField{Name: lower, Value: v})
					}
				}
			}
			continue
		}
		for _, v := range values {
			headers = append(headers, hpack.HeaderField{Name: lower, Value: v})
		}
	}

	return headers
}

// isHopByHopHeader reports whether the header is an HTTP/1 hop-by-hop header
// that should not be forwarded in HTTP/2.
func isHopByHopHeader(name string) bool {
	switch name {
	case "connection", "keep-alive", "proxy-connection",
		"transfer-encoding", "upgrade", "te":
		return true
	}
	return false
}

// encodeHeaders encodes header fields into an HPACK header block.
func (tc *transportConn) encodeHeaders(headers []hpack.HeaderField) []byte {
	return tc.encoder.Encode(headers)
}

// writeHeaderFrames writes HEADERS + CONTINUATION frames for a header block.
func (tc *transportConn) writeHeaderFrames(streamID uint32, endStream bool, fragment []byte) error {
	maxPayload := int(tc.conn.PeerSettings().MaxFrameSize)

	if len(fragment) <= maxPayload {
		return tc.writer.WriteHeaders(streamID, endStream, true, fragment)
	}

	// Split across HEADERS + CONTINUATION frames.
	first := fragment[:maxPayload]
	rest := fragment[maxPayload:]

	if err := tc.writer.WriteHeaders(streamID, endStream, false, first); err != nil {
		return fmt.Errorf("write HEADERS frame: %w", err)
	}

	for len(rest) > 0 {
		chunk := rest
		endHeaders := true
		if len(chunk) > maxPayload {
			chunk = rest[:maxPayload]
			endHeaders = false
		}
		if err := tc.writer.WriteContinuation(streamID, endHeaders, chunk); err != nil {
			return fmt.Errorf("write CONTINUATION frame: %w", err)
		}
		rest = rest[len(chunk):]
	}

	return nil
}

// writeDataFrames writes DATA frames for a request body, respecting flow control.
// It waits for send window availability, polling with context cancellation support.
func (tc *transportConn) writeDataFrames(ctx context.Context, streamID uint32, body []byte) error {
	maxPayload := int(tc.conn.PeerSettings().MaxFrameSize)

	for len(body) > 0 {
		// Wait for available send window on both connection and stream level.
		var available int32
		for {
			connWindow := tc.conn.SendWindow()
			streamWindow, ok := tc.conn.Streams().GetSendWindow(streamID)
			if !ok {
				return fmt.Errorf("stream %d does not exist", streamID)
			}
			available = connWindow
			if streamWindow < available {
				available = streamWindow
			}
			if available > 0 {
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-tc.readLoopDone:
				return fmt.Errorf("connection closed while waiting for send window")
			case <-time.After(10 * time.Millisecond):
				// Retry after peer sends WINDOW_UPDATE.
			}
		}

		chunk := int(available)
		if chunk > len(body) {
			chunk = len(body)
		}
		if chunk > maxPayload {
			chunk = maxPayload
		}

		endStream := chunk >= len(body)
		n := int32(chunk)

		// Consume flow control windows.
		if err := tc.conn.ConsumeSendWindow(n); err != nil {
			return fmt.Errorf("connection flow control: %w", err)
		}
		if err := tc.conn.Streams().ConsumeSendWindow(streamID, n); err != nil {
			return fmt.Errorf("stream flow control: %w", err)
		}

		tc.writeMu.Lock()
		err := tc.writer.WriteData(streamID, endStream, body[:chunk])
		tc.writeMu.Unlock()
		if err != nil {
			return fmt.Errorf("write DATA frame: %w", err)
		}

		body = body[chunk:]
	}

	return nil
}

// sendRawFrames writes pre-formed frame bytes to the upstream and waits for the
// response. Stream IDs in the raw frames are rewritten to the allocated stream
// ID for this connection.
func (tc *transportConn) sendRawFrames(ctx context.Context, rawBytes []byte) (*RoundTripResult, error) {
	if tc.conn.IsClosed() {
		return nil, fmt.Errorf("connection closed")
	}
	if received, _, _ := tc.conn.GoAwayReceived(); received {
		return nil, fmt.Errorf("connection received GOAWAY")
	}

	streamID := tc.allocStreamID()

	// Rewrite stream IDs in the raw frames to the allocated stream ID.
	rewritten, hasEndStream, err := rewriteRawFrameStreamIDs(rawBytes, streamID)
	if err != nil {
		return nil, fmt.Errorf("rewrite stream IDs: %w", err)
	}

	if !hasEndStream {
		return nil, fmt.Errorf("raw frames must contain END_STREAM flag to complete the request")
	}

	ss := &streamState{
		done:        make(chan streamResult, 1),
		headersDone: make(chan struct{}),
	}

	tc.streamsMu.Lock()
	tc.streams[streamID] = ss
	tc.streamsMu.Unlock()

	defer func() {
		tc.streamsMu.Lock()
		delete(tc.streams, streamID)
		tc.streamsMu.Unlock()
	}()

	// Transition to open state.
	tc.conn.Streams().Transition(streamID, EventSendHeaders) //nolint:errcheck

	// Write the raw frames directly.
	tc.writeMu.Lock()
	err = tc.writer.WriteRawBytes(rewritten)
	tc.writeMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("write raw frames: %w", err)
	}

	// If the raw frames contained END_STREAM, transition the stream state.
	if hasEndStream {
		tc.conn.Streams().Transition(streamID, EventSendEndStream) //nolint:errcheck
	}

	// Wait for response.
	select {
	case <-ctx.Done():
		tc.sendReset(streamID, ErrCodeCancel)
		return nil, ctx.Err()
	case result := <-ss.done:
		if result.err != nil {
			return nil, result.err
		}
	}

	// Build response.
	resp, err := tc.buildResponse(&gohttp.Request{URL: &url.URL{}}, ss)
	if err != nil {
		return nil, fmt.Errorf("build response for raw stream %d: %w", streamID, err)
	}

	return &RoundTripResult{
		Response:   resp,
		ServerAddr: tc.netConn.RemoteAddr().String(),
		RawFrames:  ss.rawFrames,
	}, nil
}

// sendReset sends a RST_STREAM frame for the given stream asynchronously.
// The write is dispatched to a goroutine to avoid blocking the caller
// when the peer is not reading.
func (tc *transportConn) sendReset(streamID, errCode uint32) {
	tc.conn.Streams().Transition(streamID, EventSendRST) //nolint:errcheck
	go func() {
		tc.writeMu.Lock()
		defer tc.writeMu.Unlock()
		tc.writer.WriteRSTStream(streamID, errCode) //nolint:errcheck
	}()
}

// readLoopFromChannel reads frames from a channel fed by a background
// reader goroutine, dispatching each to the appropriate handler.
func (tc *transportConn) readLoopFromChannel(ch <-chan frameReadResult) {
	defer close(tc.readLoopDone)

	for r := range ch {
		if r.err != nil {
			tc.handleReadError(r.err)
			return
		}
		if err := tc.dispatchFrame(r.f); err != nil {
			tc.logger.Error("frame dispatch error", "error", err)
			tc.closeWithError(err)
			return
		}
	}
}

// dispatchFrame routes a received frame to the appropriate handler.
func (tc *transportConn) dispatchFrame(f *frame.Frame) error {
	switch f.Header.Type {
	case frame.TypeSettings:
		return tc.handleSettings(f)
	case frame.TypeHeaders:
		return tc.handleResponseHeaders(f)
	case frame.TypeData:
		return tc.handleData(f)
	case frame.TypeWindowUpdate:
		return tc.handleWindowUpdate(f)
	case frame.TypePing:
		return tc.handlePing(f)
	case frame.TypeGoAway:
		return tc.handleGoAway(f)
	case frame.TypeRSTStream:
		return tc.handleRSTStream(f)
	case frame.TypeContinuation:
		return tc.handleContinuation(f)
	default:
		// Ignore unknown frame types per RFC 9113 Section 4.1.
		return nil
	}
}

// handleSettings processes a SETTINGS frame from the server.
func (tc *transportConn) handleSettings(f *frame.Frame) error {
	params, err := tc.conn.HandleSettings(f)
	if err != nil {
		return err
	}
	if params == nil {
		// SETTINGS ACK.
		return nil
	}

	// Update frame size limits if changed.
	peerSettings := tc.conn.PeerSettings()
	tc.writer.SetMaxFrameSize(peerSettings.MaxFrameSize) //nolint:errcheck
	tc.reader.SetMaxFrameSize(peerSettings.MaxFrameSize) //nolint:errcheck

	// Send SETTINGS ACK asynchronously.
	go func() {
		tc.writeMu.Lock()
		defer tc.writeMu.Unlock()
		tc.writer.WriteSettingsAck() //nolint:errcheck
	}()
	return nil
}

// handleResponseHeaders processes a HEADERS frame containing response headers.
func (tc *transportConn) handleResponseHeaders(f *frame.Frame) error {
	streamID := f.Header.StreamID

	// Check for streaming handler first.
	tc.streamsMu.Lock()
	sss, isStreaming := tc.streamingStreams[streamID]
	ss, ok := tc.streams[streamID]
	tc.streamsMu.Unlock()

	if isStreaming {
		return tc.handleStreamingHeaders(f, sss)
	}

	if !ok {
		// Unknown stream; might be after a reset. Ignore.
		return nil
	}

	ss.rawFrames = append(ss.rawFrames, f.RawBytes)

	fragment, err := f.HeaderBlockFragment()
	if err != nil {
		return fmt.Errorf("stream %d header block: %w", streamID, err)
	}

	if f.Header.Flags.Has(frame.FlagEndHeaders) {
		fields, decErr := tc.decoder.Decode(fragment)
		if decErr != nil {
			return fmt.Errorf("stream %d HPACK decode: %w", streamID, decErr)
		}
		tc.processDecodedHeaders(ss, f, fields)
	} else {
		// Need CONTINUATION frames; store fragment in headerBuf (not data).
		ss.headerBuf = append(ss.headerBuf[:0], fragment...)
	}

	return nil
}

// handleContinuation processes a CONTINUATION frame.
func (tc *transportConn) handleContinuation(f *frame.Frame) error {
	streamID := f.Header.StreamID

	// Check for streaming handler first.
	tc.streamsMu.Lock()
	sss, isStreaming := tc.streamingStreams[streamID]
	ss, ok := tc.streams[streamID]
	tc.streamsMu.Unlock()

	if isStreaming {
		return tc.handleStreamingContinuation(f, sss)
	}

	if !ok {
		return nil
	}

	ss.rawFrames = append(ss.rawFrames, f.RawBytes)

	fragment, err := f.ContinuationFragment()
	if err != nil {
		return fmt.Errorf("stream %d continuation: %w", streamID, err)
	}

	ss.headerBuf = append(ss.headerBuf, fragment...)

	if f.Header.Flags.Has(frame.FlagEndHeaders) {
		fields, decErr := tc.decoder.Decode(ss.headerBuf)
		if decErr != nil {
			return fmt.Errorf("stream %d HPACK decode: %w", streamID, decErr)
		}
		// Clear the header fragment accumulator.
		ss.headerBuf = ss.headerBuf[:0]
		tc.processDecodedHeaders(ss, f, fields)
	}

	return nil
}

// processDecodedHeaders routes decoded headers to initial headers or trailers.
func (tc *transportConn) processDecodedHeaders(ss *streamState, f *frame.Frame, fields []hpack.HeaderField) {
	select {
	case <-ss.headersDone:
		// Already received initial headers — these are trailers.
		ss.trailers = append(ss.trailers, fields...)
	default:
		ss.headers = append(ss.headers, fields...)
		close(ss.headersDone)
	}

	endStream := f.Header.Flags.Has(frame.FlagEndStream)
	if endStream {
		ss.endStream = true
		tc.conn.Streams().Transition(f.Header.StreamID, EventRecvEndStream) //nolint:errcheck
		ss.done <- streamResult{}
	}
}

// handleData processes a DATA frame from the server.
func (tc *transportConn) handleData(f *frame.Frame) error {
	streamID := f.Header.StreamID

	// Check for streaming handler first.
	tc.streamsMu.Lock()
	sss, isStreaming := tc.streamingStreams[streamID]
	ss, ok := tc.streams[streamID]
	tc.streamsMu.Unlock()

	if isStreaming {
		return tc.handleStreamingData(f, sss)
	}

	if !ok {
		return nil
	}

	ss.rawFrames = append(ss.rawFrames, f.RawBytes)

	payload, err := f.DataPayload()
	if err != nil {
		return fmt.Errorf("stream %d data payload: %w", streamID, err)
	}

	// Wait for headers to be done before appending data.
	<-ss.headersDone

	ss.data = append(ss.data, payload...)

	// Consume receive window and send WINDOW_UPDATE asynchronously.
	// The write is dispatched to a goroutine to avoid blocking the read
	// loop on synchronous transports where writes block until read.
	if len(payload) > 0 {
		n := int32(len(payload))
		tc.conn.ConsumeRecvWindow(n)                               //nolint:errcheck
		tc.conn.Streams().ConsumeRecvWindow(streamID, n)           //nolint:errcheck
		tc.conn.IncrementRecvWindow(uint32(n))                     //nolint:errcheck
		tc.conn.Streams().IncrementRecvWindow(streamID, uint32(n)) //nolint:errcheck

		go func() {
			tc.writeMu.Lock()
			defer tc.writeMu.Unlock()
			tc.writer.WriteWindowUpdate(0, uint32(n))        //nolint:errcheck
			tc.writer.WriteWindowUpdate(streamID, uint32(n)) //nolint:errcheck
		}()
	}

	if f.Header.Flags.Has(frame.FlagEndStream) {
		ss.endStream = true
		tc.conn.Streams().Transition(streamID, EventRecvEndStream) //nolint:errcheck
		ss.done <- streamResult{}
	}

	return nil
}

// handleWindowUpdate processes a WINDOW_UPDATE frame from the server.
func (tc *transportConn) handleWindowUpdate(f *frame.Frame) error {
	return tc.conn.HandleWindowUpdate(f)
}

// handlePing processes a PING frame from the server.
func (tc *transportConn) handlePing(f *frame.Frame) error {
	needsAck, data, err := tc.conn.HandlePing(f)
	if err != nil {
		return err
	}
	if needsAck {
		go func() {
			tc.writeMu.Lock()
			defer tc.writeMu.Unlock()
			tc.writer.WritePing(true, data) //nolint:errcheck
		}()
		return nil
	}
	return nil
}

// handleGoAway processes a GOAWAY frame from the server.
func (tc *transportConn) handleGoAway(f *frame.Frame) error {
	lastStreamID, errCode, _, err := tc.conn.HandleGoAway(f)
	if err != nil {
		return err
	}

	tc.logger.Debug("received GOAWAY",
		"last_stream_id", lastStreamID,
		"error_code", ErrCodeString(errCode),
	)

	// Signal error to all streams beyond lastStreamID.
	tc.streamsMu.Lock()
	for id, ss := range tc.streams {
		if id > lastStreamID {
			select {
			case ss.done <- streamResult{err: fmt.Errorf("stream %d rejected by GOAWAY (last=%d)", id, lastStreamID)}:
			default:
			}
		}
	}
	for id, sss := range tc.streamingStreams {
		if id > lastStreamID {
			goawayErr := fmt.Errorf("stream %d rejected by GOAWAY (last=%d)", id, lastStreamID)
			sss.abort(goawayErr)
			select {
			case sss.done <- streamResult{err: goawayErr}:
			default:
			}
		}
	}
	tc.streamsMu.Unlock()

	return nil
}

// handleRSTStream processes a RST_STREAM frame from the server.
func (tc *transportConn) handleRSTStream(f *frame.Frame) error {
	errCode, err := tc.conn.HandleRSTStream(f)
	if err != nil {
		return err
	}

	streamID := f.Header.StreamID
	rstErr := &StreamError{StreamID: streamID, Code: errCode, Reason: "RST_STREAM received"}

	tc.streamsMu.Lock()
	sss, isStreaming := tc.streamingStreams[streamID]
	ss, ok := tc.streams[streamID]
	tc.streamsMu.Unlock()

	if isStreaming {
		sss.abort(rstErr)
		select {
		case sss.done <- streamResult{err: rstErr}:
		default:
		}
		return nil
	}

	if !ok {
		return nil
	}

	select {
	case ss.done <- streamResult{err: rstErr}:
	default:
	}

	return nil
}

// handleReadError handles errors from the read loop.
func (tc *transportConn) handleReadError(err error) {
	if errors.Is(err, io.EOF) {
		tc.logger.Debug("upstream connection closed by server")
	} else {
		tc.logger.Error("upstream read error", "error", err)
	}
	tc.closeWithError(err)
}

// closeWithError signals all pending streams with an error and closes the connection.
func (tc *transportConn) closeWithError(err error) {
	connErr := fmt.Errorf("connection error: %w", err)
	tc.streamsMu.Lock()
	for _, ss := range tc.streams {
		select {
		case ss.done <- streamResult{err: connErr}:
		default:
		}
	}
	for _, sss := range tc.streamingStreams {
		sss.abort(connErr)
		select {
		case sss.done <- streamResult{err: connErr}:
		default:
		}
	}
	tc.streamsMu.Unlock()
	tc.close()
}

// close closes the connection.
func (tc *transportConn) close() {
	tc.closeOnce.Do(func() {
		tc.conn.Close()
		tc.netConn.Close()
	})
}

// buildResponse converts stream state into an *http.Response.
func (tc *transportConn) buildResponse(req *gohttp.Request, ss *streamState) (*gohttp.Response, error) {
	// Create a shallow copy of the request so we don't mutate the caller's req.URL.
	reqCopy := *req
	urlCopy := *req.URL
	reqCopy.URL = &urlCopy

	resp := &gohttp.Response{
		Request: &reqCopy,
		Header:  make(gohttp.Header),
		Trailer: make(gohttp.Header),
	}

	for _, hf := range ss.headers {
		if hf.Name == ":status" {
			code, err := strconv.Atoi(hf.Value)
			if err != nil {
				return nil, fmt.Errorf("invalid :status %q: %w", hf.Value, err)
			}
			resp.StatusCode = code
			resp.Status = fmt.Sprintf("%d %s", code, httputil.StatusText(code))
			continue
		}
		if strings.HasPrefix(hf.Name, ":") {
			// Skip other pseudo-headers.
			continue
		}
		resp.Header.Add(hf.Name, hf.Value)
	}

	if resp.StatusCode == 0 {
		return nil, fmt.Errorf("no :status pseudo-header in response")
	}

	for _, hf := range ss.trailers {
		if strings.HasPrefix(hf.Name, ":") {
			continue
		}
		resp.Trailer.Add(hf.Name, hf.Value)
	}

	resp.Body = io.NopCloser(bytes.NewReader(ss.data))
	resp.ContentLength = int64(len(ss.data))
	resp.Proto = "HTTP/2.0"
	resp.ProtoMajor = 2

	// Extract TLS state.
	if tlsState, ok := httputil.TLSConnectionState(tc.netConn); ok {
		resp.TLS = &tlsState
	}

	return resp, nil
}
