package http2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// Role identifies whether the Layer is the server side (peer is the client)
// or the client side (peer is the server) of an HTTP/2 connection.
type Role uint8

const (
	// ServerRole means the local endpoint behaves as the HTTP/2 server.
	ServerRole Role = iota
	// ClientRole means the local endpoint behaves as the HTTP/2 client.
	ClientRole
)

// String returns the role name.
func (r Role) String() string {
	switch r {
	case ServerRole:
		return "server"
	case ClientRole:
		return "client"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(r))
	}
}

// options is the runtime configuration for a Layer.
type options struct {
	scheme            string
	ctx               envelope.EnvelopeContext
	initialSettings   *Settings
	maxHeaderListSize uint32
}

// Option configures a Layer.
type Option func(*options)

// WithScheme sets the HTTP scheme ("http" or "https") stamped onto envelopes.
func WithScheme(scheme string) Option {
	return func(o *options) { o.scheme = scheme }
}

// WithEnvelopeContext sets the EnvelopeContext template stamped onto every
// envelope produced by this Layer. ReceivedAt is overwritten per-envelope.
func WithEnvelopeContext(ctx envelope.EnvelopeContext) Option {
	return func(o *options) { o.ctx = ctx }
}

// WithInitialSettings overrides the local SETTINGS sent during the preface.
func WithInitialSettings(s Settings) Option {
	return func(o *options) {
		copyS := s
		o.initialSettings = &copyS
	}
}

// WithMaxHeaderListSize sets the local SETTINGS_MAX_HEADER_LIST_SIZE value
// the decoder will accept. 0 = use HPACK's defaultMaxHeaderListSize.
func WithMaxHeaderListSize(n uint32) Option {
	return func(o *options) { o.maxHeaderListSize = n }
}

// Layer is the HTTP/2 Layer per RFC-001. It wraps a net.Conn and yields one
// Channel per HTTP/2 stream via Channels().
type Layer struct {
	netConn     net.Conn
	role        Role
	streamID    string // connection-level identifier (logging / trace correlation)
	opts        options
	conn        *Conn // local-vs-peer SETTINGS, flow control, stream lifecycle
	frameReader *frame.Reader
	frameWriter *frame.Writer
	decoder     *hpack.Decoder
	encoder     *hpack.Encoder

	// encoderTableSize tracks the last value of peer.HeaderTableSize for which
	// we emitted a Dynamic Table Size Update.
	encoderTableSize uint32

	// channels holds the per-stream Channels keyed by HTTP/2 stream id.
	mu         sync.Mutex
	channels   map[uint32]*channel
	assemblers map[uint32]*streamAssembler
	closed     bool

	// Output of new Channels to consumers.
	channelOut          chan layer.Channel
	closeChannelOutOnce sync.Once

	// Internal state used by reader.go.
	pendingHeaderStream uint32 // non-zero while CONTINUATION is expected

	// Writer goroutine machinery.
	//
	// writerQueue is owned exclusively by the writer goroutine with respect
	// to closing: the writer never closes it either, and Close() does not
	// close it. GC reclaims it once the writer exits and no more senders
	// exist. All senders (enqueueWrite) select on <-shutdown as the escape
	// hatch, so no send can block forever and no send races a close.
	writerQueue chan writeRequest
	writerDone  chan struct{}

	// Reader goroutine done signal.
	readerDone chan struct{}

	// shutdown is closed once on shutdown to signal reader/writer/Send.
	shutdown     chan struct{}
	shutdownOnce sync.Once

	// windowUpdated is signaled when a WINDOW_UPDATE arrives, so the writer
	// goroutine can re-attempt blocked DATA frames.
	windowUpdated chan struct{}

	// nextClientStreamID gives the next odd stream ID for client-initiated
	// streams (1, 3, 5, ...).
	nextClientStreamID uint32

	// passthroughTrailerCount is incremented every time trailers arrive while
	// a stream is in passthrough body mode (best-effort metric only).
	passthroughMu           sync.Mutex
	passthroughTrailerCount uint64

	// Last non-EOF error from the reader goroutine; set under lastErrMu.
	lastErrMu sync.Mutex
	lastErr   error
}

// PassthroughTrailerCount returns the number of trailer blocks dropped because
// they arrived after a stream had switched to passthrough body mode. This is
// a diagnostic metric only; trailers in passthrough are not delivered to
// consumers.
func (l *Layer) PassthroughTrailerCount() uint64 {
	l.passthroughMu.Lock()
	defer l.passthroughMu.Unlock()
	return l.passthroughTrailerCount
}

// LastReaderError returns the most recent non-EOF error observed by the
// reader goroutine. Intended for diagnostics and tests; nil if no error
// has occurred or the layer is still healthy.
func (l *Layer) LastReaderError() error {
	l.lastErrMu.Lock()
	defer l.lastErrMu.Unlock()
	return l.lastErr
}

// ActiveStreamCount returns the number of streams currently open or
// half-closed. Used by connection pools to decide whether to reuse this
// Layer for a new stream.
func (l *Layer) ActiveStreamCount() int {
	return l.conn.Streams().ActiveCount()
}

// PeerMaxConcurrentStreams returns the peer-advertised
// SETTINGS_MAX_CONCURRENT_STREAMS. Returns 0 if the peer has not yet sent a
// SETTINGS frame (RFC 9113 §6.5.2 — treat as unbounded). Callers must use
// this method (rather than PeerSettings().MaxConcurrentStreams directly)
// to distinguish "peer advertised N" from "peer has not advertised yet",
// because Conn seeds peerSettings with the RFC default (100) before the
// first peer SETTINGS arrives.
func (l *Layer) PeerMaxConcurrentStreams() uint32 {
	if !l.conn.PeerSettingsReceived() {
		return 0
	}
	return l.conn.PeerSettings().MaxConcurrentStreams
}

// New creates an HTTP/2 Layer wrapping conn.
//
// The preface is exchanged synchronously inside New (per role). Once preface
// bytes have been transferred, reader and writer goroutines start and process
// the peer's initial SETTINGS.
//
// streamID is the connection-level identifier used by the caller for
// logging/tracing. Per-stream Channels generate their own UUID-based StreamIDs
// returned by Channel.StreamID().
func New(conn net.Conn, streamID string, role Role, opts ...Option) (*Layer, error) {
	o := options{
		scheme: "https",
	}
	for _, opt := range opts {
		opt(&o)
	}

	httpConn := NewConn()
	if o.initialSettings != nil {
		if err := httpConn.SetLocalSettings(*o.initialSettings); err != nil {
			return nil, err
		}
	} else {
		// Default: bump local InitialWindowSize so streaming bodies up to
		// passthroughThreshold do not stall under per-stream flow control.
		def := DefaultSettings()
		def.InitialWindowSize = defaultLargeStreamWindow
		if err := httpConn.SetLocalSettings(def); err != nil {
			return nil, err
		}
	}
	local := httpConn.LocalSettings()

	dec := hpack.NewDecoder(local.HeaderTableSize)
	if o.maxHeaderListSize > 0 {
		dec.SetMaxHeaderListSize(o.maxHeaderListSize)
	}
	enc := hpack.NewEncoder(local.HeaderTableSize, true)

	l := &Layer{
		netConn:            conn,
		role:               role,
		streamID:           streamID,
		opts:               o,
		conn:               httpConn,
		frameReader:        frame.NewReader(conn),
		frameWriter:        frame.NewWriter(conn),
		decoder:            dec,
		encoder:            enc,
		channels:           make(map[uint32]*channel),
		assemblers:         make(map[uint32]*streamAssembler),
		channelOut:         make(chan layer.Channel, 8),
		writerQueue:        make(chan writeRequest, 64),
		writerDone:         make(chan struct{}),
		readerDone:         make(chan struct{}),
		shutdown:           make(chan struct{}),
		windowUpdated:      make(chan struct{}, 1),
		nextClientStreamID: 1,
		encoderTableSize:   local.HeaderTableSize,
	}

	if err := l.runPreface(); err != nil {
		_ = conn.Close()
		return nil, err
	}

	go l.writerLoop()
	go l.readerLoop()

	// Enqueue our local SETTINGS as the first writer task.
	l.enqueueWrite(writeRequest{settings: &writeSettings{
		params: settingsToFrame(local),
	}})

	// Bump the connection-level recv window to a large value so streaming
	// bodies do not stall under flow control. We must update our local
	// accounting before any peer DATA can arrive — the writer goroutine
	// already does so after the frame is sent (handleWriteWindowUpdate),
	// but we cannot guarantee that runs before the first DATA arrives. So
	// we pre-bump the local window here. We send a WINDOW_UPDATE matching
	// the bump using a noLocalUpdate path on the writer to avoid double-
	// counting.
	bump := uint32(defaultLargeConnWindow - defaultConnectionWindowSize)
	if err := l.conn.IncrementRecvWindow(bump); err != nil {
		_ = conn.Close()
		return nil, err
	}
	l.enqueueWrite(writeRequest{windowUpdate: &writeWindowUpdate{
		streamID:        0,
		increment:       bump,
		skipLocalUpdate: true,
	}})

	return l, nil
}

// defaultLargeConnWindow is the connection-level recv window we advertise on
// startup. 16 MiB is enough for streaming bodies up to passthroughThreshold
// without stalling under flow control.
const defaultLargeConnWindow = 16 * 1024 * 1024

// defaultLargeStreamWindow is the per-stream initial recv window we advertise
// via SETTINGS_INITIAL_WINDOW_SIZE. Same rationale as defaultLargeConnWindow.
const defaultLargeStreamWindow = 16 * 1024 * 1024

// closeDrainTimeout bounds how long Close waits for the writer goroutine to
// drain its queue (and emit GOAWAY) before forcibly closing the underlying
// conn. 100ms is enough for a typical local-host send with no congestion.
const closeDrainTimeout = 100 * time.Millisecond

// Channels yields one Channel per HTTP/2 stream as it is created. The channel
// is closed when the Layer shuts down.
func (l *Layer) Channels() <-chan layer.Channel { return l.channelOut }

// OpenStream creates a new client-initiated stream and returns its Channel.
// Only valid in ClientRole. The HEADERS frame is not sent until Send is called.
func (l *Layer) OpenStream(ctx context.Context) (layer.Channel, error) {
	if l.role != ClientRole {
		return nil, errors.New("http2: OpenStream is only valid in ClientRole")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.shutdown:
		return nil, &layer.StreamError{Code: layer.ErrorRefused, Reason: "layer shutdown"}
	default:
	}

	if sent, _ := l.conn.GoAwaySent(); sent {
		return nil, &layer.StreamError{Code: layer.ErrorRefused, Reason: "GOAWAY sent"}
	}
	if recv, _, _ := l.conn.GoAwayReceived(); recv {
		return nil, &layer.StreamError{Code: layer.ErrorRefused, Reason: "GOAWAY received"}
	}

	l.mu.Lock()
	id := l.nextClientStreamID
	l.nextClientStreamID += 2
	l.mu.Unlock()

	// Place the stream in idle state so the writer's flow-control checks
	// can find it.
	_ = l.conn.Streams().Transition(id, EventSendHeaders)

	ch := newChannel(l, id, false)
	l.registerChannel(id, ch)
	return ch, nil
}

// Close tears down the Layer: sends GOAWAY, drains the writer, closes
// streams, closes the connection. Safe to call multiple times.
//
// Ownership: Close does NOT close writerQueue. The writer goroutine is the
// sole owner w.r.t. lifecycle — it exits when it observes <-shutdown, after
// draining any already-queued writes. All senders select on <-shutdown so
// enqueue is race-free against Close (see USK-614).
func (l *Layer) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	l.mu.Unlock()

	// Best-effort GOAWAY. Enqueued BEFORE close(shutdown) so the writer
	// goroutine, still running, dispatches it as part of its normal loop.
	last := l.conn.Streams().LastPeerStreamID()
	l.enqueueWrite(writeRequest{goAway: &writeGoAway{
		lastStreamID: last,
		code:         ErrCodeNo,
	}})

	// Trigger shutdown signal. After this, any further enqueueWrite call
	// takes the <-shutdown branch and fails with errWriterClosed instead
	// of sending on writerQueue, so the writer sees no new work.
	l.shutdownOnce.Do(func() { close(l.shutdown) })

	// Best-effort: give the writer a short window to drain (and emit the
	// queued GOAWAY) before tearing down the underlying conn. Then close
	// the conn regardless so the reader unblocks. Bound the wait so a
	// stuck/slow writer cannot hang Close indefinitely.
	select {
	case <-l.writerDone:
	case <-time.After(closeDrainTimeout):
	}
	closeErr := l.netConn.Close()
	<-l.writerDone
	<-l.readerDone

	// Final broadcast (idempotent).
	l.broadcastShutdown()
	return closeErr
}

// enqueueWrite places a write request on the writer queue. If the Layer is
// shutting down, the request fails with errWriterClosed without ever touching
// writerQueue.
//
// This uses a plain select between the channel send and <-shutdown. No
// preflight lock is needed because the writer goroutine never closes
// writerQueue — it exits when it observes <-shutdown. See Layer.Close
// docstring for the ownership rationale (USK-614).
func (l *Layer) enqueueWrite(req writeRequest) {
	select {
	case l.writerQueue <- req:
	case <-l.shutdown:
		failWriteRequest(req, errWriterClosed)
	}
}

// failWriteRequest delivers err on the done channel of whichever sub-request
// is non-nil in req.
func failWriteRequest(req writeRequest, err error) {
	switch {
	case req.opaque != nil:
		deliverDone(req.opaque.done, err)
	case req.message != nil:
		deliverDone(req.message.done, err)
	case req.rst != nil:
		deliverDone(req.rst.done, err)
	case req.windowUpdate != nil:
		deliverDone(req.windowUpdate.done, err)
	case req.pingAck != nil:
		deliverDone(req.pingAck.done, err)
	case req.settings != nil:
		deliverDone(req.settings.done, err)
	case req.settingsAck != nil:
		deliverDone(req.settingsAck.done, err)
	case req.goAway != nil:
		deliverDone(req.goAway.done, err)
	}
}

// runPreface performs the preface exchange before reader/writer goroutines
// start. After this returns nil, raw frames can flow in either direction.
func (l *Layer) runPreface() error {
	switch l.role {
	case ServerRole:
		return runServerPreface(l.netConn)
	case ClientRole:
		return runClientPreface(l.netConn)
	default:
		return fmt.Errorf("http2: unknown role %d", l.role)
	}
}

// settingsToFrame converts a Settings struct into a list of frame.Setting
// suitable for sending in a SETTINGS frame.
func settingsToFrame(s Settings) []frame.Setting {
	return []frame.Setting{
		{ID: frame.SettingHeaderTableSize, Value: s.HeaderTableSize},
		{ID: frame.SettingEnablePush, Value: s.EnablePush},
		{ID: frame.SettingMaxConcurrentStreams, Value: s.MaxConcurrentStreams},
		{ID: frame.SettingInitialWindowSize, Value: s.InitialWindowSize},
		{ID: frame.SettingMaxFrameSize, Value: s.MaxFrameSize},
		{ID: frame.SettingMaxHeaderListSize, Value: s.MaxHeaderListSize},
	}
}
