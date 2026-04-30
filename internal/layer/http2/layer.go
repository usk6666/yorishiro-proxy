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
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
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
//
// Body-related options (spill dir, spill threshold, max size) have moved to
// the httpaggregator package as part of USK-637 — the HTTP/2 Layer itself
// no longer owns a BodyBuffer. The Options WithBodySpillDir /
// WithBodySpillThreshold / WithMaxBodySize are retained here as shims
// (accepting the values and exposing them via BodyOpts) so callers can keep
// threading configuration through BuildConfig unchanged; the aggregator
// consults BodyOpts when wrapping the Layer's event-granular Channels.
type options struct {
	scheme             string
	ctx                envelope.EnvelopeContext
	initialSettings    *Settings
	maxHeaderListSize  uint32
	bodySpillDir       string
	bodySpillThreshold int64
	maxBody            int64
	stateReleaser      pluginv2.StateReleaser
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

// WithBodySpillDir records the directory used for body spill temp files.
// The Layer itself no longer owns BodyBuffers post-USK-637; the aggregator
// wrapper reads this value via BodyOpts to drive its spill decisions.
func WithBodySpillDir(dir string) Option {
	return func(o *options) { o.bodySpillDir = dir }
}

// WithBodySpillThreshold records the spill threshold for aggregator use.
func WithBodySpillThreshold(n int64) Option {
	return func(o *options) { o.bodySpillThreshold = n }
}

// WithMaxBodySize records the absolute body size cap for aggregator use.
func WithMaxBodySize(n int64) Option {
	return func(o *options) { o.maxBody = n }
}

// WithStateReleaser injects a pluginv2.StateReleaser the Layer invokes
// when a stream reaches its terminal state. nil = no-op (legacy parallel:
// the Layer compiles and runs without pluginv2 wired up). The release is
// fired exactly once per stream from channel.markTerminated, regardless
// of which terminal path triggered it (Close, RST_STREAM, peer GOAWAY-
// driven failStream, or layer broadcastShutdown).
func WithStateReleaser(r pluginv2.StateReleaser) Option {
	return func(o *options) { o.stateReleaser = r }
}

// BodyBufferOpts exposes the aggregator-relevant body configuration values
// threaded into this Layer at construction time. The aggregator reads these
// when wrapping a per-stream Channel so body accumulation respects the same
// limits the HTTP/1.x Layer applies.
type BodyBufferOpts struct {
	SpillDir       string
	SpillThreshold int64
	MaxBody        int64
}

// BodyOpts returns the body-buffer configuration threaded into this Layer.
// Used by internal/layer/httpaggregator to size its BodyBuffer operations.
func (l *Layer) BodyOpts() BodyBufferOpts {
	return BodyBufferOpts{
		SpillDir:       l.opts.bodySpillDir,
		SpillThreshold: l.opts.bodySpillThreshold,
		MaxBody:        l.opts.maxBody,
	}
}

// Layer is the HTTP/2 Layer per RFC-001. It wraps a net.Conn and yields one
// event-granular Channel per HTTP/2 stream via Channels().
type Layer struct {
	netConn     net.Conn
	role        Role
	streamID    string // connection-level identifier (logging / trace correlation)
	opts        options
	conn        *Conn
	frameReader *frame.Reader
	frameWriter *frame.Writer
	decoder     *hpack.Decoder
	encoder     *hpack.Encoder

	encoderTableSize uint32

	mu         sync.Mutex
	channels   map[uint32]*channel
	assemblers map[uint32]*eventAssembler
	closed     bool

	channelOut          chan layer.Channel
	closeChannelOutOnce sync.Once

	pendingHeaderStream uint32

	writerQueue chan writeRequest
	writerDone  chan struct{}
	readerDone  chan struct{}

	shutdown     chan struct{}
	shutdownOnce sync.Once

	windowUpdated chan struct{}

	nextClientStreamID uint32

	lastErrMu sync.Mutex
	lastErr   error
}

// Role returns the Layer's role (ServerRole or ClientRole).
func (l *Layer) GetRole() Role { return l.role }

// releaseStreamState fires the configured pluginv2.StateReleaser for
// streamID using the Layer's EnvelopeContext.ConnID. No-op when no
// releaser was configured (the legacy parallel path) or when ConnID is
// unset (defensive — refuses to issue a release with an empty key).
func (l *Layer) releaseStreamState(streamID string) {
	if l.opts.stateReleaser == nil {
		return
	}
	if l.opts.ctx.ConnID == "" {
		return
	}
	l.opts.stateReleaser.ReleaseStream(l.opts.ctx.ConnID, streamID)
}

// EnvelopeContextTemplate returns a copy of the EnvelopeContext template
// stamped onto envelopes produced by this Layer.
func (l *Layer) EnvelopeContextTemplate() envelope.EnvelopeContext {
	return l.opts.ctx
}

// LastReaderError returns the most recent non-EOF error observed by the
// reader goroutine.
func (l *Layer) LastReaderError() error {
	l.lastErrMu.Lock()
	defer l.lastErrMu.Unlock()
	return l.lastErr
}

// ActiveStreamCount returns the number of streams currently open or
// half-closed.
func (l *Layer) ActiveStreamCount() int {
	return l.conn.Streams().ActiveCount()
}

// PeerMaxConcurrentStreams returns the peer-advertised
// SETTINGS_MAX_CONCURRENT_STREAMS.
func (l *Layer) PeerMaxConcurrentStreams() uint32 {
	if !l.conn.PeerSettingsReceived() {
		return 0
	}
	return l.conn.PeerSettings().MaxConcurrentStreams
}

// New creates an HTTP/2 Layer wrapping conn.
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
		assemblers:         make(map[uint32]*eventAssembler),
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

	l.enqueueWrite(writeRequest{settings: &writeSettings{
		params: settingsToFrame(local),
	}})

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

const defaultLargeConnWindow = 16 * 1024 * 1024
const defaultLargeStreamWindow = 16 * 1024 * 1024

const closeDrainTimeout = 100 * time.Millisecond

// Channels yields one event-granular Channel per HTTP/2 stream.
func (l *Layer) Channels() <-chan layer.Channel { return l.channelOut }

// OpenStream creates a new client-initiated stream and returns its Channel.
// Only valid in ClientRole.
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

	_ = l.conn.Streams().Transition(id, EventSendHeaders)

	ch := newChannel(l, id, false)
	l.registerChannel(id, ch)
	return ch, nil
}

// Close tears down the Layer: sends GOAWAY, drains the writer, closes
// streams, closes the connection. Safe to call multiple times.
func (l *Layer) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	l.mu.Unlock()

	last := l.conn.Streams().LastPeerStreamID()
	l.enqueueWrite(writeRequest{goAway: &writeGoAway{
		lastStreamID: last,
		code:         ErrCodeNo,
	}})

	l.shutdownOnce.Do(func() { close(l.shutdown) })

	select {
	case <-l.writerDone:
	case <-time.After(closeDrainTimeout):
	}
	closeErr := l.netConn.Close()
	<-l.writerDone
	<-l.readerDone

	l.broadcastShutdown()
	return closeErr
}

// enqueueWrite places a write request on the writer queue.
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
	case req.headers != nil:
		deliverDone(req.headers.done, err)
	case req.dataEvent != nil:
		deliverDone(req.dataEvent.done, err)
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
// start.
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
