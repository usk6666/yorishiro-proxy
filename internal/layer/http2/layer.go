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
	scheme               string
	ctx                  envelope.EnvelopeContext
	initialSettings      *Settings
	maxConcurrentStreams uint32
	maxHeaderListSize    uint32
	bodySpillDir         string
	bodySpillThreshold   int64
	maxBody              int64
	stateReleaser        pluginv2.StateReleaser
	// enableConnectProtocol overrides the ServerRole-only default
	// advertisement of SETTINGS_ENABLE_CONNECT_PROTOCOL. Tracked as a
	// pointer so the zero value of options can be distinguished from
	// "explicitly disabled". nil = use role default (ServerRole = 1,
	// ClientRole = 0); non-nil = use the supplied bool.
	enableConnectProtocol *bool
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

// WithMaxConcurrentStreams overrides only the SETTINGS_MAX_CONCURRENT_STREAMS
// value advertised in the preface SETTINGS frame, leaving every other
// default (including the large flow-control window) intact. Zero is treated
// as "use default" and is ignored. When both WithMaxConcurrentStreams and
// WithInitialSettings are supplied, WithInitialSettings wins (the explicit
// full-Settings override takes precedence over the per-field override).
func WithMaxConcurrentStreams(n uint32) Option {
	return func(o *options) { o.maxConcurrentStreams = n }
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

// WithEnableConnectProtocol overrides whether SETTINGS_ENABLE_CONNECT_PROTOCOL
// (RFC 8441 §3) is advertised in the initial SETTINGS frame. By default
// ServerRole advertises 1 (extended CONNECT permitted) and ClientRole
// advertises nothing for this setting. Passing true on either role forces
// advertisement of value 1; passing false on either role suppresses
// advertisement entirely. Per RFC 8441 §3, only servers SHOULD advertise
// this setting in production; the override is provided so tests and
// diagnostic configurations can mirror the server's setting from the client
// side.
//
// USK-764: introduced solely to let tests exercise the off-path. The live
// data path always uses the role default.
func WithEnableConnectProtocol(enable bool) Option {
	return func(o *options) {
		v := enable
		o.enableConnectProtocol = &v
	}
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

	// nextClientStreamID is the next odd id to hand out to a client-
	// initiated stream. Allocation happens lazily — on the first
	// sendHeadersEvent — under mu, atomically with the writer-queue
	// enqueue (USK-740). This guarantees id order matches enqueue order
	// on the writer queue, which is FIFO from there to the wire, and so
	// satisfies RFC 9113 §5.1.1 wire-order without an explicit
	// HEADERS-order gate.
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

// GoAwayClosed reports whether this Layer can no longer accept new streams
// because GOAWAY has been sent (locally) or received (from peer). OpenStream
// returns *layer.StreamError{Code: ErrorRefused} in either case (see
// Layer.OpenStream below); the connection pool calls this to evict dead
// entries before handing them out, so a request that pool-hits a recycled
// upstream conn does not surface a spurious "refused" failure.
func (l *Layer) GoAwayClosed() bool {
	if sent, _ := l.conn.GoAwaySent(); sent {
		return true
	}
	if recv, _, _ := l.conn.GoAwayReceived(); recv {
		return true
	}
	return false
}

// IsShutdown reports whether this Layer's shutdown channel has been closed.
// A closed shutdown channel means the Layer can no longer accept new streams
// — OpenStream returns *layer.StreamError{Code: ErrorRefused, Reason: "layer
// shutdown"} for any caller in this state.
//
// USK-796: complements GoAwayClosed for the upstream-clean-EOF path. When
// handleReadError observes io.EOF (upstream FIN), it closes the shutdown
// channel without setting lastErr and without exchanging GOAWAY, so neither
// LastReaderError() nor GoAwayClosed() flags the Layer as dead. The pool
// must consult IsShutdown() to evict such entries before handing them to
// the next CONNECT, otherwise the pool fast-path immediately surfaces
// "layer shutdown" failures.
//
// Implemented as a non-blocking select on the existing shutdown channel:
// no new state, no new locks, safe to call concurrently with the writer
// path that closes the channel via shutdownOnce.
func (l *Layer) IsShutdown() bool {
	select {
	case <-l.shutdown:
		return true
	default:
		return false
	}
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

// PeerSettings returns the peer-advertised initial SETTINGS, or the
// RFC 9113 §6.5.2 defaults if no peer SETTINGS frame has been received
// yet. Callers that need to distinguish "received default" from "not yet
// received" should call PeerSettingsReceived first, or wait on
// WaitPeerSettings.
func (l *Layer) PeerSettings() Settings {
	return l.conn.PeerSettings()
}

// PeerSettingsReceived reports whether the peer has sent at least one
// SETTINGS frame.
func (l *Layer) PeerSettingsReceived() bool {
	return l.conn.PeerSettingsReceived()
}

// ErrShutdownBeforePeerSettings is returned by WaitPeerSettings when the
// Layer is torn down before the peer's first SETTINGS frame arrives.
var ErrShutdownBeforePeerSettings = errors.New("http2: layer shutdown before peer SETTINGS received")

// WaitPeerSettings blocks until the peer's first non-ACK SETTINGS frame is
// applied, the supplied context is canceled, or the Layer is shut down. On
// success returns nil and PeerSettings() / PeerSettingsReceived() reflect
// the peer's advertised values.
//
// Errors:
//   - ctx.Err() when ctx is canceled or its deadline expires before peer
//     SETTINGS arrive
//   - ErrShutdownBeforePeerSettings when l.shutdown closes (Close() called,
//     reader observed EOF, etc.) before peer SETTINGS arrive
//
// USK-871: the proxy ServerRole needs to mirror the upstream's
// SETTINGS_ENABLE_CONNECT_PROTOCOL value, so stack assembly waits on this
// signal between dialing upstream and constructing the client-facing Layer.
// Fast-path: if the peer SETTINGS frame has already been observed, returns
// immediately with nil.
func (l *Layer) WaitPeerSettings(ctx context.Context) error {
	ready := l.conn.PeerSettingsReady()
	// Fast path: already received. The channel close on a closed channel is
	// monotonic so this is race-free.
	select {
	case <-ready:
		return nil
	default:
	}
	select {
	case <-ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-l.shutdown:
		return ErrShutdownBeforePeerSettings
	}
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
		settings := *o.initialSettings
		applyEnablePushDefault(&settings, role)
		applyEnableConnectProtocolDefault(&settings, role, o.enableConnectProtocol)
		if err := httpConn.SetLocalSettings(settings); err != nil {
			return nil, err
		}
	} else {
		def := DefaultSettings()
		def.InitialWindowSize = defaultLargeStreamWindow
		// Apply per-field MaxConcurrentStreams override only when the
		// caller did not supply a full WithInitialSettings; the explicit
		// override wins per the WithMaxConcurrentStreams contract.
		if o.maxConcurrentStreams != 0 {
			def.MaxConcurrentStreams = o.maxConcurrentStreams
		}
		applyEnablePushDefault(&def, role)
		applyEnableConnectProtocolDefault(&def, role, o.enableConnectProtocol)
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
		params: settingsToFrame(local, role),
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

// OpenStream returns a new client-initiated stream Channel. Only valid
// in ClientRole.
//
// USK-740: OpenStream is a pure constructor. The wire-level HTTP/2
// stream id is NOT allocated here — it is reserved lazily on the first
// sendHeadersEvent, atomically with the state-machine transition,
// channel registration, and writer-queue enqueue. Because the writer
// queue is FIFO and the lazy-allocate critical section is single-mu,
// id order matches enqueue order by construction, satisfying RFC 9113
// §5.1.1 wire-order. The HEADERS-order gate USK-739 introduced is no
// longer needed.
//
// Side effects:
//   - h2Stream on the returned channel reads as 0 until the first Send
//     (use H2StreamID() to observe). For tests that need to assert id
//     ordering, drive a Send before reading the id.
//   - Pairing OpenStream with Close() is no longer required for
//     synchronization correctness. Callers may still want to Close in
//     the abandon-without-Send case for resource cleanup, but a
//     channel orphaned between OpenStream and Send no longer blocks
//     subsequent OpenStream callers.
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

	// Pure constructor: bind to layer, leave h2Stream==0 so the first
	// sendHeadersEvent can allocate the id under l.mu.
	return newChannel(l, 0), nil
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
//
// USK-812: Go's select is pseudo-random when multiple cases are ready, so a
// concurrent close(shutdown) racing a queue-send with available buffer
// capacity could pseudo-randomly reject the request even though the
// writer's drain loop would have processed it. Try the buffered send first
// in a non-blocking probe; only fall back to the cancellation branch when
// the queue is genuinely full. The writerLoop's `case <-l.shutdown:` branch
// drains queued requests best-effort, so a request enqueued just before
// shutdown still reaches the wire.
//
// Post-exit safety: if writerLoop has already returned (writerDone closed),
// any send to writerQueue would be orphaned — there is no consumer, and
// waitDone's `<-shutdown` fall-through (`return <-done`) would block
// forever. Short-circuit such sends to failWriteRequest(ErrWriterClosed)
// so done fires and the caller unwinds. The slow-path select also adds
// `<-l.writerDone` for the queue-full case.
func (l *Layer) enqueueWrite(req writeRequest) {
	select {
	case <-l.writerDone:
		failWriteRequest(req, ErrWriterClosed)
		return
	default:
	}
	select {
	case l.writerQueue <- req:
		return
	default:
	}
	select {
	case l.writerQueue <- req:
	case <-l.writerDone:
		failWriteRequest(req, ErrWriterClosed)
	case <-l.shutdown:
		failWriteRequest(req, ErrWriterClosed)
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
//
// SETTINGS_ENABLE_PUSH (0x02) is included only when role == ClientRole. RFC
// 9113 §7.2.2 forbids servers from explicitly setting the value: "Servers
// MUST NOT explicitly set this value. Clients MUST treat receipt of a
// SETTINGS frame with SETTINGS_ENABLE_PUSH set to a value other than 0 as
// a connection error of type PROTOCOL_ERROR." Strict h2 clients (curl,
// Chrome, golang.org/x/net/http2) enforce that MUST and respond to any
// emitted value — including 1 — with GOAWAY(PROTOCOL_ERROR), so ServerRole
// must omit the setting entirely (USK-825). ClientRole continues to emit
// value 0 per RFC 9113 §6.5.2 ("A client MUST send a value of 0"), set by
// applyEnablePushDefault before this function runs.
//
// SETTINGS_MAX_HEADER_LIST_SIZE (0x06) is included only when the field is
// non-zero. RFC 9113 §6.5.2 specifies the default as "unlimited", which on
// the wire means omitting the setting entirely. Emitting the setting with
// value 0 advertises a hard zero header-list limit to the peer; gRPC-go
// clients interpret that as "any header byte violates the server limit"
// and reject every RPC with `header list size to send violates the maximum
// size (0 bytes) set by server`. The same gap is documented (and side-
// stepped via WithMaxHeaderListSize) by the gRPC layer integration suite.
//
// SETTINGS_ENABLE_CONNECT_PROTOCOL (0x08) is included only when the field
// is non-zero. RFC 8441 §3 says only servers advertise it; clients ignore
// the setting when sending. Endpoints that have not opted in (the default
// for ClientRole, and ServerRole when WithEnableConnectProtocol(false) is
// supplied) leave the field at 0 and the setting is omitted from the
// initial SETTINGS frame entirely. This keeps the wire output identical
// to the pre-USK-764 behaviour for endpoints that do not support extended
// CONNECT.
func settingsToFrame(s Settings, role Role) []frame.Setting {
	out := []frame.Setting{
		{ID: frame.SettingHeaderTableSize, Value: s.HeaderTableSize},
	}
	if role == ClientRole {
		// RFC 9113 §6.5.2: clients MUST send ENABLE_PUSH=0.
		// applyEnablePushDefault has already forced s.EnablePush to 0.
		out = append(out, frame.Setting{ID: frame.SettingEnablePush, Value: s.EnablePush})
	}
	// RFC 9113 §7.2.2: "Servers MUST NOT explicitly set this value." ServerRole
	// omits SETTINGS_ENABLE_PUSH from the initial SETTINGS frame entirely
	// (USK-825). Strict h2 clients reject any emitted value with
	// GOAWAY(PROTOCOL_ERROR), including value 1 (the prior default seeded by
	// defaultEnablePush).
	out = append(out,
		frame.Setting{ID: frame.SettingMaxConcurrentStreams, Value: s.MaxConcurrentStreams},
		frame.Setting{ID: frame.SettingInitialWindowSize, Value: s.InitialWindowSize},
		frame.Setting{ID: frame.SettingMaxFrameSize, Value: s.MaxFrameSize},
	)
	if s.MaxHeaderListSize != 0 {
		out = append(out, frame.Setting{
			ID:    frame.SettingMaxHeaderListSize,
			Value: s.MaxHeaderListSize,
		})
	}
	if s.EnableConnectProtocol != 0 {
		out = append(out, frame.Setting{
			ID:    frame.SettingEnableConnectProtocol,
			Value: s.EnableConnectProtocol,
		})
	}
	return out
}

// applyEnablePushDefault forces SETTINGS_ENABLE_PUSH to comply with
// RFC 9113 based on the local Role.
//
// RFC 9113 §6.5.2 requires of clients:
//
//   - "A client MUST send a value of 0 [for SETTINGS_ENABLE_PUSH]; a
//     server MUST treat any other value from a client as a connection
//     error of type PROTOCOL_ERROR."
//
// RFC 9113 §7.2.2 requires of servers:
//
//   - "Servers MUST NOT explicitly set this value. Clients MUST treat
//     receipt of a SETTINGS frame with SETTINGS_ENABLE_PUSH set to a
//     value other than 0 as a connection error of type PROTOCOL_ERROR."
//
// DefaultSettings() seeds value 1 (the legacy non-zero default). For
// ClientRole that default violates §6.5.2: strict upstreams (Google
// Frontend, nghttp2-server) reply to a `SETTINGS{ENABLE_PUSH=1}` from
// a client with GOAWAY(PROTOCOL_ERROR, last_stream_id=0), causing
// every first stream to be refused (USK-820).
//
// For ServerRole the wire-level fix is to omit SETTINGS_ENABLE_PUSH
// entirely (settingsToFrame handles the wire-side omission), but we
// still zero the in-memory value here for state hygiene — LocalSettings()
// must report the same shape the wire actually carries. Strict h2
// clients (curl, Chrome, golang.org/x/net/http2) treat any non-zero
// emitted value as a PROTOCOL_ERROR, and after USK-823 retired HTTP/2
// server-push recording end-to-end no caller has a legitimate reason
// to advertise push availability from a ServerRole Layer (USK-825).
//
// Both roles are unconditionally normalized to 0; the previous "leave
// ServerRole untouched so caller intent survives" carve-out has no
// remaining legitimate caller and is incompatible with §7.2.2 MUST.
func applyEnablePushDefault(s *Settings, role Role) {
	switch role {
	case ClientRole, ServerRole:
		s.EnablePush = 0
	}
}

// applyEnableConnectProtocolDefault sets s.EnableConnectProtocol per the
// USK-764 advertisement policy:
//
//   - When override is non-nil, use its bool (true → 1, false → 0). This
//     covers WithEnableConnectProtocol(true|false) on either role.
//   - Otherwise, ServerRole defaults to 1 (advertise extended CONNECT
//     support per RFC 8441 §3) and ClientRole defaults to 0 (clients do
//     not advertise this setting per RFC 8441 §3).
//
// Any pre-existing s.EnableConnectProtocol from a caller-supplied
// WithInitialSettings is unconditionally overwritten — the role default
// and explicit option are the only paths that flip the bit.
func applyEnableConnectProtocolDefault(s *Settings, role Role, override *bool) {
	if override != nil {
		if *override {
			s.EnableConnectProtocol = 1
		} else {
			s.EnableConnectProtocol = 0
		}
		return
	}
	if role == ServerRole {
		s.EnableConnectProtocol = 1
	} else {
		s.EnableConnectProtocol = 0
	}
}
