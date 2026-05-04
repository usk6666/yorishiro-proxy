package http1

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// Layer wraps a net.Conn in an HTTP/1.x Layer. It yields exactly one Channel
// that produces HTTPMessage envelopes for each request or response in
// keep-alive order.
//
// The Layer owns the connection and closes it on Close().
type Layer struct {
	conn     net.Conn
	ch       chan layer.Channel
	channel  *channel
	opts     options
	detached bool
}

// StreamingResponsePredicate decides whether a Receive-direction response
// should bypass body draining. The Channel evaluates this predicate against
// the parsed response (headers + status, before the body is consumed). When
// true, the response Envelope is emitted with an empty body and the still-
// open body reader is held on the Layer for [Layer.DetachStreamingBody].
type StreamingResponsePredicate func(*parser.RawResponse) bool

// options holds Layer configuration.
type options struct {
	scheme             string
	ctx                envelope.EnvelopeContext
	bufSize            int
	bodySpillDir       string
	bodySpillThreshold int64
	maxBody            int64
	streamingDetect    StreamingResponsePredicate

	// stateReleaser is the optional pluginv2 hook invoked when the Channel
	// reaches its terminal state. Drives ReleaseTransaction(ConnID, FlowID)
	// for every envelope this Channel emitted via Next. nil = no-op
	// (legacy parallel path / tests that don't construct an Engine).
	stateReleaser pluginv2.StateReleaser
}

// Option configures a Layer.
type Option func(*options)

// WithScheme sets the HTTP scheme ("http" or "https") for envelopes.
func WithScheme(scheme string) Option {
	return func(o *options) { o.scheme = scheme }
}

// WithEnvelopeContext sets the template EnvelopeContext stamped onto every
// envelope produced by this Layer's Channel. ReceivedAt is overwritten
// per-envelope.
func WithEnvelopeContext(ctx envelope.EnvelopeContext) Option {
	return func(o *options) { o.ctx = ctx }
}

// WithBufioSize sets the bufio.Reader buffer size. Default is 4096.
func WithBufioSize(size int) Option {
	return func(o *options) { o.bufSize = size }
}

// WithBodySpillDir sets the directory used for temp files when a body
// exceeds BodySpillThreshold. Defaults to os.TempDir() if unset.
func WithBodySpillDir(dir string) Option {
	return func(o *options) { o.bodySpillDir = dir }
}

// WithBodySpillThreshold sets the in-memory body size limit above which
// bodies spill to disk. Defaults to config.DefaultBodySpillThreshold (10 MiB).
func WithBodySpillThreshold(n int64) Option {
	return func(o *options) { o.bodySpillThreshold = n }
}

// WithMaxBodySize sets the absolute body size cap. Defaults to config.MaxBodySize
// (254 MiB). Writes exceeding this cap surface as *layer.StreamError with
// Code=layer.ErrorInternalError.
func WithMaxBodySize(n int64) Option {
	return func(o *options) { o.maxBody = n }
}

// WithStateReleaser injects a pluginv2.StateReleaser the Layer invokes
// when the Channel reaches its terminal state. The release fires
// ReleaseTransaction(ConnID, FlowID) once for every envelope the Channel
// emitted via Next during its lifetime — RFC §9.3 D6 / Q26 maps the HTTP
// transaction scope to (ConnID, FlowID). Mirrors http2 / ws / httpaggregator
// shape. nil = no-op.
func WithStateReleaser(r pluginv2.StateReleaser) Option {
	return func(o *options) { o.stateReleaser = r }
}

// WithStreamingResponseDetect installs a predicate evaluated against each
// response on a Receive-direction Channel. When the predicate returns true,
// Channel.Next emits the response Envelope with an empty body and keeps the
// still-open body reader pending on the Layer; the swap orchestrator can
// then claim the body via [Layer.DetachStreamingBody]. The predicate is a
// no-op on Send-direction Channels (which read requests, not responses).
//
// This is the primitive that makes HTTP/1.x → SSE swap possible without
// blocking on a body that has no end (text/event-stream is open-ended; a
// CL-bounded drain would never return).
func WithStreamingResponseDetect(predicate StreamingResponsePredicate) Option {
	return func(o *options) { o.streamingDetect = predicate }
}

// IsSSEResponse is the canonical predicate for [WithStreamingResponseDetect].
// It returns true when rawResp's Content-Type media type is
// text/event-stream (case-insensitive; parameters such as ";charset=utf-8"
// are ignored) AND the status is 2xx — mirroring the equivalent check in
// session.UpgradeStep so detection at the http1 Channel and detection at
// the Pipeline Step agree on the same wire condition.
//
// Per RFC 8895 the canonical content-type for SSE is text/event-stream; we
// accept any 2xx status because servers occasionally use 200, 206, 207 etc.
// for streamed responses (and the wire-fidelity principle says the proxy
// reports what the server sent).
func IsSSEResponse(rawResp *parser.RawResponse) bool {
	if rawResp == nil {
		return false
	}
	if rawResp.StatusCode < 200 || rawResp.StatusCode >= 300 {
		return false
	}
	ct := rawResp.Headers.Get("Content-Type")
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "text/event-stream")
}

// New creates an HTTP/1.x Layer wrapping conn.
//
// direction determines what the Channel parses:
//   - envelope.Send: parses requests (server-facing / client-side layer)
//   - envelope.Receive: parses responses (client-facing / upstream-side layer)
//
// streamID is the connection-level identifier returned by Channel.StreamID().
func New(conn net.Conn, streamID string, direction envelope.Direction, opts ...Option) *Layer {
	o := options{
		scheme:             "http",
		bufSize:            4096,
		bodySpillDir:       "", // resolved to os.TempDir() by bodybuf.NewFile
		bodySpillThreshold: config.DefaultBodySpillThreshold,
		maxBody:            config.MaxBodySize,
	}
	for _, opt := range opts {
		opt(&o)
	}

	l := &Layer{
		conn: conn,
		ch:   make(chan layer.Channel, 1),
		opts: o,
	}

	reader := bufio.NewReaderSize(conn, o.bufSize)

	l.channel = &channel{
		reader:    reader,
		writer:    conn,
		conn:      conn,
		streamID:  streamID,
		direction: direction,
		scheme:    o.scheme,
		ctxTmpl:   o.ctx,
		termDone:  make(chan struct{}),
		bodyOpts: bodyOpts{
			spillDir:       o.bodySpillDir,
			spillThreshold: o.bodySpillThreshold,
			maxBody:        o.maxBody,
		},
		streamingDetect: o.streamingDetect,
		stateReleaser:   o.stateReleaser,
	}
	l.ch <- l.channel
	close(l.ch)
	return l
}

// Channels returns a channel that yields exactly one Channel, then closes.
func (l *Layer) Channels() <-chan layer.Channel { return l.ch }

// Close closes the underlying connection. The Layer owns the connection.
// It also fires the Channel's Closed signal with io.EOF if the Channel has
// not already observed a terminal state (covers the idle-Channel race where
// Close runs with no Next in flight).
//
// If DetachStream has transferred ownership of the conn to a subsequent
// layer (e.g., WSLayer after a 101 Upgrade), Close is a no-op for the conn
// but still calls markTerminated defensively so any observer parked on
// the inner Channel's Closed() unblocks.
func (l *Layer) Close() error {
	if l.detached {
		// Ownership of the conn was transferred via DetachStream; the
		// successor layer owns lifecycle. markTerminated is idempotent so
		// repeated calls (e.g., from defer cleanup) are safe.
		if l.channel != nil {
			l.channel.markTerminated(io.EOF)
		}
		return nil
	}
	err := l.conn.Close()
	if l.channel != nil {
		l.channel.markTerminated(io.EOF)
	}
	return err
}

// DetachStream tears down the HTTP/1 layer after an Upgrade response and
// returns the buffered reader, writer, and underlying closer so that the
// next layer (WebSocket) can be constructed on top of the same wire.
//
// Ownership of the returned bufio.Reader, conn (writer), and conn (closer)
// transfers to the caller. The Layer becomes unusable: subsequent Close()
// calls are no-ops for the conn (the successor layer is responsible for
// closing it). The internal Channel is marked terminated so any observer
// parked on Closed() unblocks.
//
// The bufio.Reader retains any bytes the HTTP/1 parser read past the final
// \r\n\r\n of the 101 Switching Protocols response — those bytes are the
// first WebSocket frame(s) and must be parsed by the next layer.
//
// Any read deadline previously installed by [Layer.Interrupt] is reset to
// zero so the successor Layer's reads operate without a stale past-deadline.
//
// Calling DetachStream more than once returns a sentinel error.
func (l *Layer) DetachStream() (io.Reader, io.Writer, io.Closer, error) {
	if l.detached {
		return nil, nil, nil, errors.New("http1: stream already detached")
	}
	l.detached = true
	// Clear any past-deadline a prior Interrupt installed; the successor
	// Layer (ws / sse) must read without inheriting the wake-up trigger.
	_ = l.conn.SetReadDeadline(time.Time{})
	if l.channel != nil {
		l.channel.markTerminated(io.EOF)
		return l.channel.reader, l.conn, l.conn, nil
	}
	// Defensive: a Layer constructed via New always has a non-nil channel,
	// but if a future refactor ever leaves channel nil we still surface
	// the underlying conn so the caller can drive the wire.
	return l.conn, l.conn, l.conn, nil
}

// Interrupt forwards to the channel's Interrupt method so external callers
// (and tests) can wake a goroutine parked inside Channel.Next without going
// through the unexported channel type. session.upstreamToClient prefers the
// direct Channel.Interrupt path via the channelInterrupter interface; this
// Layer-level wrapper is for callers that hold the Layer rather than the
// Channel (e.g., unit tests).
//
// See channel.Interrupt for the mechanism and limitations.
//
// Returns nil after DetachStream (the channel keeps its conn pointer until
// terminated; SetReadDeadline on a closed conn returns an error which we
// surface, but Interrupt itself does not close the conn).
func (l *Layer) Interrupt() error {
	if l.detached {
		return nil
	}
	if l.channel != nil {
		return l.channel.Interrupt()
	}
	if l.conn == nil {
		return nil
	}
	return l.conn.SetReadDeadline(time.Now())
}

// DetachStreamingBody hands the still-open response body io.ReadCloser to
// the swap orchestrator. Pre-condition: the most recent Channel.Next() must
// have emitted a response Envelope whose body draining was suppressed by
// the configured [WithStreamingResponseDetect] predicate. Returns sentinel
// errors when the precondition is not met.
//
// The returned ReadCloser owns the underlying connection; closing it closes
// the conn. The Layer becomes unusable: subsequent Close calls are no-ops
// for the conn (the successor (e.g. sse.Channel) is responsible for closing
// it). The internal Channel is marked terminated so any observer parked on
// Closed() unblocks.
//
// Any read deadline previously installed by [Layer.Interrupt] is reset to
// zero so the successor reader operates without a stale past-deadline.
func (l *Layer) DetachStreamingBody() (io.ReadCloser, error) {
	if l.detached {
		return nil, errors.New("http1: stream already detached")
	}
	if l.channel == nil || l.channel.streamingBody == nil {
		return nil, errors.New("http1: no streaming body pending (predicate did not match or channel never read)")
	}
	body := l.channel.streamingBody
	l.channel.streamingBody = nil
	l.detached = true
	// Clear any past-deadline a prior Interrupt installed; the successor
	// (sse) must read without inheriting the wake-up trigger.
	_ = l.conn.SetReadDeadline(time.Time{})
	l.channel.markTerminated(io.EOF)
	return &streamingBodyCloser{r: body, conn: l.conn}, nil
}

// streamingBodyCloser pairs the parser's body reader with the conn so the
// swap orchestrator can dispose of the wire by closing the body.
type streamingBodyCloser struct {
	r    io.Reader
	conn net.Conn
}

func (s *streamingBodyCloser) Read(p []byte) (int, error) { return s.r.Read(p) }
func (s *streamingBodyCloser) Close() error               { return s.conn.Close() }
