package http1

import (
	"bufio"
	"errors"
	"io"
	"net"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
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

// options holds Layer configuration.
type options struct {
	scheme             string
	ctx                envelope.EnvelopeContext
	bufSize            int
	bodySpillDir       string
	bodySpillThreshold int64
	maxBody            int64
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
// Calling DetachStream more than once returns a sentinel error.
func (l *Layer) DetachStream() (io.Reader, io.Writer, io.Closer, error) {
	if l.detached {
		return nil, nil, nil, errors.New("http1: stream already detached")
	}
	l.detached = true
	if l.channel != nil {
		l.channel.markTerminated(io.EOF)
		return l.channel.reader, l.conn, l.conn, nil
	}
	// Defensive: a Layer constructed via New always has a non-nil channel,
	// but if a future refactor ever leaves channel nil we still surface
	// the underlying conn so the caller can drive the wire.
	return l.conn, l.conn, l.conn, nil
}
