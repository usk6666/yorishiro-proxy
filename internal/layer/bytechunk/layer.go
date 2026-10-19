package bytechunk

import (
	"io"
	"net"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// Option configures a ByteChunk Layer at construction time.
type Option func(*options)

type options struct {
	ctxTmpl       envelope.EnvelopeContext
	stateReleaser pluginv2.StateReleaser
}

// WithEnvelopeContext sets the EnvelopeContext template stamped on every
// envelope the Layer's Channel produces: ConnID, TargetHost and the TLS
// snapshot of the wire this Layer reads (RFC-001 §3.1 — TLS is per-Layer).
// The template is copied per envelope and ReceivedAt is overwritten with
// the read time; the caller's value is never mutated.
//
// Without it the envelopes carry only ReceivedAt, which leaves
// HostScopeStep with no TargetHost to check (USK-1083). Production
// construction sites always pass it; the MCP resend_raw / fuzz_raw
// Receive Layers do not (their scope is checked before the dial).
func WithEnvelopeContext(ctx envelope.EnvelopeContext) Option {
	return func(o *options) { o.ctxTmpl = ctx }
}

// WithStateReleaser injects a pluginv2.StateReleaser fired once from
// Layer.Close with ReleaseTransaction(ConnID, StreamID) and
// ReleaseStream(ConnID, StreamID) — raw keys both plugin scopes on the
// StreamID (pluginv2 transactionKey). No-op when ConnID is empty. The
// session driving the Layer repeats the release via ReleaseState after it
// exits.
//
// The release runs on Layer.Close, not on the Channel's terminal state:
// after the client side reads EOF the session keeps running Receive
// envelopes, rewritten to the client StreamID, through PluginStep, and a
// release at EOF would let those recreate the scope and leak it.
func WithStateReleaser(r pluginv2.StateReleaser) Option {
	return func(o *options) { o.stateReleaser = r }
}

// Layer wraps a net.Conn in a single-channel Layer that yields RawMessage
// envelopes. It owns the connection and closes it on Close().
type Layer struct {
	conn    net.Conn
	ch      chan layer.Channel
	channel *Channel

	stateReleaser pluginv2.StateReleaser
	releaseOnce   sync.Once
}

// New creates a ByteChunk Layer wrapping conn. The direction parameter
// determines the Direction field on envelopes produced by Next():
//   - envelope.Send means this layer reads client→server traffic
//   - envelope.Receive means this layer reads server→client traffic
//
// Session uses two bytechunk Layers (one per direction) connected to the
// 2-goroutine model.
func New(conn net.Conn, streamID string, direction envelope.Direction, opts ...Option) *Layer {
	var o options
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	l := &Layer{
		conn:          conn,
		ch:            make(chan layer.Channel, 1),
		stateReleaser: o.stateReleaser,
	}
	l.channel = &Channel{
		conn:      conn,
		streamID:  streamID,
		direction: direction,
		ctxTmpl:   o.ctxTmpl,
		buf:       make([]byte, 32*1024), // 32 KB read buffer
		termDone:  make(chan struct{}),
	}
	l.ch <- l.channel
	close(l.ch)
	return l
}

// Channels returns a channel that yields exactly one Channel, then closes.
func (l *Layer) Channels() <-chan layer.Channel { return l.ch }

// Close closes the underlying connection. The Layer owns the connection.
// It also fires the Channel's Closed signal with io.EOF if the Channel has
// not already observed a terminal state, covering the case where Layer.Close
// races an idle Next-less Channel.
//
// Close also fires the WithStateReleaser hook, exactly once however often
// Close is called.
func (l *Layer) Close() error {
	err := l.conn.Close()
	if l.channel != nil {
		l.channel.markTerminated(io.EOF)
	}
	l.releaseOnce.Do(l.ReleaseState)
	return err
}

// ReleaseState drops the plugin transaction / stream scopes keyed on this
// Layer's (ConnID, StreamID) through the WithStateReleaser hook. It is a
// no-op without a releaser or a ConnID, and safe to call repeatedly.
//
// Layer.Close calls it once. The session that drives the Layer calls it
// again after it has exited (USK-1083 review S-2): when a ctx-cancel
// watcher makes the first Close, a plugin dispatch already in flight for
// an envelope read before the Close re-creates the scope, and only a
// release after the session's goroutines are gone is guaranteed to be the
// last one.
func (l *Layer) ReleaseState() {
	if l.stateReleaser == nil || l.channel == nil {
		return
	}
	connID, streamID := l.channel.ctxTmpl.ConnID, l.channel.streamID
	if connID == "" || streamID == "" {
		return
	}
	l.stateReleaser.ReleaseTransaction(connID, streamID)
	l.stateReleaser.ReleaseStream(connID, streamID)
}
