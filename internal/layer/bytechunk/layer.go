package bytechunk

import (
	"io"
	"net"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// Layer wraps a net.Conn in a single-channel Layer that yields RawMessage
// envelopes. It owns the connection and closes it on Close().
type Layer struct {
	conn    net.Conn
	ch      chan layer.Channel
	channel *Channel
}

// New creates a ByteChunk Layer wrapping conn. The direction parameter
// determines the Direction field on envelopes produced by Next():
//   - envelope.Send means this layer reads client→server traffic
//   - envelope.Receive means this layer reads server→client traffic
//
// Session uses two bytechunk Layers (one per direction) connected to the
// 2-goroutine model.
func New(conn net.Conn, streamID string, direction envelope.Direction) *Layer {
	l := &Layer{
		conn: conn,
		ch:   make(chan layer.Channel, 1),
	}
	l.channel = &Channel{
		conn:      conn,
		streamID:  streamID,
		direction: direction,
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
func (l *Layer) Close() error {
	err := l.conn.Close()
	if l.channel != nil {
		l.channel.markTerminated(io.EOF)
	}
	return err
}
