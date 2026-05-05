package bytechunk

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// Channel is the Pipeline's input/output surface for raw byte chunks.
// Each Next() call reads from the underlying connection and produces a
// RawMessage envelope. Each Send() call writes RawMessage bytes to the
// connection.
type Channel struct {
	conn      net.Conn
	streamID  string
	direction envelope.Direction
	seq       int
	buf       []byte

	// Terminal-state tracking. Populated before termDone is closed so
	// callers observing Closed see a stable Err value.
	termMu   sync.Mutex
	termErr  error
	termOnce sync.Once
	termDone chan struct{}
}

// StreamID returns the stable identifier for this channel.
func (c *Channel) StreamID() string { return c.streamID }

// Next reads the next chunk from the connection and returns it as a
// RawMessage envelope. Returns io.EOF when the connection is closed normally.
//
// If the context has a deadline, it is applied as the read deadline on the
// connection. Context cancellation is also respected.
func (c *Channel) Next(ctx context.Context) (*envelope.Envelope, error) {
	// Apply context deadline to the connection read deadline.
	if deadline, ok := ctx.Deadline(); ok {
		if err := c.conn.SetReadDeadline(deadline); err != nil {
			return nil, fmt.Errorf("bytechunk: set read deadline: %w", err)
		}
		defer c.conn.SetReadDeadline(time.Time{}) //nolint:errcheck
	}

	// Check for context cancellation before blocking on Read.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	n, err := c.conn.Read(c.buf)
	if n > 0 {
		// Copy the bytes out of the reusable buffer.
		data := make([]byte, n)
		copy(data, c.buf[:n])

		env := &envelope.Envelope{
			StreamID:  c.streamID,
			FlowID:    uuid.New().String(),
			Sequence:  c.seq,
			Direction: c.direction,
			Protocol:  envelope.ProtocolRaw,
			Raw:       data,
			Message:   &envelope.RawMessage{Bytes: data},
			Context: envelope.EnvelopeContext{
				ReceivedAt: time.Now(),
			},
		}
		c.seq++
		return env, nil
	}
	if err != nil {
		if err == io.EOF || isConnectionClosed(err) {
			c.markTerminated(io.EOF)
			return nil, io.EOF
		}
		wrapped := fmt.Errorf("bytechunk: read: %w", err)
		c.markTerminated(wrapped)
		return nil, wrapped
	}
	// n == 0 && err == nil: unusual but possible; retry.
	return c.Next(ctx)
}

// Send writes the envelope's RawMessage bytes to the connection.
// The envelope's Message must be a *RawMessage.
func (c *Channel) Send(ctx context.Context, env *envelope.Envelope) error {
	msg, ok := env.Message.(*envelope.RawMessage)
	if !ok {
		return fmt.Errorf("bytechunk: Send requires *RawMessage, got %T", env.Message)
	}
	if len(msg.Bytes) == 0 {
		return nil
	}

	// Apply context deadline to the connection write deadline.
	if deadline, ok := ctx.Deadline(); ok {
		if err := c.conn.SetWriteDeadline(deadline); err != nil {
			return fmt.Errorf("bytechunk: set write deadline: %w", err)
		}
		defer c.conn.SetWriteDeadline(time.Time{}) //nolint:errcheck
	}

	_, err := c.conn.Write(msg.Bytes)
	if err != nil {
		return fmt.Errorf("bytechunk: write: %w", err)
	}
	return nil
}

// Close is a no-op for Channel. The underlying connection is owned by the
// Layer, not the Channel.
func (c *Channel) Close() error { return nil }

// Closed returns a channel closed when this Channel has reached its terminal
// state. See layer.Channel for the contract.
func (c *Channel) Closed() <-chan struct{} { return c.termDone }

// Err returns the terminal error. See layer.Channel for the contract.
func (c *Channel) Err() error {
	c.termMu.Lock()
	defer c.termMu.Unlock()
	return c.termErr
}

// markTerminated stores err (first-writer-wins) and closes termDone exactly
// once. Callers must guarantee err is non-nil; io.EOF is used for normal
// termination.
func (c *Channel) markTerminated(err error) {
	c.termMu.Lock()
	if c.termErr == nil {
		c.termErr = err
	}
	c.termMu.Unlock()
	c.termOnce.Do(func() { close(c.termDone) })
}

// isConnectionClosed checks for common "connection closed" errors that
// should be treated as EOF.
func isConnectionClosed(err error) bool {
	if netErr, ok := err.(*net.OpError); ok {
		return netErr.Err.Error() == "use of closed network connection"
	}
	return false
}
