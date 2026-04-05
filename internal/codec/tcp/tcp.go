// Package tcp implements the TCP Codec (identity codec).
//
// TCP Codec performs no parsing or serialization. It passes raw byte chunks
// as Exchange values, one per Read call. Each TCP connection maps to a single
// StreamID; each chunk receives a unique FlowID.
package tcp

import (
	"context"
	"net"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
)

// defaultBufSize is the read buffer size (32 KB).
const defaultBufSize = 32 * 1024

// Codec is a TCP identity codec that wraps a net.Conn.
//
// It satisfies the codec.Codec interface. Each call to Next reads raw bytes
// from the connection and returns them as an Exchange without any protocol
// parsing. Send writes Exchange.Body directly to the connection.
type Codec struct {
	conn      net.Conn
	buf       []byte
	streamID  string
	direction exchange.Direction
	seq       int
}

// New creates a new TCP Codec for the given connection.
//
// streamID is assigned once and shared across all Exchanges produced by this
// Codec instance. direction indicates the data flow direction (Send for
// client-side, Receive for upstream-side).
func New(conn net.Conn, streamID string, direction exchange.Direction) *Codec {
	return &Codec{
		conn:      conn,
		buf:       make([]byte, defaultBufSize),
		streamID:  streamID,
		direction: direction,
	}
}

// NewWithStreamID creates a new TCP Codec with an auto-generated StreamID.
func NewWithStreamID(conn net.Conn, direction exchange.Direction) *Codec {
	return New(conn, uuid.New().String(), direction)
}

// Next reads the next chunk of bytes from the connection and returns it as
// an Exchange. It blocks until data arrives or ctx is cancelled. When the
// connection is closed, Next returns io.EOF.
func (c *Codec) Next(ctx context.Context) (*exchange.Exchange, error) {
	// Respect context cancellation by setting a deadline if the context has one.
	if deadline, ok := ctx.Deadline(); ok {
		if err := c.conn.SetReadDeadline(deadline); err != nil {
			return nil, err
		}
	}

	n, err := c.conn.Read(c.buf)
	if err != nil {
		return nil, err
	}

	body := make([]byte, n)
	copy(body, c.buf[:n])
	raw := make([]byte, n)
	copy(raw, c.buf[:n])

	ex := &exchange.Exchange{
		StreamID:  c.streamID,
		FlowID:    uuid.New().String(),
		Sequence:  c.seq,
		Direction: c.direction,
		Body:      body,
		RawBytes:  raw,
		Protocol:  exchange.TCP,
	}
	c.seq++
	return ex, nil
}

// Send writes the Exchange body to the connection.
func (c *Codec) Send(ctx context.Context, ex *exchange.Exchange) error {
	_, err := c.conn.Write(ex.Body)
	return err
}

// Close closes the underlying connection.
func (c *Codec) Close() error {
	return c.conn.Close()
}
