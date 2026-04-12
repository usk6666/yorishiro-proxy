package layer

import (
	"context"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// Channel is the unit the Pipeline operates on. Each Channel represents a
// single logical stream of Envelopes (e.g., one HTTP/1.x keep-alive
// connection, one HTTP/2 stream, one WebSocket connection).
//
// Next reads the next Envelope from the channel. It returns io.EOF on
// normal termination and other errors (including *StreamError) on abnormal
// termination.
//
// Send writes an Envelope back out through the channel.
//
// Close closes just this channel. The underlying Layer lifecycle is
// managed separately.
type Channel interface {
	// StreamID returns the stable identifier for this channel's lifetime.
	StreamID() string

	// Next reads the next Envelope from the channel.
	// Returns io.EOF on normal termination, *StreamError or other errors
	// on abnormal termination.
	Next(ctx context.Context) (*envelope.Envelope, error)

	// Send writes an Envelope back out through the channel.
	Send(ctx context.Context, env *envelope.Envelope) error

	// Close closes just this channel. Underlying layer lifecycle is separate.
	Close() error
}
