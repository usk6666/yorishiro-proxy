// Package codec defines the protocol-specific parse/serialize interface.
//
// A Codec is a stateful object tied to the lifecycle of a single connection
// (or a single session after protocol upgrade). Each protocol — HTTP/1.x,
// HTTP/2, WebSocket, gRPC, Raw TCP — implements Codec. The Session loop
// calls Next and Send without knowing the concrete protocol.
//
//	Client <-> [Client Codec] <-> Pipeline <-> [Upstream Codec] <-> Server
package codec

import (
	"context"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
)

// Codec is the protocol-specific parse/serialize interface.
//
// One Codec instance is created per connection (or per post-upgrade session).
// It is stateful: protocol upgrades (HTTP -> WebSocket, HTTP/2 -> gRPC, etc.)
// are handled as internal state transitions and are not exposed in the
// interface. The Session loop is protocol-agnostic.
type Codec interface {
	// Next reads the next Exchange from the wire.
	//
	// It blocks until data arrives or ctx is cancelled. When the stream
	// ends normally (e.g., connection closed by peer), Next returns io.EOF.
	Next(ctx context.Context) (*exchange.Exchange, error)

	// Send writes an Exchange to the wire.
	//
	// If Pipeline Steps have modified Exchange.Headers or Exchange.Body,
	// Send must apply the diff to Exchange.Opaque (the protocol-specific
	// source of truth) before serializing. Send must NOT write
	// Exchange.Headers directly to the wire — this preserves wire fidelity.
	//
	// When Pipeline has not modified anything, the original wire bytes are
	// sent as-is.
	Send(ctx context.Context, ex *exchange.Exchange) error

	// Close releases resources held by the Codec (connections, buffers, etc.).
	Close() error
}
