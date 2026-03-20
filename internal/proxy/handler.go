package proxy

import (
	"context"
	"net"
)

// ProtocolHandler defines the interface for protocol-specific connection handling.
type ProtocolHandler interface {
	// Name returns the human-readable protocol name (e.g. "HTTP/1.1", "gRPC").
	Name() string

	// Detect examines peeked bytes to determine if this handler can process the connection.
	Detect(peek []byte) bool

	// Handle takes ownership of the connection and processes it according to the protocol.
	Handle(ctx context.Context, conn net.Conn) error
}

// HandlerLister is an optional interface implemented by ProtocolDetector
// implementations that can enumerate their registered handlers.
// This is used by TCPForwardListener to find a handler by name for
// fixed-protocol dispatch (e.g. protocol: "http").
type HandlerLister interface {
	Handlers() []ProtocolHandler
}
