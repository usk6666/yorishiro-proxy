package layer

// Layer consumes a lower layer and yields Channels upward.
//
// For single-channel layers (HTTP/1.x, WebSocket, gRPC wrapper), exactly
// one Channel is sent on the Channels() channel, then it is closed.
// For multi-channel layers (HTTP/2), one Channel is sent per stream.
//
// Close tears down the layer and, if the layer owns its lower resources,
// cascades Close to them. Ownership is established at construction time.
type Layer interface {
	// Channels returns a receive-only channel that yields Channels as they
	// become available. The channel is closed when no more Channels will
	// be produced (either because the layer supports only one, or because
	// the connection was closed).
	Channels() <-chan Channel

	// Close tears down the layer. If the layer owns lower resources
	// (the default), it cascades close to them. If the layer borrows
	// resources (e.g., via DetachStream), it closes only itself.
	Close() error
}
