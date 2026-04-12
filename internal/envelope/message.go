package envelope

// Message is a protocol-specific payload type. Each protocol (HTTP, WebSocket,
// gRPC, raw TCP, etc.) provides its own implementation. See RFC-001 section 3.2.
type Message interface {
	// Protocol returns the protocol identifier. Must match Envelope.Protocol.
	Protocol() Protocol

	// CloneMessage returns a deep copy for variant snapshotting.
	CloneMessage() Message
}

// KeyValue is an order-preserved, case-preserved key-value pair used for
// HTTP headers, trailers, and similar ordered metadata.
type KeyValue struct {
	Name  string
	Value string
}

// cloneKeyValues returns a deep copy of a KeyValue slice.
func cloneKeyValues(kvs []KeyValue) []KeyValue {
	if kvs == nil {
		return nil
	}
	c := make([]KeyValue, len(kvs))
	copy(c, kvs)
	return c
}
