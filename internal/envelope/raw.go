package envelope

// RawMessage represents a raw byte chunk from a TCP or raw-mode TLS
// passthrough channel. See RFC-001 section 3.2.4.
type RawMessage struct {
	// Bytes contains exactly the bytes received in one Read() call
	// (or written in one Write() call).
	Bytes []byte
}

// Protocol returns ProtocolRaw.
func (m *RawMessage) Protocol() Protocol { return ProtocolRaw }

// CloneMessage returns a deep copy of the RawMessage.
func (m *RawMessage) CloneMessage() Message {
	return &RawMessage{
		Bytes: cloneBytes(m.Bytes),
	}
}
