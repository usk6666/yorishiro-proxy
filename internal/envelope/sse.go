package envelope

import "time"

// SSEMessage represents one Server-Sent Event (RFC 8895). See RFC-001
// section 3.2.5.
type SSEMessage struct {
	// Event is the parsed event name (from the "event:" field).
	Event string

	// Data is the parsed event data (from one or more "data:" fields,
	// joined with newlines).
	Data string

	// ID is the parsed last event ID (from the "id:" field).
	ID string

	// Retry is the parsed reconnection interval (from the "retry:"
	// field). Zero when unset.
	Retry time.Duration
}

// Protocol returns ProtocolSSE.
func (m *SSEMessage) Protocol() Protocol { return ProtocolSSE }

// CloneMessage returns a deep copy of the SSEMessage. All fields are
// value types, so assignment is sufficient.
func (m *SSEMessage) CloneMessage() Message {
	return &SSEMessage{
		Event: m.Event,
		Data:  m.Data,
		ID:    m.ID,
		Retry: m.Retry,
	}
}
