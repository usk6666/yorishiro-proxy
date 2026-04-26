package envelope

import "time"

// SSE-specific anomaly types. Detected by the SSE parser when an event
// emits with a recoverable protocol-level deviation (i.e. one that does
// NOT terminate the stream — see [SSEMessage.Anomalies]).
const (
	// AnomalySSEMissingData marks an event that reached its blank-line
	// terminator with at least one of event:/id:/retry: set but no data:
	// line. Per WHATWG HTML SSE such events are normally discarded by the
	// user agent, but recording them is useful for MITM diagnostics.
	AnomalySSEMissingData AnomalyType = "SSEMissingData"

	// AnomalySSETruncated marks the final event emitted when the underlying
	// reader returned a non-EOF error mid-event. The accumulated fields
	// are emitted as a best-effort final event so the analyst sees the
	// partial state.
	AnomalySSETruncated AnomalyType = "SSETruncated"

	// AnomalySSEDuplicateID marks an event that observed multiple id:
	// lines. Per RFC 8895 the last value wins, but the duplicate is
	// flagged for analyst visibility.
	AnomalySSEDuplicateID AnomalyType = "SSEDuplicateID"
)

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

	// Anomalies records parser-detected deviations for this event. Stream-
	// terminating problems (oversize event, framing failure) surface as
	// *layer.StreamError instead and never reach this slice.
	Anomalies []Anomaly
}

// Protocol returns ProtocolSSE.
func (m *SSEMessage) Protocol() Protocol { return ProtocolSSE }

// CloneMessage returns a deep copy of the SSEMessage.
func (m *SSEMessage) CloneMessage() Message {
	return &SSEMessage{
		Event:     m.Event,
		Data:      m.Data,
		ID:        m.ID,
		Retry:     m.Retry,
		Anomalies: cloneAnomalies(m.Anomalies),
	}
}
