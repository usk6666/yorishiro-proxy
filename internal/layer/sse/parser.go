package sse

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// SSEEvent represents a single parsed Server-Sent Events event.
// An SSE event is terminated by a blank line ("\n\n" or "\r\n\r\n").
// See: https://html.spec.whatwg.org/multipage/server-sent-events.html
type SSEEvent struct {
	// EventType is the value of the "event:" field, or empty for the default
	// message event type.
	EventType string
	// Data is the concatenated "data:" field values, joined by newlines.
	Data string
	// ID is the value of the last "id:" field, or empty if not set.
	ID string
	// Retry is the value of the "retry:" field as a raw string, or empty
	// if not set. Validation of the numeric value is left to the caller.
	Retry string
	// RawBytes is the original raw bytes of the event as read from the stream,
	// including the terminating blank line.
	RawBytes []byte
	// Anomalies records parser-detected deviations for this event. Empty
	// for well-formed events. The parser still returns the event so the
	// caller sees the partial / suspicious data.
	Anomalies []envelope.Anomaly
}

// String returns the reconstructed SSE event in wire format. This is useful
// for recording and debugging, but may differ slightly from the original
// wire format (e.g., field ordering may change).
func (e *SSEEvent) String() string {
	var b strings.Builder
	if e.EventType != "" {
		fmt.Fprintf(&b, "event: %s\n", e.EventType)
	}
	if e.ID != "" {
		fmt.Fprintf(&b, "id: %s\n", e.ID)
	}
	if e.Retry != "" {
		fmt.Fprintf(&b, "retry: %s\n", e.Retry)
	}
	for _, line := range strings.Split(e.Data, "\n") {
		fmt.Fprintf(&b, "data: %s\n", line)
	}
	b.WriteString("\n")
	return b.String()
}

// SSEParser parses Server-Sent Events from a stream. It reads events one at a
// time from the underlying reader, making it suitable for streaming use.
//
// The parser follows the SSE specification:
//   - Lines starting with ":" are comments and are ignored
//   - Fields are "event:", "data:", "id:", "retry:"
//   - Events are delimited by one or more blank lines
//   - Lines are terminated by LF, CR, or CRLF
type SSEParser struct {
	scanner *bufio.Scanner
	maxSize int
	// truncated is set after the parser emitted a final event carrying
	// AnomalySSETruncated. Subsequent Next() calls return io.EOF so the
	// caller terminates cleanly without re-surfacing the underlying read
	// error as a stream-level abort (the truncation was already conveyed
	// via the anomaly).
	truncated bool
}

// NewSSEParser creates a new SSEParser that reads events from r.
// maxEventSize limits the maximum raw byte size of a single event to prevent
// memory exhaustion (CWE-400). If maxEventSize is 0, a default of 1 MB is used.
func NewSSEParser(r io.Reader, maxEventSize int) *SSEParser {
	if maxEventSize <= 0 {
		maxEventSize = 1 << 20 // 1 MB default
	}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), maxEventSize)
	scanner.Split(splitSSELine)
	return &SSEParser{
		scanner: scanner,
		maxSize: maxEventSize,
	}
}

// splitSSELine is a bufio.SplitFunc that recognises CR / LF / CRLF as
// equivalent line terminators per WHATWG HTML §9.2.2 (Server-sent events —
// Parsing an event stream):
//
//	end-of-line = ( cr lf / cr / lf )
//
// Behavior:
//   - If data contains LF: split at LF; returned token excludes the LF and
//     the immediately preceding CR (CRLF is consumed as one terminator).
//   - If data contains CR followed by a non-LF byte: split at CR; returned
//     token excludes the CR (CR-only terminator).
//   - If data ends in a bare CR and atEOF is false: request more data
//     (the CR may be the start of a CRLF that spans two reads).
//   - At atEOF with non-empty trailing bytes: return them as the final token
//     (with any single trailing CR stripped — CR alone at EOF is its own
//     terminator).
//   - At atEOF with empty data: return (0, nil, nil) signalling EOF.
//
// This contract mirrors bufio.ScanLines' partial-buffer discipline so the
// scanner safely handles CRLF-spans-chunks.
func splitSSELine(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	for i := 0; i < len(data); i++ {
		switch data[i] {
		case '\n':
			// LF terminator. If the immediately preceding byte is CR,
			// the pair is a single CRLF terminator and the token must
			// exclude both bytes.
			if i > 0 && data[i-1] == '\r' {
				return i + 1, data[:i-1], nil
			}
			return i + 1, data[:i], nil
		case '\r':
			// CR terminator candidate. If the next byte is LF, this is
			// a CRLF terminator — let the LF branch on the next loop
			// iteration consume both bytes atomically.
			if i+1 < len(data) {
				if data[i+1] == '\n' {
					continue
				}
				// Next byte is some non-LF byte; CR is its own
				// terminator.
				return i + 1, data[:i], nil
			}
			// CR is the last buffered byte. If atEOF, this CR is the
			// final terminator; emit the preceding bytes as the token.
			// Otherwise request more data — the next read may yield
			// the LF half of a CRLF.
			if atEOF {
				return i + 1, data[:i], nil
			}
			return 0, nil, nil
		}
	}
	// No terminator found. At EOF, return the entire remainder as the
	// final token. Otherwise request more data.
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

// Next reads and returns the next SSE event from the stream.
// It returns io.EOF when the stream is exhausted. Comment-only blocks
// (lines starting with ":") and blocks containing only unknown fields are
// silently consumed; Next advances past them and returns the next real
// event.
//
// Per WHATWG HTML §9.2, a block that ends without observing a data: field
// is a valid client-state update (lastEventId / retry / event-type) — it
// is NOT dispatched as an event. We still emit such a block when at least
// one recognized directive (event:/id:/retry:) was seen, so downstream
// recording surfaces the state change. Unknown fields alone do not
// trigger emission (USK-886).
//
// Anomaly contract: parser-detected deviations that do NOT terminate the
// stream surface on the returned event's Anomalies field; the call still
// succeeds. Stream-terminating problems (oversize event, framing failure)
// are returned as the error.
func (p *SSEParser) Next() (*SSEEvent, error) {
	if p.truncated {
		return nil, io.EOF
	}
	var st eventState

	for p.scanner.Scan() {
		line := p.scanner.Text()
		st.rawBuf.WriteString(line)
		st.rawBuf.WriteByte('\n')

		// Check for accumulated size limit.
		if st.rawBuf.Len() > p.maxSize {
			return nil, fmt.Errorf("SSE event exceeds maximum size (%d bytes)", p.maxSize)
		}

		// Blank line terminates the event.
		if line == "" {
			if !st.hasData && !st.hasDirective {
				// Empty line without preceding data or directive: skip
				// (inter-event gap, comment-only block, unknown-field-only
				// block, or stray chunked-TE terminator that leaked into
				// the SSE parser before USK-886 routed dechunking upstream).
				st.rawBuf.Reset()
				continue
			}
			return st.build(nil), nil
		}

		// Comment line (starts with ":").
		if strings.HasPrefix(line, ":") {
			continue
		}

		// Parse field name and value, then dispatch.
		fieldName, fieldValue := parseSSEField(line)
		st.applyField(fieldName, fieldValue)
	}

	scanErr := p.scanner.Err()

	// Stream ended. If we have accumulated data or a directive, emit a
	// final event. A non-EOF read error mid-event is flagged as
	// AnomalySSETruncated and the partial event is still returned so the
	// analyst can see what was captured before the read failed; subsequent
	// Next() returns io.EOF.
	if st.hasData || st.hasDirective {
		if scanErr != nil {
			p.truncated = true
		}
		return st.build(scanErr), nil
	}

	if scanErr != nil {
		return nil, fmt.Errorf("SSE parse error: %w", scanErr)
	}
	return nil, io.EOF
}

// eventState carries the in-flight accumulators for a single SSE event
// being parsed. Extracted from SSEParser.Next so the per-field dispatch
// logic does not contribute to that function's cyclomatic complexity.
type eventState struct {
	eventType    string
	dataParts    []string
	id           string
	retry        string
	rawBuf       bytes.Buffer
	hasData      bool
	hasDirective bool // event/id/retry seen
	idSeenCount  int
}

// applyField dispatches one parsed SSE field into the in-flight event
// state. Unknown fields are silently ignored per WHATWG HTML §9.2; they
// do NOT flip an emission flag, so unknown-field-only blocks are
// consumed without dispatching (USK-886).
func (s *eventState) applyField(name, value string) {
	switch name {
	case "event":
		s.eventType = value
		s.hasDirective = true
	case "data":
		s.dataParts = append(s.dataParts, value)
		s.hasData = true
	case "id":
		// Per spec: if the field value does not contain U+0000 NULL,
		// set the last event ID buffer. We ignore NULL check for simplicity.
		s.id = value
		s.hasDirective = true
		s.idSeenCount++
	case "retry":
		s.retry = value
		s.hasDirective = true
	}
}

// build hands the accumulated state off to buildEvent. scanErr is non-nil
// when the underlying read failed mid-event; buildEvent attaches the
// truncation anomaly in that case.
func (s *eventState) build(scanErr error) *SSEEvent {
	return buildEvent(s.eventType, s.dataParts, s.id, s.retry,
		s.rawBuf.Bytes(), s.idSeenCount, scanErr)
}

// buildEvent assembles an SSEEvent from accumulated parser state and
// attaches anomalies for recoverable deviations. scanErr, when non-nil,
// is treated as a mid-event truncation marker.
//
// AnomalySSEMissingData is intentionally NOT emitted here. Per WHATWG HTML
// §9.2, a block that observes only directive fields (event:/id:/retry:)
// without data: is a valid client-state update and not an error. The
// AnomalySSEMissingData constant remains defined in envelope/sse.go for
// backward compatibility with previously-captured flows. See USK-886.
func buildEvent(
	eventType string,
	dataParts []string,
	id, retry string,
	raw []byte,
	idSeenCount int,
	scanErr error,
) *SSEEvent {
	var anomalies []envelope.Anomaly
	if idSeenCount > 1 {
		anomalies = append(anomalies, envelope.Anomaly{
			Type:   envelope.AnomalySSEDuplicateID,
			Detail: fmt.Sprintf("event has %d id: lines (last value wins)", idSeenCount),
		})
	}
	if scanErr != nil {
		anomalies = append(anomalies, envelope.Anomaly{
			Type:   envelope.AnomalySSETruncated,
			Detail: fmt.Sprintf("stream ended mid-event: %v", scanErr),
		})
	}
	return &SSEEvent{
		EventType: eventType,
		Data:      strings.Join(dataParts, "\n"),
		ID:        id,
		Retry:     retry,
		RawBytes:  copyBytes(raw),
		Anomalies: anomalies,
	}
}

// parseSSEField splits an SSE line into field name and value.
// Per the spec:
//   - If the line contains ":", the field name is the part before the first ":"
//     and the value is the part after (with a single leading space stripped if present).
//   - If the line does not contain ":", the entire line is the field name and
//     the value is empty.
func parseSSEField(line string) (string, string) {
	idx := strings.IndexByte(line, ':')
	if idx < 0 {
		return line, ""
	}
	name := line[:idx]
	value := line[idx+1:]
	// Strip a single leading space from the value, if present.
	if len(value) > 0 && value[0] == ' ' {
		value = value[1:]
	}
	return name, value
}

// copyBytes returns a copy of b.
func copyBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
