package sse

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
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
	return &SSEParser{
		scanner: scanner,
		maxSize: maxEventSize,
	}
}

// Next reads and returns the next SSE event from the stream.
// It returns io.EOF when the stream is exhausted. Comment-only blocks
// (lines starting with ":") are silently consumed; Next advances past them
// and returns the next real event.
func (p *SSEParser) Next() (*SSEEvent, error) {
	var (
		eventType string
		dataParts []string
		id        string
		retry     string
		rawBuf    bytes.Buffer
		hasFields bool
	)

	for p.scanner.Scan() {
		line := p.scanner.Text()
		rawBuf.WriteString(line)
		rawBuf.WriteByte('\n')

		// Check for accumulated size limit.
		if rawBuf.Len() > p.maxSize {
			return nil, fmt.Errorf("SSE event exceeds maximum size (%d bytes)", p.maxSize)
		}

		// Blank line terminates the event.
		if line == "" {
			if !hasFields {
				// Empty line without preceding fields: skip (inter-event gap
				// or comment-only block terminator).
				rawBuf.Reset()
				continue
			}
			// Build and return the event.
			data := strings.Join(dataParts, "\n")
			return &SSEEvent{
				EventType: eventType,
				Data:      data,
				ID:        id,
				Retry:     retry,
				RawBytes:  copyBytes(rawBuf.Bytes()),
			}, nil
		}

		// Comment line (starts with ":").
		if strings.HasPrefix(line, ":") {
			continue
		}

		// Parse field name and value.
		fieldName, fieldValue := parseSSEField(line)

		switch fieldName {
		case "event":
			eventType = fieldValue
			hasFields = true
		case "data":
			dataParts = append(dataParts, fieldValue)
			hasFields = true
		case "id":
			// Per spec: if the field value does not contain U+0000 NULL,
			// set the last event ID buffer. We ignore NULL check for simplicity.
			id = fieldValue
			hasFields = true
		case "retry":
			retry = fieldValue
			hasFields = true
		default:
			// Unknown field: ignored per spec, but we mark as having fields
			// so the event is emitted if followed by a blank line.
			hasFields = true
		}
	}

	if err := p.scanner.Err(); err != nil {
		return nil, fmt.Errorf("SSE parse error: %w", err)
	}

	// Stream ended. If we have accumulated fields, emit a final event.
	// This handles the case where the stream closes without a trailing blank line.
	if hasFields {
		data := strings.Join(dataParts, "\n")
		return &SSEEvent{
			EventType: eventType,
			Data:      data,
			ID:        id,
			Retry:     retry,
			RawBytes:  copyBytes(rawBuf.Bytes()),
		}, nil
	}

	return nil, io.EOF
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
