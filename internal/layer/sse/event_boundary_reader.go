package sse

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

// ErrEventTooLarge is returned by EventBoundaryReader.Next when a single
// event exceeds the configured maximum size. The returned partial buffer
// (when non-nil) is the bytes accumulated before the cap was crossed so
// the caller can surface the wire snapshot via an anomaly path.
//
// Match with errors.Is.
var ErrEventTooLarge = errors.New("sse: event exceeds maximum size")

// defaultBoundaryBufSize is the initial bufio.Reader buffer; matches the
// SSE parser's default.
const defaultBoundaryBufSize = 4096

// EventBoundaryReader splits a Server-Sent Events byte stream into one raw
// chunk per event boundary. An event is terminated by any double line
// terminator: "\n\n", "\r\n\r\n", "\r\n\n", or "\n\r\n" (WHATWG HTML §9.2
// treats CR / LF / CRLF as equivalent line endings, so the blank line that
// separates events may take any of these forms).
//
// EventBoundaryReader retains the wire-observed raw bytes for each event
// (including the terminating blank line) so a MITM proxy can re-emit them
// byte-for-byte downstream. This is the layer that lets runUpgradeSSE
// forward unchanged events verbatim while still routing each event through
// the Pipeline as a structured envelope.
//
// Concurrency: a single EventBoundaryReader is NOT safe for concurrent use.
// One goroutine must own all Next() calls.
type EventBoundaryReader struct {
	br      *bufio.Reader
	max     int
	buf     []byte
	eof     bool
	pending bool // true when buf carries a partial event awaiting a boundary
}

// NewEventBoundaryReader returns a reader that splits r on SSE event
// boundaries. maxBytes is the per-event cap; non-positive values fall back
// to DefaultMaxEventSize.
func NewEventBoundaryReader(r io.Reader, maxBytes int) *EventBoundaryReader {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxEventSize
	}
	return &EventBoundaryReader{
		br:  bufio.NewReaderSize(r, defaultBoundaryBufSize),
		max: maxBytes,
	}
}

// Next returns the next event's raw bytes, including the terminating blank
// line. On graceful end-of-stream it returns (nil, io.EOF). If a partial
// event is buffered when the underlying reader yields io.EOF, the partial
// bytes are returned with err == io.EOF on that call; the next call
// returns (nil, io.EOF).
//
// If an event would exceed the configured cap, Next returns (partial,
// ErrEventTooLarge) where partial holds the bytes accumulated up to the
// cap. Subsequent calls return (nil, io.EOF) — the reader is poisoned.
//
// On any other read error, Next returns (partial-or-nil, wrapped-err);
// subsequent calls return (nil, io.EOF).
func (e *EventBoundaryReader) Next() ([]byte, error) {
	if e.eof && !e.pending {
		return nil, io.EOF
	}
	for {
		// Have we already buffered a complete event? Scan for the
		// boundary in the current buffer first to avoid pulling more
		// bytes than necessary.
		if i := findEventBoundary(e.buf); i >= 0 {
			out := e.buf[:i]
			e.buf = e.buf[i:]
			if len(e.buf) == 0 {
				e.pending = false
			}
			return cloneBytesSnapshot(out), nil
		}

		line, err := e.br.ReadSlice('\n')
		if len(line) > 0 {
			if len(e.buf)+len(line) > e.max {
				// Append what we can (up to the cap) so the partial
				// snapshot is preserved for diagnostics.
				room := e.max - len(e.buf)
				if room > 0 {
					e.buf = append(e.buf, line[:room]...)
				}
				partial := cloneBytesSnapshot(e.buf)
				e.eof = true
				e.pending = false
				e.buf = nil
				return partial, fmt.Errorf("%w (cap=%d)", ErrEventTooLarge, e.max)
			}
			e.buf = append(e.buf, line...)
			e.pending = true
		}
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				// Line longer than the bufio buffer: keep reading the
				// continuation slices on the next loop iteration.
				continue
			}
			if errors.Is(err, io.EOF) {
				e.eof = true
				if e.pending && len(e.buf) > 0 {
					out := cloneBytesSnapshot(e.buf)
					e.buf = nil
					e.pending = false
					return out, io.EOF
				}
				return nil, io.EOF
			}
			// Unrecoverable read error: surface the partial buffer (if
			// any) so the caller can record what was captured before
			// the wire failed.
			e.eof = true
			partial := cloneBytesSnapshot(e.buf)
			e.buf = nil
			e.pending = false
			if len(partial) > 0 {
				return partial, fmt.Errorf("sse: event boundary read: %w", err)
			}
			return nil, fmt.Errorf("sse: event boundary read: %w", err)
		}
	}
}

// eventBoundaryTerminators lists the recognized event-terminating byte
// sequences in decreasing length order. WHATWG HTML §9.2 treats CR / LF /
// CRLF as equivalent line endings, so the blank line that separates events
// may take any of these forms. Longer sequences are tested first so the
// 4-byte CRLF+CRLF case is not partially matched as a shorter form.
var eventBoundaryTerminators = [][]byte{
	[]byte("\r\n\r\n"),
	[]byte("\r\n\n"),
	[]byte("\n\r\n"),
	[]byte("\n\n"),
	[]byte("\r\r"),
}

// findEventBoundary returns the index just past the first event-terminating
// blank line in b, or -1 if no boundary is present. The returned index is
// inclusive of the terminator so callers slice b[:idx] to obtain the raw
// event bytes.
func findEventBoundary(b []byte) int {
	for i := 0; i < len(b); i++ {
		if b[i] != '\n' && b[i] != '\r' {
			continue
		}
		if end := matchBoundaryAt(b, i); end >= 0 {
			return end
		}
	}
	return -1
}

// matchBoundaryAt returns the index one past the end of the longest
// boundary terminator anchored at b[i], or -1 if no terminator matches.
// Terminators are tested in decreasing length order so the 4-byte
// CRLF+CRLF case is not partially matched as the shorter LF+LF.
func matchBoundaryAt(b []byte, i int) int {
	for _, t := range eventBoundaryTerminators {
		if i+len(t) <= len(b) && bytesEqualAt(b, i, t) {
			return i + len(t)
		}
	}
	return -1
}

// bytesEqualAt reports whether b[i:i+len(t)] equals t. Caller must
// ensure i+len(t) <= len(b).
func bytesEqualAt(b []byte, i int, t []byte) bool {
	for k, c := range t {
		if b[i+k] != c {
			return false
		}
	}
	return true
}

// cloneBytesSnapshot returns an independent copy of b, or nil for empty
// input. Callers retain ownership of the returned slice; the reader's
// internal buffer is reused on the next call.
func cloneBytesSnapshot(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
