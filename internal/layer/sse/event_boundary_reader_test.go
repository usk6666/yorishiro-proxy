package sse

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// TestEventBoundaryReader_LFLF covers the canonical SSE event terminator
// "\n\n" — the configuration that broke pre-USK-890 client chunked-decode.
func TestEventBoundaryReader_LFLF(t *testing.T) {
	wire := "data: hello\n\n"
	r := NewEventBoundaryReader(strings.NewReader(wire), 1024)
	got, err := r.Next()
	if err != nil {
		t.Fatalf("Next: unexpected err %v", err)
	}
	if string(got) != wire {
		t.Fatalf("Next = %q, want %q", got, wire)
	}
	got2, err := r.Next()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("second Next err = %v, want io.EOF", err)
	}
	if got2 != nil {
		t.Fatalf("second Next bytes = %q, want nil", got2)
	}
}

// TestEventBoundaryReader_CRLFCRLF covers the legacy CRLF event terminator.
// WHATWG HTML §9.2 treats CR/LF/CRLF as equivalent line endings.
func TestEventBoundaryReader_CRLFCRLF(t *testing.T) {
	wire := "event: ping\r\ndata: 1\r\n\r\n"
	r := NewEventBoundaryReader(strings.NewReader(wire), 1024)
	got, err := r.Next()
	if err != nil {
		t.Fatalf("Next: unexpected err %v", err)
	}
	if string(got) != wire {
		t.Fatalf("Next = %q, want %q", got, wire)
	}
}

// TestEventBoundaryReader_MixedLineEndings exercises mixed LF + CRLF within
// a single event terminated by a "\n\n" blank-line boundary. The internal
// lines retain their original endings (no canonicalization).
func TestEventBoundaryReader_MixedLineEndings(t *testing.T) {
	wire := "event: foo\r\nid: 1\ndata: hello\n\n"
	r := NewEventBoundaryReader(strings.NewReader(wire), 1024)
	got, err := r.Next()
	if err != nil {
		t.Fatalf("Next: unexpected err %v", err)
	}
	if string(got) != wire {
		t.Fatalf("Next = %q, want %q", got, wire)
	}
}

// TestEventBoundaryReader_CRLF_then_LF covers the "\r\n\n" boundary —
// servers that mix CRLF line endings with a bare-LF blank line.
func TestEventBoundaryReader_CRLF_then_LF(t *testing.T) {
	wire := "data: payload-1\r\n\n"
	r := NewEventBoundaryReader(strings.NewReader(wire), 1024)
	got, err := r.Next()
	if err != nil {
		t.Fatalf("Next: unexpected err %v", err)
	}
	if string(got) != wire {
		t.Fatalf("Next = %q, want %q", got, wire)
	}
}

// TestEventBoundaryReader_MultipleEvents asserts back-to-back events
// each surface as one Next() call. This is the core regression target —
// the prior code lost the first event in the chunked-decode path.
func TestEventBoundaryReader_MultipleEvents(t *testing.T) {
	wire := "data: payload-1\n\ndata: payload-2\n\ndata: payload-3\n\n"
	r := NewEventBoundaryReader(strings.NewReader(wire), 1024)

	want := []string{
		"data: payload-1\n\n",
		"data: payload-2\n\n",
		"data: payload-3\n\n",
	}
	for i, exp := range want {
		got, err := r.Next()
		if err != nil {
			t.Fatalf("Next[%d]: unexpected err %v", i, err)
		}
		if string(got) != exp {
			t.Fatalf("Next[%d] = %q, want %q", i, got, exp)
		}
	}
	_, err := r.Next()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("final Next err = %v, want io.EOF", err)
	}
}

// TestEventBoundaryReader_PartialThenEOF covers a stream that ends
// without a terminating blank line. The reader returns the partial bytes
// with io.EOF on the call that observes the underlying EOF, then nil/EOF
// on every subsequent call.
func TestEventBoundaryReader_PartialThenEOF(t *testing.T) {
	wire := "data: no terminator yet"
	r := NewEventBoundaryReader(strings.NewReader(wire), 1024)
	got, err := r.Next()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("Next err = %v, want io.EOF wrapped", err)
	}
	if string(got) != wire {
		t.Fatalf("partial Next = %q, want %q", got, wire)
	}
	got2, err := r.Next()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("second Next err = %v, want io.EOF", err)
	}
	if got2 != nil {
		t.Fatalf("second Next bytes = %q, want nil", got2)
	}
}

// TestEventBoundaryReader_ExactlyAtMaxBytes asserts an event whose total
// raw length equals the cap is accepted (cap is inclusive).
func TestEventBoundaryReader_ExactlyAtMaxBytes(t *testing.T) {
	wire := "data: ok\n\n"
	r := NewEventBoundaryReader(strings.NewReader(wire), len(wire))
	got, err := r.Next()
	if err != nil {
		t.Fatalf("Next: unexpected err %v", err)
	}
	if string(got) != wire {
		t.Fatalf("Next = %q, want %q", got, wire)
	}
}

// TestEventBoundaryReader_OverflowReturnsErrAndPartial asserts an event
// exceeding the cap returns ErrEventTooLarge with the partial buffer
// preserved up to the cap. Subsequent Next calls return (nil, io.EOF) —
// the reader is poisoned.
func TestEventBoundaryReader_OverflowReturnsErrAndPartial(t *testing.T) {
	// Big payload, then a boundary.
	payload := strings.Repeat("a", 200)
	wire := "data: " + payload + "\n\n"
	r := NewEventBoundaryReader(strings.NewReader(wire), 32)
	got, err := r.Next()
	if !errors.Is(err, ErrEventTooLarge) {
		t.Fatalf("Next err = %v, want ErrEventTooLarge", err)
	}
	if len(got) != 32 {
		t.Fatalf("partial len = %d, want cap=32; got=%q", len(got), got)
	}
	got2, err := r.Next()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("post-overflow Next err = %v, want io.EOF", err)
	}
	if got2 != nil {
		t.Fatalf("post-overflow Next bytes = %q, want nil", got2)
	}
}

// TestEventBoundaryReader_CommentOnlyBlock asserts a comment-only block
// (":foo\n\n") yields one raw chunk — the SSE parser will return a nil
// envelope for this block per WHATWG HTML §9.2, and the runUpgradeSSE
// relay forwards the raw bytes verbatim so EventSource clients keep the
// connection warm.
func TestEventBoundaryReader_CommentOnlyBlock(t *testing.T) {
	wire := ": keepalive\n\n"
	r := NewEventBoundaryReader(strings.NewReader(wire), 1024)
	got, err := r.Next()
	if err != nil {
		t.Fatalf("Next: unexpected err %v", err)
	}
	if string(got) != wire {
		t.Fatalf("Next = %q, want %q", got, wire)
	}
}

// TestEventBoundaryReader_TrailingBlanksBetweenEvents asserts inter-event
// whitespace (a stray blank line between two events) is consumed as part
// of the first event's terminator and does not produce a spurious empty
// chunk.
func TestEventBoundaryReader_TrailingBlanksBetweenEvents(t *testing.T) {
	wire := "data: a\n\ndata: b\n\n"
	r := NewEventBoundaryReader(strings.NewReader(wire), 1024)
	got, err := r.Next()
	if err != nil {
		t.Fatalf("Next[0]: %v", err)
	}
	if string(got) != "data: a\n\n" {
		t.Fatalf("Next[0] = %q", got)
	}
	got, err = r.Next()
	if err != nil {
		t.Fatalf("Next[1]: %v", err)
	}
	if string(got) != "data: b\n\n" {
		t.Fatalf("Next[1] = %q", got)
	}
}

// TestEventBoundaryReader_NoSpaceAfterColon round-trips the "data:value"
// no-space-after-colon variant byte-for-byte. The boundary reader does
// not parse fields; it just splits on blank lines.
func TestEventBoundaryReader_NoSpaceAfterColon(t *testing.T) {
	wire := "data:tight\n\n"
	r := NewEventBoundaryReader(strings.NewReader(wire), 1024)
	got, err := r.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if string(got) != wire {
		t.Fatalf("Next = %q, want %q", got, wire)
	}
}

// TestEventBoundaryReader_Bytes verifies the helper works on binary
// data without panics or normalization — defensive against attacker-
// controlled input that embeds NUL bytes.
func TestEventBoundaryReader_Bytes(t *testing.T) {
	wire := []byte("data: \x00null\n\n")
	r := NewEventBoundaryReader(bytes.NewReader(wire), 1024)
	got, err := r.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if !bytes.Equal(got, wire) {
		t.Fatalf("Next = %q, want %q", got, wire)
	}
}

// TestEventBoundaryReader_LineLongerThanBufioBuffer asserts a single SSE
// line longer than the internal bufio buffer (defaultBoundaryBufSize =
// 4096 B) round-trips byte-for-byte. The internal loop relies on
// bufio.ErrBufferFull triggering a continuation pass that appends the
// remaining slice; this test locks the behaviour against regressions.
//
// The payload is 12 KiB so it spans three bufio refills. The per-event
// cap is set well above the payload size so the cap path is not exercised
// — this test focuses on the long-line continuation, not the overflow
// guard (covered by TestEventBoundaryReader_OverflowReturnsErrAndPartial).
func TestEventBoundaryReader_LineLongerThanBufioBuffer(t *testing.T) {
	payload := strings.Repeat("x", 12*1024)
	wire := "data: " + payload + "\n\n"
	r := NewEventBoundaryReader(strings.NewReader(wire), 1<<20)
	got, err := r.Next()
	if err != nil {
		t.Fatalf("Next: unexpected err %v", err)
	}
	if string(got) != wire {
		t.Fatalf("long-line round-trip mismatch: got len=%d, want len=%d", len(got), len(wire))
	}
	got2, err := r.Next()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("second Next err = %v, want io.EOF", err)
	}
	if got2 != nil {
		t.Fatalf("second Next bytes = %q, want nil", got2)
	}
}

// USK-907: WHATWG HTML §9.2.2 ABNF treats CR / LF / CRLF as equivalent
// line terminators. The pre-fix EventBoundaryReader scanned with
// br.ReadSlice('\n'), so a CR-only stream advanced only at EOF — the
// boundary table's "\r\r" entry was unreachable mid-stream because no LF
// was ever read. The fix swaps the line-segment reader for a CR-or-LF
// helper while keeping the boundary table architecture intact.

// TestEventBoundaryReader_CROnlyEventSeparator pins the CR-only mid-stream
// boundary advance. Two events separated by "\r\r" must be returned as
// two distinct Next() calls without buffering until EOF.
func TestEventBoundaryReader_CROnlyEventSeparator(t *testing.T) {
	wire := "data: a\r\rdata: b\r\r"
	r := NewEventBoundaryReader(strings.NewReader(wire), 1024)

	got, err := r.Next()
	if err != nil {
		t.Fatalf("first Next: %v", err)
	}
	if string(got) != "data: a\r\r" {
		t.Fatalf("first Next = %q, want %q", got, "data: a\r\r")
	}

	got, err = r.Next()
	if err != nil {
		t.Fatalf("second Next: %v", err)
	}
	if string(got) != "data: b\r\r" {
		t.Fatalf("second Next = %q, want %q", got, "data: b\r\r")
	}

	got2, err := r.Next()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("third Next err = %v, want io.EOF", err)
	}
	if got2 != nil {
		t.Fatalf("third Next bytes = %q, want nil", got2)
	}
}

// chunkedReader yields one byte per Read() call to exercise the CRLF-spans-
// chunks safety contract: when CR and LF arrive in separate Read() calls
// the readLineSegment helper must reassemble them into one atomic CRLF
// segment so the boundary reader does not interpret CRLF as
// `CR + empty-line + LF`.
type chunkedReader struct {
	data []byte
	pos  int
}

func (c *chunkedReader) Read(p []byte) (int, error) {
	if c.pos >= len(c.data) {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = c.data[c.pos]
	c.pos++
	return 1, nil
}

// TestEventBoundaryReader_CROnlyChunkedReader feeds the CR-only event
// stream one byte at a time. The boundary reader must still emit two
// distinct events.
func TestEventBoundaryReader_CROnlyChunkedReader(t *testing.T) {
	wire := "data: a\r\rdata: b\r\r"
	r := NewEventBoundaryReader(&chunkedReader{data: []byte(wire)}, 1024)

	got, err := r.Next()
	if err != nil {
		t.Fatalf("first Next: %v", err)
	}
	if string(got) != "data: a\r\r" {
		t.Fatalf("first Next = %q, want %q", got, "data: a\r\r")
	}

	got, err = r.Next()
	if err != nil {
		t.Fatalf("second Next: %v", err)
	}
	if string(got) != "data: b\r\r" {
		t.Fatalf("second Next = %q, want %q", got, "data: b\r\r")
	}
}

// TestEventBoundaryReader_CRLFChunkedReader proves CRLF stays atomic when
// the CR and LF bytes arrive in separate Read() calls.
func TestEventBoundaryReader_CRLFChunkedReader(t *testing.T) {
	wire := "event: ping\r\ndata: 1\r\n\r\n"
	r := NewEventBoundaryReader(&chunkedReader{data: []byte(wire)}, 1024)

	got, err := r.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if string(got) != wire {
		t.Fatalf("Next = %q, want %q (CRLF must round-trip byte-identical)", got, wire)
	}
}

// TestEventBoundaryReader_MixedCRLFAndCROnly alternates CRLF-CRLF and
// CR-CR boundaries in one stream — exercises the boundary table's "\r\n\r\n"
// + "\r\r" coverage with the new line-segment driver.
func TestEventBoundaryReader_MixedCRLFAndCROnly(t *testing.T) {
	wire := "data: a\r\n\r\ndata: b\r\rdata: c\r\n\r\n"
	r := NewEventBoundaryReader(strings.NewReader(wire), 1024)

	want := []string{
		"data: a\r\n\r\n",
		"data: b\r\r",
		"data: c\r\n\r\n",
	}
	for i, exp := range want {
		got, err := r.Next()
		if err != nil {
			t.Fatalf("Next[%d]: %v", i, err)
		}
		if string(got) != exp {
			t.Fatalf("Next[%d] = %q, want %q", i, got, exp)
		}
	}
	_, err := r.Next()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("final Next err = %v, want io.EOF", err)
	}
}

// TestFindEventBoundary exercises the boundary-detection helper directly
// for each terminator shape.
func TestFindEventBoundary(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"lf-lf", "abc\n\n", 5},
		{"crlf-crlf", "abc\r\n\r\n", 7},
		{"crlf-lf", "abc\r\n\n", 6},
		{"lf-crlf", "abc\n\r\n", 6},
		{"cr-cr", "abc\r\r", 5},
		{"no-boundary", "abc", -1},
		{"single-lf", "abc\n", -1},
		{"single-crlf", "abc\r\n", -1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := findEventBoundary([]byte(c.in))
			if got != c.want {
				t.Fatalf("findEventBoundary(%q) = %d, want %d", c.in, got, c.want)
			}
		})
	}
}
