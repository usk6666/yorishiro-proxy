package http1

import (
	"net"
	"sync"
)

// interruptCaptureReader wraps a net.Conn so any bytes returned by Read after
// [interruptCaptureReader.StartCapture] is called are recorded in a side
// buffer that DetachStream can replay.
//
// Rationale (USK-715). The H1 → WS swap orchestrator (session.upstreamToClient)
// fires Channel.Interrupt right after Send(101). Interrupt sets a past read
// deadline so the parker (parser.ParseRequest → bufio.Reader → conn.Read)
// surfaces os.ErrDeadlineExceeded and the session can return ErrUpgradePending.
//
// On a slow CI runner the test client's first WS frame can land in the proxy's
// kernel TCP buffer between Send(101) returning and Interrupt's
// SetReadDeadline taking effect — i.e., the in-flight conn.Read syscall
// returns successfully with WS frame bytes BEFORE the deadline is honored.
// Those bytes are then fed to the bufio.Reader and consumed by the parser as
// it tries to parse "the next request". The parser fails (binary WS frame
// bytes are not a valid HTTP request line / headers) and discards the bytes
// when it returns the wrapped error. The bytes are now lost — they are not
// in bufio's buffered remainder (the parser advanced bufio's read pointer
// past them), they are not in the conn (conn already returned them), and
// they are not in the parser's locals (those went out of scope).
//
// The capture reader is the safety net. Once StartCapture is called (just
// before Interrupt's SetReadDeadline) every byte returned by conn.Read is
// also written to a side buffer. After parser exits with the deadline
// error, [Layer.DetachStream] retrieves the captured bytes via Drain and
// builds an io.MultiReader that replays them ahead of bufio.Reader's
// remainder so the new ws.Layer sees the WS frame bytes in their original
// wire order.
//
// Concurrency: a single mutex guards `capturing` + the side buffer slice.
// The Read path (parser goroutine) and the StartCapture / Drain path
// (orchestrator goroutine) call the methods serialized by the mutex.
type interruptCaptureReader struct {
	conn net.Conn

	mu        sync.Mutex
	capturing bool
	buf       []byte // captured bytes; nil until first Read after StartCapture
}

// newInterruptCaptureReader wraps c. The wrapper does not change normal
// read behavior until StartCapture is called.
func newInterruptCaptureReader(c net.Conn) *interruptCaptureReader {
	return &interruptCaptureReader{conn: c}
}

// Read forwards to the underlying conn. When capturing, any bytes returned
// (n > 0) are also appended to the side buffer.
//
// The capture happens AFTER conn.Read returns so the side buffer mirrors
// exactly what bufio.Reader sees on its end of the pipe. We must not capture
// less than what bufio sees or DetachStream's MultiReader would lose bytes.
func (r *interruptCaptureReader) Read(p []byte) (int, error) {
	n, err := r.conn.Read(p)
	if n > 0 {
		r.mu.Lock()
		if r.capturing {
			r.buf = append(r.buf, p[:n]...)
		}
		r.mu.Unlock()
	}
	return n, err
}

// StartCapture enables capture. Bytes returned by Read after this call are
// appended to the side buffer. Subsequent calls are idempotent.
//
// Callers should invoke StartCapture BEFORE the act that may make the
// in-flight Read race-favorable to data-arrival (currently:
// SetReadDeadline(time.Now()) on Interrupt). This minimizes the window where
// a successful conn.Read returns bytes that fall outside the capture.
func (r *interruptCaptureReader) StartCapture() {
	r.mu.Lock()
	r.capturing = true
	r.mu.Unlock()
}

// Drain returns all captured bytes and resets capture state. Subsequent
// Read calls do not capture (until StartCapture is called again). Returns
// nil when no capture occurred.
//
// The returned slice is a fresh copy that the caller owns; the wrapper's
// internal buffer is reset so a long-lived wrapper does not retain old
// captured bytes.
func (r *interruptCaptureReader) Drain() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.capturing = false
	if len(r.buf) == 0 {
		r.buf = nil
		return nil
	}
	out := make([]byte, len(r.buf))
	copy(out, r.buf)
	r.buf = nil
	return out
}
