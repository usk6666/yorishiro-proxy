package grpc

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/config"
)

// FrameCallback is called when a complete gRPC frame has been reassembled.
// The raw parameter contains the original wire bytes (5-byte header + payload)
// for transparent forwarding. The frame parameter contains the parsed frame.
// If the callback returns an error, the FrameBuffer stops processing.
type FrameCallback func(raw []byte, frame *Frame) error

// FrameBuffer reassembles gRPC Length-Prefixed Messages from arbitrary byte
// stream chunks. HTTP/2 DATA frame boundaries do not align with gRPC message
// boundaries, so this buffer accumulates bytes until a complete gRPC message
// (5-byte header + payload) is available.
//
// FrameBuffer is safe for concurrent use.
type FrameBuffer struct {
	mu  sync.Mutex
	buf []byte
	cb  FrameCallback
}

// NewFrameBuffer creates a new FrameBuffer that calls cb for each complete
// gRPC frame. The callback receives both the raw wire bytes (for transparent
// forwarding) and the parsed Frame (for inspection/recording).
func NewFrameBuffer(cb FrameCallback) *FrameBuffer {
	return &FrameBuffer{
		cb: cb,
	}
}

// Write appends data to the internal buffer and emits complete gRPC frames
// via the callback. A single Write call may produce zero, one, or multiple
// frames depending on the data. Partial frames are buffered until the next
// Write call completes them.
//
// This method preserves the original wire bytes for transparent forwarding:
// the raw bytes passed to the callback are exactly the bytes received from
// the network, with no re-encoding.
func (fb *FrameBuffer) Write(data []byte) error {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	// Reject writes that would grow the buffer beyond one maximum gRPC
	// frame (header + payload). This prevents a malicious sender from
	// forcing unbounded memory growth with a slow-drip large frame.
	maxBufSize := frameHeaderSize + int(config.MaxGRPCMessageSize)
	if len(fb.buf)+len(data) > maxBufSize {
		err := fmt.Errorf("grpc frame buffer overflow: %d + %d > %d",
			len(fb.buf), len(data), maxBufSize)
		fb.buf = nil
		return err
	}

	fb.buf = append(fb.buf, data...)

	for {
		if len(fb.buf) < frameHeaderSize {
			return nil
		}

		// Validate compressed flag.
		if fb.buf[0] > 1 {
			err := fmt.Errorf("invalid grpc compressed flag: %d", fb.buf[0])
			fb.buf = nil
			return err
		}

		msgLen := binary.BigEndian.Uint32(fb.buf[1:5])
		if msgLen > config.MaxGRPCMessageSize {
			err := fmt.Errorf("grpc message too large: %d > %d", msgLen, config.MaxGRPCMessageSize)
			fb.buf = nil
			return err
		}

		totalLen := frameHeaderSize + int(msgLen)
		if len(fb.buf) < totalLen {
			// Incomplete frame; wait for more data.
			return nil
		}

		// Extract the raw bytes for this frame.
		raw := make([]byte, totalLen)
		copy(raw, fb.buf[:totalLen])

		frame := &Frame{
			Compressed: raw[0] != 0,
			Payload:    raw[frameHeaderSize:],
		}

		// Advance buffer.
		fb.buf = fb.buf[totalLen:]

		if fb.cb != nil {
			if err := fb.cb(raw, frame); err != nil {
				return fmt.Errorf("frame callback: %w", err)
			}
		}
	}
}

// Flush returns any remaining bytes in the buffer that do not form a complete
// gRPC frame. This should be called when the stream ends to detect incomplete
// frames. Returns nil if the buffer is empty.
func (fb *FrameBuffer) Flush() []byte {
	fb.mu.Lock()
	defer fb.mu.Unlock()

	if len(fb.buf) == 0 {
		return nil
	}
	remaining := make([]byte, len(fb.buf))
	copy(remaining, fb.buf)
	fb.buf = nil
	return remaining
}

// Buffered returns the number of bytes currently buffered (incomplete frame).
func (fb *FrameBuffer) Buffered() int {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	return len(fb.buf)
}
