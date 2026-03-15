package frame

import (
	"fmt"
	"io"
)

// Reader reads HTTP/2 frames from an underlying io.Reader.
//
// It enforces frame size limits per SETTINGS_MAX_FRAME_SIZE and preserves
// raw bytes for each frame read. The reader is not safe for concurrent use.
type Reader struct {
	r            io.Reader
	maxFrameSize uint32
	headerBuf    [HeaderSize]byte
}

// NewReader creates a Reader that reads frames from r.
// The initial maximum frame size is set to DefaultMaxFrameSize (16384).
func NewReader(r io.Reader) *Reader {
	return &Reader{
		r:            r,
		maxFrameSize: DefaultMaxFrameSize,
	}
}

// SetMaxFrameSize updates the maximum allowed frame payload size.
// The value must be between DefaultMaxFrameSize and MaxAllowedFrameSize
// inclusive, per RFC 9113 Section 6.5.2.
func (rd *Reader) SetMaxFrameSize(size uint32) error {
	if size < DefaultMaxFrameSize || size > MaxAllowedFrameSize {
		return fmt.Errorf("set max frame size: %d out of range [%d, %d]", size, DefaultMaxFrameSize, MaxAllowedFrameSize)
	}
	rd.maxFrameSize = size
	return nil
}

// MaxFrameSize returns the current maximum allowed frame payload size.
func (rd *Reader) MaxFrameSize() uint32 {
	return rd.maxFrameSize
}

// ReadFrame reads the next HTTP/2 frame from the underlying reader.
//
// It returns an error if the frame payload exceeds the current maximum
// frame size. The returned Frame's RawBytes contains the complete frame
// (header + payload) for L4 recording.
//
// If the underlying reader returns io.EOF before any bytes are read,
// ReadFrame returns io.EOF. If EOF occurs mid-frame, it returns
// io.ErrUnexpectedEOF (wrapped).
//
// After a frame size error, the reader is in an unrecoverable state
// (the header has been consumed but the payload remains unread) and
// the connection should be closed.
func (rd *Reader) ReadFrame() (*Frame, error) {
	// Read the 9-byte header.
	_, err := io.ReadFull(rd.r, rd.headerBuf[:])
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, fmt.Errorf("read frame header: %w", io.ErrUnexpectedEOF)
		}
		return nil, err // io.EOF or other error
	}

	hdr, err := ParseHeader(rd.headerBuf[:])
	if err != nil {
		return nil, fmt.Errorf("read frame: %w", err)
	}

	// Enforce frame size limit.
	if hdr.Length > rd.maxFrameSize {
		return nil, fmt.Errorf("read frame: payload length %d exceeds max frame size %d", hdr.Length, rd.maxFrameSize)
	}

	// Allocate raw bytes buffer: header + payload.
	raw := make([]byte, HeaderSize+int(hdr.Length))
	copy(raw[:HeaderSize], rd.headerBuf[:])

	// Read the payload.
	if hdr.Length > 0 {
		_, err = io.ReadFull(rd.r, raw[HeaderSize:])
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return nil, fmt.Errorf("read frame payload: %w", err)
		}
	}

	return &Frame{
		Header:   hdr,
		Payload:  raw[HeaderSize:],
		RawBytes: raw,
	}, nil
}
