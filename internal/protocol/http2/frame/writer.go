package frame

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Writer writes HTTP/2 frames to an underlying io.Writer.
//
// It validates frame structure before writing. The writer is not safe
// for concurrent use.
type Writer struct {
	w            io.Writer
	maxFrameSize uint32
}

// NewWriter creates a Writer that writes frames to w.
// The initial maximum frame size is set to DefaultMaxFrameSize (16384).
func NewWriter(w io.Writer) *Writer {
	return &Writer{
		w:            w,
		maxFrameSize: DefaultMaxFrameSize,
	}
}

// SetMaxFrameSize updates the maximum allowed frame payload size for writes.
// The value must be between DefaultMaxFrameSize and MaxAllowedFrameSize
// inclusive, per RFC 9113 Section 6.5.2.
func (wr *Writer) SetMaxFrameSize(size uint32) error {
	if size < DefaultMaxFrameSize || size > MaxAllowedFrameSize {
		return fmt.Errorf("set max frame size: %d out of range [%d, %d]", size, DefaultMaxFrameSize, MaxAllowedFrameSize)
	}
	wr.maxFrameSize = size
	return nil
}

// MaxFrameSize returns the current maximum allowed frame payload size.
func (wr *Writer) MaxFrameSize() uint32 {
	return wr.maxFrameSize
}

// WriteFrame writes a complete HTTP/2 frame.
// If the frame has RawBytes set and its length matches header + payload,
// it writes the raw bytes directly. Otherwise, it serializes the header
// and payload.
//
// Returns an error if the payload exceeds the current maximum frame size.
func (wr *Writer) WriteFrame(f *Frame) error {
	if uint32(len(f.Payload)) > wr.maxFrameSize {
		return fmt.Errorf("write frame: payload length %d exceeds max frame size %d", len(f.Payload), wr.maxFrameSize)
	}

	// Use raw bytes if available and consistent.
	if len(f.RawBytes) == HeaderSize+len(f.Payload) {
		_, err := wr.w.Write(f.RawBytes)
		if err != nil {
			return fmt.Errorf("write frame: %w", err)
		}
		return nil
	}

	// Serialize header + payload.
	hdr := Header{
		Length:   uint32(len(f.Payload)),
		Type:     f.Header.Type,
		Flags:    f.Header.Flags,
		StreamID: f.Header.StreamID,
	}
	buf := hdr.AppendTo(make([]byte, 0, HeaderSize+len(f.Payload)))
	buf = append(buf, f.Payload...)

	_, err := wr.w.Write(buf)
	if err != nil {
		return fmt.Errorf("write frame: %w", err)
	}
	return nil
}

// WriteData writes a DATA frame with the given payload.
func (wr *Writer) WriteData(streamID uint32, endStream bool, data []byte) error {
	var flags Flags
	if endStream {
		flags |= FlagEndStream
	}
	return wr.WriteFrame(&Frame{
		Header: Header{
			Length:   uint32(len(data)),
			Type:     TypeData,
			Flags:    flags,
			StreamID: streamID,
		},
		Payload: data,
	})
}

// WriteHeaders writes a HEADERS frame with the given header block fragment.
func (wr *Writer) WriteHeaders(streamID uint32, endStream, endHeaders bool, fragment []byte) error {
	var flags Flags
	if endStream {
		flags |= FlagEndStream
	}
	if endHeaders {
		flags |= FlagEndHeaders
	}
	return wr.WriteFrame(&Frame{
		Header: Header{
			Length:   uint32(len(fragment)),
			Type:     TypeHeaders,
			Flags:    flags,
			StreamID: streamID,
		},
		Payload: fragment,
	})
}

// WriteContinuation writes a CONTINUATION frame with the given header
// block fragment.
func (wr *Writer) WriteContinuation(streamID uint32, endHeaders bool, fragment []byte) error {
	var flags Flags
	if endHeaders {
		flags |= FlagEndHeaders
	}
	return wr.WriteFrame(&Frame{
		Header: Header{
			Length:   uint32(len(fragment)),
			Type:     TypeContinuation,
			Flags:    flags,
			StreamID: streamID,
		},
		Payload: fragment,
	})
}

// WriteSettings writes a SETTINGS frame with the given parameters.
func (wr *Writer) WriteSettings(settings []Setting) error {
	payload := make([]byte, len(settings)*6)
	for i, s := range settings {
		off := i * 6
		binary.BigEndian.PutUint16(payload[off:off+2], uint16(s.ID))
		binary.BigEndian.PutUint32(payload[off+2:off+6], s.Value)
	}
	return wr.WriteFrame(&Frame{
		Header: Header{
			Length: uint32(len(payload)),
			Type:   TypeSettings,
		},
		Payload: payload,
	})
}

// WriteSettingsAck writes a SETTINGS frame with the ACK flag set.
func (wr *Writer) WriteSettingsAck() error {
	return wr.WriteFrame(&Frame{
		Header: Header{
			Type:  TypeSettings,
			Flags: FlagAck,
		},
	})
}

// WritePing writes a PING frame with the given 8-byte opaque data.
func (wr *Writer) WritePing(ack bool, data [8]byte) error {
	var flags Flags
	if ack {
		flags |= FlagAck
	}
	return wr.WriteFrame(&Frame{
		Header: Header{
			Length: 8,
			Type:   TypePing,
			Flags:  flags,
		},
		Payload: data[:],
	})
}

// WriteGoAway writes a GOAWAY frame.
func (wr *Writer) WriteGoAway(lastStreamID, errCode uint32, debugData []byte) error {
	payload := make([]byte, 8+len(debugData))
	binary.BigEndian.PutUint32(payload[0:4], lastStreamID&0x7FFFFFFF)
	binary.BigEndian.PutUint32(payload[4:8], errCode)
	if len(debugData) > 0 {
		copy(payload[8:], debugData)
	}
	return wr.WriteFrame(&Frame{
		Header: Header{
			Length: uint32(len(payload)),
			Type:   TypeGoAway,
		},
		Payload: payload,
	})
}

// WriteWindowUpdate writes a WINDOW_UPDATE frame.
// The increment must be between 1 and 2^31-1 inclusive.
func (wr *Writer) WriteWindowUpdate(streamID, increment uint32) error {
	if increment == 0 || increment > 0x7FFFFFFF {
		return fmt.Errorf("write window update: increment %d out of range [1, %d]", increment, 0x7FFFFFFF)
	}
	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], increment&0x7FFFFFFF)
	return wr.WriteFrame(&Frame{
		Header: Header{
			Length:   4,
			Type:     TypeWindowUpdate,
			StreamID: streamID,
		},
		Payload: payload[:],
	})
}

// WriteRSTStream writes a RST_STREAM frame with the given error code.
func (wr *Writer) WriteRSTStream(streamID, errCode uint32) error {
	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], errCode)
	return wr.WriteFrame(&Frame{
		Header: Header{
			Length:   4,
			Type:     TypeRSTStream,
			StreamID: streamID,
		},
		Payload: payload[:],
	})
}

// WritePriority writes a PRIORITY frame.
func (wr *Writer) WritePriority(streamID uint32, exclusive bool, streamDep uint32, weight uint8) error {
	var payload [5]byte
	v := streamDep & 0x7FFFFFFF
	if exclusive {
		v |= 1 << 31
	}
	binary.BigEndian.PutUint32(payload[0:4], v)
	payload[4] = weight
	return wr.WriteFrame(&Frame{
		Header: Header{
			Length:   5,
			Type:     TypePriority,
			StreamID: streamID,
		},
		Payload: payload[:],
	})
}

// WritePushPromise writes a PUSH_PROMISE frame with the given promised
// stream ID and header block fragment.
func (wr *Writer) WritePushPromise(streamID, promisedStreamID uint32, endHeaders bool, fragment []byte) error {
	var flags Flags
	if endHeaders {
		flags |= FlagEndHeaders
	}
	payload := make([]byte, 4+len(fragment))
	binary.BigEndian.PutUint32(payload[0:4], promisedStreamID&0x7FFFFFFF)
	copy(payload[4:], fragment)
	return wr.WriteFrame(&Frame{
		Header: Header{
			Length:   uint32(len(payload)),
			Type:     TypePushPromise,
			Flags:    flags,
			StreamID: streamID,
		},
		Payload: payload,
	})
}
