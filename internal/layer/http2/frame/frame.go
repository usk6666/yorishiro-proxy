package frame

import (
	"encoding/binary"
	"fmt"
)

// HeaderSize is the fixed size of an HTTP/2 frame header in bytes.
// Per RFC 9113 Section 4.1, the header consists of:
//   - Length (24 bits)
//   - Type (8 bits)
//   - Flags (8 bits)
//   - Reserved (1 bit) + Stream Identifier (31 bits)
const HeaderSize = 9

// DefaultMaxFrameSize is the default value for SETTINGS_MAX_FRAME_SIZE (16384 bytes).
// Per RFC 9113 Section 6.5.2.
const DefaultMaxFrameSize = 1 << 14 // 16384

// MaxAllowedFrameSize is the maximum allowed value for SETTINGS_MAX_FRAME_SIZE (16777215 bytes).
// Per RFC 9113 Section 6.5.2.
const MaxAllowedFrameSize = (1 << 24) - 1 // 16777215

// Type represents an HTTP/2 frame type.
// Per RFC 9113 Section 6, the following frame types are defined.
type Type uint8

const (
	// TypeData indicates a DATA frame (type 0x00).
	TypeData Type = 0x00
	// TypeHeaders indicates a HEADERS frame (type 0x01).
	TypeHeaders Type = 0x01
	// TypePriority indicates a PRIORITY frame (type 0x02).
	TypePriority Type = 0x02
	// TypeRSTStream indicates a RST_STREAM frame (type 0x03).
	TypeRSTStream Type = 0x03
	// TypeSettings indicates a SETTINGS frame (type 0x04).
	TypeSettings Type = 0x04
	// TypePushPromise indicates a PUSH_PROMISE frame (type 0x05).
	TypePushPromise Type = 0x05
	// TypePing indicates a PING frame (type 0x06).
	TypePing Type = 0x06
	// TypeGoAway indicates a GOAWAY frame (type 0x07).
	TypeGoAway Type = 0x07
	// TypeWindowUpdate indicates a WINDOW_UPDATE frame (type 0x08).
	TypeWindowUpdate Type = 0x08
	// TypeContinuation indicates a CONTINUATION frame (type 0x09).
	TypeContinuation Type = 0x09
)

// String returns the human-readable name of the frame type.
func (t Type) String() string {
	switch t {
	case TypeData:
		return "DATA"
	case TypeHeaders:
		return "HEADERS"
	case TypePriority:
		return "PRIORITY"
	case TypeRSTStream:
		return "RST_STREAM"
	case TypeSettings:
		return "SETTINGS"
	case TypePushPromise:
		return "PUSH_PROMISE"
	case TypePing:
		return "PING"
	case TypeGoAway:
		return "GOAWAY"
	case TypeWindowUpdate:
		return "WINDOW_UPDATE"
	case TypeContinuation:
		return "CONTINUATION"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02x)", uint8(t))
	}
}

// Flags represents the flags byte of an HTTP/2 frame.
type Flags uint8

// Common frame flags per RFC 9113 Section 6.
const (
	// FlagEndStream is set on DATA and HEADERS frames to indicate the
	// last frame the endpoint will send for the identified stream.
	FlagEndStream Flags = 0x01
	// FlagAck is set on SETTINGS and PING frames to indicate acknowledgment.
	FlagAck Flags = 0x01
	// FlagEndHeaders is set on HEADERS and CONTINUATION frames to indicate
	// that the header block is complete.
	FlagEndHeaders Flags = 0x04
	// FlagPadded is set on DATA, HEADERS, and PUSH_PROMISE frames to
	// indicate that padding is present.
	FlagPadded Flags = 0x08
	// FlagPriority is set on HEADERS frames to indicate that the Exclusive
	// flag, Stream Dependency, and Weight fields are present.
	FlagPriority Flags = 0x20
)

// Has reports whether f contains all flags in v.
func (f Flags) Has(v Flags) bool {
	return f&v == v
}

// Header represents a parsed HTTP/2 frame header.
type Header struct {
	// Length is the payload length (24 bits, max 16777215).
	Length uint32
	// Type is the frame type.
	Type Type
	// Flags is the frame flags byte.
	Flags Flags
	// StreamID is the stream identifier (31 bits, high bit reserved).
	StreamID uint32
}

// ParseHeader parses a 9-byte frame header.
// The input must be at least HeaderSize bytes; only the first 9 are used.
func ParseHeader(buf []byte) (Header, error) {
	if len(buf) < HeaderSize {
		return Header{}, fmt.Errorf("parse frame header: buffer too short (%d < %d)", len(buf), HeaderSize)
	}
	length := uint32(buf[0])<<16 | uint32(buf[1])<<8 | uint32(buf[2])
	return Header{
		Length:   length,
		Type:     Type(buf[3]),
		Flags:    Flags(buf[4]),
		StreamID: binary.BigEndian.Uint32(buf[5:9]) & 0x7FFFFFFF,
	}, nil
}

// AppendTo appends the serialized 9-byte frame header to dst and returns
// the extended slice.
func (h Header) AppendTo(dst []byte) []byte {
	dst = append(dst, byte(h.Length>>16), byte(h.Length>>8), byte(h.Length))
	dst = append(dst, byte(h.Type))
	dst = append(dst, byte(h.Flags))
	var sid [4]byte
	binary.BigEndian.PutUint32(sid[:], h.StreamID&0x7FFFFFFF)
	dst = append(dst, sid[:]...)
	return dst
}

// Frame represents a complete HTTP/2 frame including its raw bytes.
type Frame struct {
	// Header is the parsed frame header.
	Header Header
	// Payload is the frame payload (excluding the 9-byte header).
	// The length matches Header.Length.
	Payload []byte
	// RawBytes contains the complete raw frame (header + payload).
	// This is preserved for L4 recording.
	RawBytes []byte
}

// DataPayload returns the application data from a DATA frame, stripping
// any padding. Returns an error if the frame is not a DATA frame or if
// padding is invalid.
func (f *Frame) DataPayload() ([]byte, error) {
	if f.Header.Type != TypeData {
		return nil, fmt.Errorf("data payload: frame type is %s, not DATA", f.Header.Type)
	}
	return stripPadding(f.Payload, f.Header.Flags)
}

// HeaderBlockFragment returns the header block fragment from a HEADERS
// frame, stripping any padding and priority fields. Returns an error if
// the frame is not a HEADERS frame or if the payload is malformed.
func (f *Frame) HeaderBlockFragment() ([]byte, error) {
	if f.Header.Type != TypeHeaders {
		return nil, fmt.Errorf("header block fragment: frame type is %s, not HEADERS", f.Header.Type)
	}
	payload := f.Payload
	var err error
	payload, err = stripPadding(payload, f.Header.Flags)
	if err != nil {
		return nil, fmt.Errorf("header block fragment: %w", err)
	}
	if f.Header.Flags.Has(FlagPriority) {
		// Priority fields: 4 bytes stream dependency + 1 byte weight = 5 bytes.
		if len(payload) < 5 {
			return nil, fmt.Errorf("header block fragment: payload too short for priority fields (%d < 5)", len(payload))
		}
		payload = payload[5:]
	}
	return payload, nil
}

// ContinuationFragment returns the header block fragment from a
// CONTINUATION frame. Returns an error if the frame type is wrong.
func (f *Frame) ContinuationFragment() ([]byte, error) {
	if f.Header.Type != TypeContinuation {
		return nil, fmt.Errorf("continuation fragment: frame type is %s, not CONTINUATION", f.Header.Type)
	}
	return f.Payload, nil
}

// SettingsParams parses a SETTINGS frame payload into key-value pairs.
// Each setting is a 16-bit identifier and a 32-bit value (6 bytes per setting).
// Returns an error if the payload length is not a multiple of 6 or if the
// frame type is not SETTINGS.
func (f *Frame) SettingsParams() ([]Setting, error) {
	if f.Header.Type != TypeSettings {
		return nil, fmt.Errorf("settings params: frame type is %s, not SETTINGS", f.Header.Type)
	}
	if f.Header.Flags.Has(FlagAck) {
		if len(f.Payload) != 0 {
			return nil, fmt.Errorf("settings params: ACK frame must have empty payload, got %d bytes", len(f.Payload))
		}
		return nil, nil
	}
	if len(f.Payload)%6 != 0 {
		return nil, fmt.Errorf("settings params: payload length %d is not a multiple of 6", len(f.Payload))
	}
	n := len(f.Payload) / 6
	settings := make([]Setting, n)
	for i := 0; i < n; i++ {
		off := i * 6
		settings[i] = Setting{
			ID:    SettingID(binary.BigEndian.Uint16(f.Payload[off : off+2])),
			Value: binary.BigEndian.Uint32(f.Payload[off+2 : off+6]),
		}
	}
	return settings, nil
}

// PingData returns the 8-byte opaque data from a PING frame.
// Returns an error if the frame type is wrong or the payload is not 8 bytes.
func (f *Frame) PingData() ([8]byte, error) {
	if f.Header.Type != TypePing {
		return [8]byte{}, fmt.Errorf("ping data: frame type is %s, not PING", f.Header.Type)
	}
	if len(f.Payload) != 8 {
		return [8]byte{}, fmt.Errorf("ping data: payload length must be 8, got %d", len(f.Payload))
	}
	var data [8]byte
	copy(data[:], f.Payload)
	return data, nil
}

// GoAwayInfo returns the parsed GOAWAY frame fields.
// Returns an error if the frame type is wrong or the payload is too short.
func (f *Frame) GoAwayInfo() (lastStreamID uint32, errCode uint32, debugData []byte, err error) {
	if f.Header.Type != TypeGoAway {
		return 0, 0, nil, fmt.Errorf("goaway info: frame type is %s, not GOAWAY", f.Header.Type)
	}
	if len(f.Payload) < 8 {
		return 0, 0, nil, fmt.Errorf("goaway info: payload too short (%d < 8)", len(f.Payload))
	}
	lastStreamID = binary.BigEndian.Uint32(f.Payload[0:4]) & 0x7FFFFFFF
	errCode = binary.BigEndian.Uint32(f.Payload[4:8])
	if len(f.Payload) > 8 {
		debugData = f.Payload[8:]
	}
	return lastStreamID, errCode, debugData, nil
}

// WindowUpdateIncrement returns the window size increment from a
// WINDOW_UPDATE frame. Returns an error if the frame type is wrong,
// the payload is not 4 bytes, or the increment is zero.
func (f *Frame) WindowUpdateIncrement() (uint32, error) {
	if f.Header.Type != TypeWindowUpdate {
		return 0, fmt.Errorf("window update increment: frame type is %s, not WINDOW_UPDATE", f.Header.Type)
	}
	if len(f.Payload) != 4 {
		return 0, fmt.Errorf("window update increment: payload length must be 4, got %d", len(f.Payload))
	}
	inc := binary.BigEndian.Uint32(f.Payload) & 0x7FFFFFFF
	if inc == 0 {
		return 0, fmt.Errorf("window update increment: increment must be non-zero")
	}
	return inc, nil
}

// RSTStreamErrorCode returns the error code from a RST_STREAM frame.
// Returns an error if the frame type is wrong or payload is not 4 bytes.
func (f *Frame) RSTStreamErrorCode() (uint32, error) {
	if f.Header.Type != TypeRSTStream {
		return 0, fmt.Errorf("rst stream error code: frame type is %s, not RST_STREAM", f.Header.Type)
	}
	if len(f.Payload) != 4 {
		return 0, fmt.Errorf("rst stream error code: payload length must be 4, got %d", len(f.Payload))
	}
	return binary.BigEndian.Uint32(f.Payload), nil
}

// PushPromiseFields returns the promised stream ID and header block fragment
// from a PUSH_PROMISE frame, stripping any padding.
func (f *Frame) PushPromiseFields() (promisedStreamID uint32, fragment []byte, err error) {
	if f.Header.Type != TypePushPromise {
		return 0, nil, fmt.Errorf("push promise fields: frame type is %s, not PUSH_PROMISE", f.Header.Type)
	}
	payload := f.Payload
	payload, err = stripPadding(payload, f.Header.Flags)
	if err != nil {
		return 0, nil, fmt.Errorf("push promise fields: %w", err)
	}
	if len(payload) < 4 {
		return 0, nil, fmt.Errorf("push promise fields: payload too short for promised stream ID (%d < 4)", len(payload))
	}
	promisedStreamID = binary.BigEndian.Uint32(payload[0:4]) & 0x7FFFFFFF
	fragment = payload[4:]
	return promisedStreamID, fragment, nil
}

// PriorityFields returns the parsed priority fields from a PRIORITY frame.
// Returns an error if the frame type is wrong or the payload is not 5 bytes.
func (f *Frame) PriorityFields() (exclusive bool, streamDep uint32, weight uint8, err error) {
	if f.Header.Type != TypePriority {
		return false, 0, 0, fmt.Errorf("priority fields: frame type is %s, not PRIORITY", f.Header.Type)
	}
	if len(f.Payload) != 5 {
		return false, 0, 0, fmt.Errorf("priority fields: payload length must be 5, got %d", len(f.Payload))
	}
	v := binary.BigEndian.Uint32(f.Payload[0:4])
	exclusive = v>>31 == 1
	streamDep = v & 0x7FFFFFFF
	weight = f.Payload[4]
	return exclusive, streamDep, weight, nil
}

// stripPadding removes padding from a frame payload when the PADDED flag is set.
func stripPadding(payload []byte, flags Flags) ([]byte, error) {
	if !flags.Has(FlagPadded) {
		return payload, nil
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("strip padding: payload empty but PADDED flag set")
	}
	padLen := int(payload[0])
	// Pad Length field is 1 byte, so total overhead is 1 + padLen.
	if padLen+1 > len(payload) {
		return nil, fmt.Errorf("strip padding: pad length %d exceeds remaining payload (%d bytes)", padLen, len(payload)-1)
	}
	return payload[1 : len(payload)-padLen], nil
}

// Setting represents a single HTTP/2 SETTINGS parameter.
type Setting struct {
	// ID is the 16-bit setting identifier.
	ID SettingID
	// Value is the 32-bit setting value.
	Value uint32
}

// SettingID represents an HTTP/2 settings parameter identifier.
type SettingID uint16

// Defined SETTINGS parameters per RFC 9113 Section 6.5.2.
const (
	// SettingHeaderTableSize corresponds to SETTINGS_HEADER_TABLE_SIZE (0x01).
	SettingHeaderTableSize SettingID = 0x01
	// SettingEnablePush corresponds to SETTINGS_ENABLE_PUSH (0x02).
	SettingEnablePush SettingID = 0x02
	// SettingMaxConcurrentStreams corresponds to SETTINGS_MAX_CONCURRENT_STREAMS (0x03).
	SettingMaxConcurrentStreams SettingID = 0x03
	// SettingInitialWindowSize corresponds to SETTINGS_INITIAL_WINDOW_SIZE (0x04).
	SettingInitialWindowSize SettingID = 0x04
	// SettingMaxFrameSize corresponds to SETTINGS_MAX_FRAME_SIZE (0x05).
	SettingMaxFrameSize SettingID = 0x05
	// SettingMaxHeaderListSize corresponds to SETTINGS_MAX_HEADER_LIST_SIZE (0x06).
	SettingMaxHeaderListSize SettingID = 0x06
)

// String returns the human-readable name of the setting ID.
func (id SettingID) String() string {
	switch id {
	case SettingHeaderTableSize:
		return "HEADER_TABLE_SIZE"
	case SettingEnablePush:
		return "ENABLE_PUSH"
	case SettingMaxConcurrentStreams:
		return "MAX_CONCURRENT_STREAMS"
	case SettingInitialWindowSize:
		return "INITIAL_WINDOW_SIZE"
	case SettingMaxFrameSize:
		return "MAX_FRAME_SIZE"
	case SettingMaxHeaderListSize:
		return "MAX_HEADER_LIST_SIZE"
	default:
		return fmt.Sprintf("UNKNOWN(0x%04x)", uint16(id))
	}
}
