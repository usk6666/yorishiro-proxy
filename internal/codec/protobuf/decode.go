// Package protobuf provides schema-less protobuf wire format codec.
// It converts protobuf binary data to/from JSON using heuristic type inference,
// following the same approach as PacketProxy's Protobuf3.java.
//
// JSON key format: "field_number:ordinal:type"
// (e.g. "0001:0000:Varint", "0002:0001:String", "0003:0002:embedded message")
package protobuf

import (
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

// wireType represents a protobuf wire type.
type wireType int

const (
	wireVarint          wireType = 0
	wire64Bit           wireType = 1
	wireLengthDelimited wireType = 2
	// wireStartGroup (3) and wireEndGroup (4) are deprecated and not supported.
	wire32Bit wireType = 5
)

// Decode converts protobuf binary data to a JSON string.
// The JSON uses sorted keys in the format "field_number:ordinal:type".
func Decode(data []byte) (string, error) {
	fields, err := decodeFields(data)
	if err != nil {
		return "", fmt.Errorf("protobuf decode: %w", err)
	}
	b, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		return "", fmt.Errorf("protobuf decode: marshal: %w", err)
	}
	return string(b), nil
}

// decodeFields parses protobuf binary into an ordered map (sorted by ordinal).
func decodeFields(data []byte) (*orderedMap, error) {
	r := &reader{data: data}
	m := newOrderedMap()
	ordinal := 0

	for r.remaining() > 0 {
		keyVal, err := r.readVarint()
		if err != nil {
			return nil, fmt.Errorf("read key: %w", err)
		}

		fieldNumber := keyVal >> 3
		wt := wireType(keyVal & 0x07)

		switch wt {
		case wireVarint:
			v, err := r.readVarint()
			if err != nil {
				return nil, fmt.Errorf("field %d: read varint: %w", fieldNumber, err)
			}
			key := formatKey(fieldNumber, ordinal, "Varint")
			// Store as signed int64 to match PacketProxy's Java long behavior.
			// This ensures negative values round-trip correctly.
			m.set(key, int64(v))

		case wire64Bit:
			v, err := r.readFixed64()
			if err != nil {
				return nil, fmt.Errorf("field %d: read 64-bit: %w", fieldNumber, err)
			}
			key := formatKey(fieldNumber, ordinal, "64-bit")
			// Store as signed int64 to match PacketProxy's Java long.
			m.set(key, int64(v))

		case wire32Bit:
			v, err := r.readFixed32()
			if err != nil {
				return nil, fmt.Errorf("field %d: read 32-bit: %w", fieldNumber, err)
			}
			key := formatKey(fieldNumber, ordinal, "32-bit")
			// Store as signed int32 to match PacketProxy's Java int.
			m.set(key, int32(v))

		case wireLengthDelimited:
			length, err := r.readVarint()
			if err != nil {
				return nil, fmt.Errorf("field %d: read length: %w", fieldNumber, err)
			}
			if length > uint64(r.remaining()) {
				return nil, fmt.Errorf("field %d: length %d exceeds remaining %d", fieldNumber, length, r.remaining())
			}
			raw := r.readBytes(int(length))

			// Heuristic type inference (same priority as PacketProxy):
			// 1. UTF-8 printable string
			// 2. Embedded protobuf message
			// 3. Packed repeated varints
			// 4. Raw bytes (hex)
			if isPrintableUTF8(raw) {
				key := formatKey(fieldNumber, ordinal, "String")
				m.set(key, string(raw))
			} else if sub, err := decodeFields(raw); err == nil {
				key := formatKey(fieldNumber, ordinal, "embedded message")
				m.set(key, sub)
			} else if validateRepeatedStrictly(raw) {
				list := decodeRepeated(raw)
				key := formatKey(fieldNumber, ordinal, "repeated")
				m.set(key, list)
			} else {
				key := formatKey(fieldNumber, ordinal, "bytes")
				m.set(key, encodeHexColon(raw))
			}

		default:
			return nil, fmt.Errorf("unsupported wire type %d", wt)
		}
		ordinal++
	}
	return m, nil
}

// formatKey creates the JSON key in "NNNN:OOOO:type" format.
func formatKey(fieldNumber uint64, ordinal int, typeName string) string {
	return fmt.Sprintf("%04x:%04x:%s", fieldNumber, ordinal, typeName)
}

// isPrintableUTF8 checks if data is valid printable UTF-8.
// Allows CR (0x0D) and LF (0x0A) but rejects other control characters.
// Matches PacketProxy's StringUtils.validatePrintableUTF8.
func isPrintableUTF8(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	i := 0
	for i < len(data) {
		b := data[i]
		// Allow CR and LF
		if b == 0x0D || b == 0x0A {
			i++
			continue
		}
		// Reject control chars (0x01-0x1F except CR/LF) and DEL
		if b > 0 && b < 0x20 {
			return false
		}
		if b == 0x7F {
			return false
		}
		if b == 0x00 {
			return false
		}
		// ASCII printable
		if b&0x80 == 0 {
			i++
			continue
		}
		// Multi-byte UTF-8: validate using standard library
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size <= 1 {
			return false
		}
		i += size
	}
	return true
}

// validateRepeatedStrictly checks if data is a valid packed repeated varint field.
// Returns false if entries exceed 64 or data doesn't align exactly.
func validateRepeatedStrictly(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	i := 0
	entries := 0
	for i < len(data) {
		n, err := varintLength(data[i:])
		if err != nil {
			return false
		}
		i += n
		entries++
	}
	if entries > 64 {
		return false
	}
	return i == len(data)
}

// varintLength returns the byte length of a varint at the start of data.
// Returns error if the varint is invalid.
func varintLength(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, fmt.Errorf("empty data")
	}
	for i := 0; i < len(data) && i < 10; i++ {
		// Reject trailing zero bytes (e.g. 0xf4 0x00 should be 0x74)
		if i >= 1 && data[i] == 0x00 {
			return 0, fmt.Errorf("invalid varint: trailing zero at byte %d", i)
		}
		if data[i]&0x80 == 0 {
			return i + 1, nil
		}
	}
	return 0, fmt.Errorf("varint too long")
}

// decodeRepeated parses packed repeated varints from data.
func decodeRepeated(data []byte) []int64 {
	r := &reader{data: data}
	var list []int64
	for r.remaining() > 0 {
		v, err := r.readVarint()
		if err != nil {
			break
		}
		list = append(list, int64(v))
	}
	return list
}

// encodeHexColon formats bytes as colon-separated hex (e.g. "01:02:0a").
func encodeHexColon(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	buf := make([]byte, 0, len(data)*3-1)
	for i, b := range data {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hexDigits[b>>4], hexDigits[b&0x0f])
	}
	return string(buf)
}

var hexDigits = [16]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}

// reader provides sequential reading over a byte slice.
type reader struct {
	data []byte
	pos  int
}

func (r *reader) remaining() int {
	return len(r.data) - r.pos
}

func (r *reader) readVarint() (uint64, error) {
	var val uint64
	for i := 0; i < 10; i++ {
		if r.pos >= len(r.data) {
			return 0, fmt.Errorf("unexpected end of data reading varint")
		}
		b := r.data[r.pos]
		r.pos++
		val |= uint64(b&0x7f) << (7 * i)
		if b&0x80 == 0 {
			return val, nil
		}
	}
	return 0, fmt.Errorf("varint too long (>10 bytes)")
}

func (r *reader) readFixed64() (uint64, error) {
	if r.remaining() < 8 {
		return 0, fmt.Errorf("not enough data for 64-bit fixed: need 8, have %d", r.remaining())
	}
	var val uint64
	for i := 0; i < 8; i++ {
		val |= uint64(r.data[r.pos]) << (8 * i)
		r.pos++
	}
	return val, nil
}

func (r *reader) readFixed32() (uint32, error) {
	if r.remaining() < 4 {
		return 0, fmt.Errorf("not enough data for 32-bit fixed: need 4, have %d", r.remaining())
	}
	var val uint32
	for i := 0; i < 4; i++ {
		val |= uint32(r.data[r.pos]) << (8 * i)
		r.pos++
	}
	return val, nil
}

func (r *reader) readBytes(n int) []byte {
	b := r.data[r.pos : r.pos+n]
	r.pos += n
	return b
}

// orderedMap preserves insertion order for JSON marshaling,
// while sorting by ordinal (second segment of the key) for encoding.
type orderedMap struct {
	keys   []string
	values map[string]interface{}
}

func newOrderedMap() *orderedMap {
	return &orderedMap{
		values: make(map[string]interface{}),
	}
}

func (m *orderedMap) set(key string, value interface{}) {
	m.keys = append(m.keys, key)
	m.values[key] = value
}

func (m *orderedMap) MarshalJSON() ([]byte, error) {
	buf := []byte{'{'}
	for i, key := range m.keys {
		if i > 0 {
			buf = append(buf, ',')
		}
		keyBytes, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		buf = append(buf, keyBytes...)
		buf = append(buf, ':')

		val := m.values[key]
		valBytes, err := json.Marshal(val)
		if err != nil {
			return nil, err
		}
		buf = append(buf, valBytes...)
	}
	buf = append(buf, '}')
	return buf, nil
}

// extractSortKey creates a sort key from "FFFF:OOOO:type" -> "OOOO-FFFF:OOOO:type"
// matching PacketProxy's orderedKeys logic.
func extractSortKey(key string) string {
	parts := parseKeyParts(key)
	if parts == nil {
		return key
	}
	return fmt.Sprintf("%s-%s", parts[1], key)
}
