package protobuf

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Encode converts a JSON string (produced by Decode) back to protobuf binary.
func Encode(jsonStr string) ([]byte, error) {
	fields, err := parseJSON(jsonStr)
	if err != nil {
		return nil, fmt.Errorf("protobuf encode: %w", err)
	}
	return encodeFields(fields)
}

// parseJSON parses the JSON string into field entries preserving order.
func parseJSON(jsonStr string) ([]fieldEntry, error) {
	dec := json.NewDecoder(strings.NewReader(jsonStr))

	// Use json.Decoder Token-based parsing to preserve key order.
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, fmt.Errorf("expected '{', got %v", tok)
	}

	var entries []fieldEntry
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("parse key: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("expected string key, got %T", keyTok)
		}

		var rawVal json.RawMessage
		if err := dec.Decode(&rawVal); err != nil {
			return nil, fmt.Errorf("parse value for %q: %w", key, err)
		}
		entries = append(entries, fieldEntry{key: key, raw: rawVal})
	}

	// Consume closing '}'
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("parse closing: %w", err)
	}

	return entries, nil
}

type fieldEntry struct {
	key string
	raw json.RawMessage
}

// encodeFields serializes field entries to protobuf binary.
// Fields are sorted by ordinal to ensure deterministic output matching PacketProxy.
func encodeFields(entries []fieldEntry) ([]byte, error) {
	sorted := sortEntries(entries)

	var w writer
	for _, e := range sorted {
		if err := encodeField(&w, e); err != nil {
			return nil, err
		}
	}
	return w.buf, nil
}

// encodeField writes a single field entry to the writer.
func encodeField(w *writer, e fieldEntry) error {
	parts := parseKeyParts(e.key)
	if parts == nil {
		return fmt.Errorf("invalid key format: %q", e.key)
	}
	fieldNumber, err := parseHex(parts[0])
	if err != nil {
		return fmt.Errorf("invalid field number in %q: %w", e.key, err)
	}

	switch parts[2] {
	case "Varint":
		return encodeVarintField(w, fieldNumber, e)
	case "String":
		return encodeStringField(w, fieldNumber, e)
	case "32-bit":
		return encode32BitField(w, fieldNumber, e)
	case "64-bit":
		return encode64BitField(w, fieldNumber, e)
	case "repeated":
		return encodeRepeatedField(w, fieldNumber, e)
	case "embedded message":
		return encodeEmbeddedField(w, fieldNumber, e)
	case "bytes":
		return encodeBytesField(w, fieldNumber, e)
	default:
		return fmt.Errorf("unknown type %q in key %q", parts[2], e.key)
	}
}

func encodeVarintField(w *writer, fieldNumber uint64, e fieldEntry) error {
	w.writeVarint((fieldNumber << 3) | uint64(wireVarint))
	v, err := parseNumber(e.raw)
	if err != nil {
		return fmt.Errorf("field %q: %w", e.key, err)
	}
	w.writeVarint(v)
	return nil
}

func encodeStringField(w *writer, fieldNumber uint64, e fieldEntry) error {
	w.writeVarint((fieldNumber << 3) | uint64(wireLengthDelimited))
	var s string
	if err := json.Unmarshal(e.raw, &s); err != nil {
		return fmt.Errorf("field %q: %w", e.key, err)
	}
	b := []byte(s)
	w.writeVarint(uint64(len(b)))
	w.buf = append(w.buf, b...)
	return nil
}

func encode32BitField(w *writer, fieldNumber uint64, e fieldEntry) error {
	w.writeVarint((fieldNumber << 3) | uint64(wire32Bit))
	v, err := parseNumber(e.raw)
	if err != nil {
		return fmt.Errorf("field %q: %w", e.key, err)
	}
	w.writeFixed32(uint32(v))
	return nil
}

func encode64BitField(w *writer, fieldNumber uint64, e fieldEntry) error {
	w.writeVarint((fieldNumber << 3) | uint64(wire64Bit))
	v, err := parseNumber(e.raw)
	if err != nil {
		return fmt.Errorf("field %q: %w", e.key, err)
	}
	w.writeFixed64(v)
	return nil
}

func encodeRepeatedField(w *writer, fieldNumber uint64, e fieldEntry) error {
	w.writeVarint((fieldNumber << 3) | uint64(wireLengthDelimited))
	var list []json.Number
	if err := json.Unmarshal(e.raw, &list); err != nil {
		return fmt.Errorf("field %q: parse repeated: %w", e.key, err)
	}
	var inner writer
	for _, n := range list {
		v, err := parseJSONNumber(n)
		if err != nil {
			return fmt.Errorf("field %q: repeated element: %w", e.key, err)
		}
		inner.writeVarint(v)
	}
	w.writeVarint(uint64(len(inner.buf)))
	w.buf = append(w.buf, inner.buf...)
	return nil
}

func encodeEmbeddedField(w *writer, fieldNumber uint64, e fieldEntry) error {
	w.writeVarint((fieldNumber << 3) | uint64(wireLengthDelimited))
	subEntries, err := parseJSONObject(e.raw)
	if err != nil {
		return fmt.Errorf("field %q: %w", e.key, err)
	}
	subBytes, err := encodeFields(subEntries)
	if err != nil {
		return fmt.Errorf("field %q: %w", e.key, err)
	}
	w.writeVarint(uint64(len(subBytes)))
	w.buf = append(w.buf, subBytes...)
	return nil
}

func encodeBytesField(w *writer, fieldNumber uint64, e fieldEntry) error {
	w.writeVarint((fieldNumber << 3) | uint64(wireLengthDelimited))
	var hexStr string
	if err := json.Unmarshal(e.raw, &hexStr); err != nil {
		return fmt.Errorf("field %q: %w", e.key, err)
	}
	b, err := decodeHexColon(hexStr)
	if err != nil {
		return fmt.Errorf("field %q: %w", e.key, err)
	}
	w.writeVarint(uint64(len(b)))
	w.buf = append(w.buf, b...)
	return nil
}

// parseJSONObject parses a JSON object from raw bytes preserving key order.
func parseJSONObject(raw json.RawMessage) ([]fieldEntry, error) {
	return parseJSON(string(raw))
}

// parseKeyParts splits "FFFF:OOOO:type" into [fieldNumber, ordinal, type].
func parseKeyParts(key string) []string {
	i1 := strings.Index(key, ":")
	if i1 < 0 {
		return nil
	}
	rest := key[i1+1:]
	i2 := strings.Index(rest, ":")
	if i2 < 0 {
		return nil
	}
	return []string{key[:i1], rest[:i2], rest[i2+1:]}
}

// parseHex parses a hex string to uint64.
func parseHex(s string) (uint64, error) {
	var v uint64
	for _, c := range s {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= uint64(c - '0')
		case c >= 'a' && c <= 'f':
			v |= uint64(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			v |= uint64(c - 'A' + 10)
		default:
			return 0, fmt.Errorf("invalid hex char %c", c)
		}
	}
	return v, nil
}

// parseNumber parses a JSON number (integer) as uint64.
func parseNumber(raw json.RawMessage) (uint64, error) {
	// Use json.Number to handle large integers precisely.
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var n json.Number
	if err := dec.Decode(&n); err != nil {
		return 0, fmt.Errorf("parse number: %w", err)
	}
	return parseJSONNumber(n)
}

// parseJSONNumber converts a json.Number to uint64, handling negative values.
func parseJSONNumber(n json.Number) (uint64, error) {
	s := n.String()
	if strings.HasPrefix(s, "-") {
		// Negative: parse as int64 first, then cast to uint64 (two's complement).
		i, err := n.Int64()
		if err != nil {
			return 0, fmt.Errorf("parse negative number %q: %w", s, err)
		}
		return uint64(i), nil
	}
	// Try parsing as float to handle JSON numbers that may exceed int64 range
	// but fit in uint64.
	i, err := n.Int64()
	if err == nil {
		return uint64(i), nil
	}
	// May be a large positive number > int64 max. Try uint64 first for precision.
	u, uErr := strconv.ParseUint(s, 10, 64)
	if uErr == nil {
		return u, nil
	}
	// Fall back to float64 for non-integer or unusual formats.
	f, err := n.Float64()
	if err != nil {
		return 0, fmt.Errorf("parse number %q: %w", s, err)
	}
	if f < 0 || f > math.MaxUint64 {
		return 0, fmt.Errorf("number %q out of uint64 range", s)
	}
	return uint64(f), nil
}

// decodeHexColon parses colon-separated hex (e.g. "01:02:0a") back to bytes.
func decodeHexColon(s string) ([]byte, error) {
	if s == "" {
		return []byte{}, nil
	}
	clean := strings.ReplaceAll(s, ":", "")
	return hex.DecodeString(clean)
}

// sortEntries sorts field entries by ordinal (matching PacketProxy's TreeMap ordering).
func sortEntries(entries []fieldEntry) []fieldEntry {
	sorted := make([]fieldEntry, len(entries))
	copy(sorted, entries)

	type si struct {
		sortKey string
		index   int
	}
	items := make([]si, len(sorted))
	for i, e := range sorted {
		items[i] = si{
			sortKey: extractSortKey(e.key),
			index:   i,
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].sortKey < items[j].sortKey
	})

	result := make([]fieldEntry, len(sorted))
	for i, item := range items {
		result[i] = sorted[item.index]
	}
	return result
}

// writer is a simple byte buffer for writing protobuf wire format.
type writer struct {
	buf []byte
}

func (w *writer) writeVarint(v uint64) {
	for i := 0; i < 10; i++ {
		b := byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			w.buf = append(w.buf, b)
			return
		}
		w.buf = append(w.buf, b|0x80)
	}
}

func (w *writer) writeFixed32(v uint32) {
	w.buf = append(w.buf,
		byte(v),
		byte(v>>8),
		byte(v>>16),
		byte(v>>24),
	)
}

func (w *writer) writeFixed64(v uint64) {
	w.buf = append(w.buf,
		byte(v),
		byte(v>>8),
		byte(v>>16),
		byte(v>>24),
		byte(v>>32),
		byte(v>>40),
		byte(v>>48),
		byte(v>>56),
	)
}
