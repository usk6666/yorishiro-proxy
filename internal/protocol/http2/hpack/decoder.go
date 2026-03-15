package hpack

import (
	"errors"
	"fmt"
)

// Decoder decodes HPACK-encoded header blocks.
type Decoder struct {
	dynTable       *DynamicTable
	maxTableSize   uint32 // maximum dynamic table size allowed by SETTINGS
	pendingMaxSize int64  // pending table size update (-1 = none)
}

// ErrIndexOutOfRange is returned when a header field index exceeds the
// combined static + dynamic table size.
var ErrIndexOutOfRange = errors.New("hpack: index out of range")

// NewDecoder creates a new Decoder with the given maximum dynamic table size.
func NewDecoder(maxTableSize uint32) *Decoder {
	return &Decoder{
		dynTable:       NewDynamicTable(maxTableSize),
		maxTableSize:   maxTableSize,
		pendingMaxSize: -1,
	}
}

// DynamicTable returns the decoder's dynamic table for inspection.
func (d *Decoder) DynamicTable() *DynamicTable {
	return d.dynTable
}

// SetMaxTableSize sets the maximum dynamic table size allowed by
// SETTINGS_HEADER_TABLE_SIZE. The encoder must send a dynamic table
// size update before the next header block.
func (d *Decoder) SetMaxTableSize(maxSize uint32) {
	d.maxTableSize = maxSize
}

// Decode decodes a complete header block from data and returns the
// list of header fields. The decoder's dynamic table is updated
// as specified by the encoded instructions.
func (d *Decoder) Decode(data []byte) ([]HeaderField, error) {
	var headers []HeaderField
	for len(data) > 0 {
		hf, rest, err := d.decodeField(data)
		if err != nil {
			return nil, err
		}
		if hf != nil {
			headers = append(headers, *hf)
		}
		data = rest
	}
	return headers, nil
}

// decodeField decodes a single header field representation from data.
// Returns nil HeaderField for table size updates.
func (d *Decoder) decodeField(data []byte) (*HeaderField, []byte, error) {
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("hpack: unexpected end of data")
	}
	b := data[0]

	switch {
	case b&0x80 != 0:
		// Section 6.1: Indexed Header Field Representation
		return d.decodeIndexed(data)

	case b&0xc0 == 0x40:
		// Section 6.2.1: Literal Header Field with Incremental Indexing
		return d.decodeLiteralIndexed(data)

	case b&0xe0 == 0x20:
		// Section 6.3: Dynamic Table Size Update
		return d.decodeTableSizeUpdate(data)

	case b&0xf0 == 0x00:
		// Section 6.2.2: Literal Header Field without Indexing
		return d.decodeLiteralNoIndex(data, false)

	case b&0xf0 == 0x10:
		// Section 6.2.3: Literal Header Field Never Indexed
		return d.decodeLiteralNoIndex(data, true)

	default:
		return nil, nil, fmt.Errorf("hpack: invalid header field prefix 0x%02x", b)
	}
}

// decodeIndexed handles Section 6.1: Indexed Header Field Representation.
func (d *Decoder) decodeIndexed(data []byte) (*HeaderField, []byte, error) {
	idx, consumed, err := decodeInteger(data, 7)
	if err != nil {
		return nil, nil, fmt.Errorf("hpack: indexed field: %w", err)
	}
	if idx == 0 {
		return nil, nil, fmt.Errorf("hpack: indexed field: index 0 is invalid")
	}
	hf, err := d.lookupIndex(idx)
	if err != nil {
		return nil, nil, err
	}
	return &hf, data[consumed:], nil
}

// decodeLiteralIndexed handles Section 6.2.1: Literal with Incremental Indexing.
func (d *Decoder) decodeLiteralIndexed(data []byte) (*HeaderField, []byte, error) {
	idx, consumed, err := decodeInteger(data, 6)
	if err != nil {
		return nil, nil, fmt.Errorf("hpack: literal indexed: %w", err)
	}
	data = data[consumed:]

	var name string
	if idx > 0 {
		hf, err := d.lookupIndex(idx)
		if err != nil {
			return nil, nil, err
		}
		name = hf.Name
	} else {
		name, data, err = d.decodeString(data)
		if err != nil {
			return nil, nil, fmt.Errorf("hpack: literal indexed name: %w", err)
		}
	}

	value, data, err := d.decodeString(data)
	if err != nil {
		return nil, nil, fmt.Errorf("hpack: literal indexed value: %w", err)
	}

	hf := HeaderField{Name: name, Value: value}
	d.dynTable.Add(hf)
	return &hf, data, nil
}

// decodeLiteralNoIndex handles Section 6.2.2 and 6.2.3.
func (d *Decoder) decodeLiteralNoIndex(data []byte, sensitive bool) (*HeaderField, []byte, error) {
	idx, consumed, err := decodeInteger(data, 4)
	if err != nil {
		return nil, nil, fmt.Errorf("hpack: literal no-index: %w", err)
	}
	data = data[consumed:]

	var name string
	if idx > 0 {
		hf, err := d.lookupIndex(idx)
		if err != nil {
			return nil, nil, err
		}
		name = hf.Name
	} else {
		name, data, err = d.decodeString(data)
		if err != nil {
			return nil, nil, fmt.Errorf("hpack: literal no-index name: %w", err)
		}
	}

	value, data, err := d.decodeString(data)
	if err != nil {
		return nil, nil, fmt.Errorf("hpack: literal no-index value: %w", err)
	}

	hf := HeaderField{Name: name, Value: value, Sensitive: sensitive}
	return &hf, data, nil
}

// decodeTableSizeUpdate handles Section 6.3: Dynamic Table Size Update.
func (d *Decoder) decodeTableSizeUpdate(data []byte) (*HeaderField, []byte, error) {
	newSize, consumed, err := decodeInteger(data, 5)
	if err != nil {
		return nil, nil, fmt.Errorf("hpack: table size update: %w", err)
	}
	if uint32(newSize) > d.maxTableSize {
		return nil, nil, fmt.Errorf("hpack: table size update %d exceeds maximum %d", newSize, d.maxTableSize)
	}
	d.dynTable.SetMaxSize(uint32(newSize))
	return nil, data[consumed:], nil
}

// decodeString decodes a string literal (Section 5.2).
func (d *Decoder) decodeString(data []byte) (string, []byte, error) {
	if len(data) == 0 {
		return "", nil, fmt.Errorf("hpack: unexpected end of string data")
	}
	huffmanEncoded := data[0]&0x80 != 0
	length, consumed, err := decodeInteger(data, 7)
	if err != nil {
		return "", nil, fmt.Errorf("hpack: string length: %w", err)
	}
	data = data[consumed:]
	if uint64(len(data)) < length {
		return "", nil, fmt.Errorf("hpack: string data truncated: need %d, have %d", length, len(data))
	}
	raw := data[:length]
	data = data[length:]

	if huffmanEncoded {
		decoded, err := huffmanDecode(nil, raw)
		if err != nil {
			return "", nil, fmt.Errorf("hpack: huffman decode: %w", err)
		}
		return string(decoded), data, nil
	}
	return string(raw), data, nil
}

// lookupIndex returns the header field at the given 1-based HPACK index.
// Indices 1-61 are in the static table; 62+ are in the dynamic table.
func (d *Decoder) lookupIndex(idx uint64) (HeaderField, error) {
	if idx >= 1 && idx <= staticTableLen {
		return staticTable[idx], nil
	}
	dynIdx := int(idx - staticTableLen - 1)
	hf, ok := d.dynTable.Entry(dynIdx)
	if !ok {
		return HeaderField{}, fmt.Errorf("%w: %d", ErrIndexOutOfRange, idx)
	}
	return hf, nil
}
