package hpack

// Encoder encodes header fields into HPACK-compressed header blocks.
type Encoder struct {
	dynTable         *DynamicTable
	buf              []byte
	useHuffman       bool
	maxTableSize     uint32
	tableSizeChanged bool
	minTableSize     uint32
}

// NewEncoder creates a new Encoder with the given maximum dynamic table size.
// If useHuffman is true, string literals are Huffman-encoded.
func NewEncoder(maxTableSize uint32, useHuffman bool) *Encoder {
	return &Encoder{
		dynTable:     NewDynamicTable(maxTableSize),
		useHuffman:   useHuffman,
		maxTableSize: maxTableSize,
		minTableSize: maxTableSize,
	}
}

// DynamicTable returns the encoder's dynamic table for inspection.
func (e *Encoder) DynamicTable() *DynamicTable {
	return e.dynTable
}

// SetMaxTableSize updates the maximum dynamic table size.
// A table size update will be emitted at the start of the next header block.
func (e *Encoder) SetMaxTableSize(maxSize uint32) {
	if maxSize < e.minTableSize {
		e.minTableSize = maxSize
	}
	e.maxTableSize = maxSize
	e.tableSizeChanged = true
}

// Encode encodes a list of header fields into an HPACK header block.
func (e *Encoder) Encode(headers []HeaderField) []byte {
	e.buf = e.buf[:0]

	// Emit table size update if needed (Section 6.3).
	if e.tableSizeChanged {
		if e.minTableSize < e.maxTableSize {
			e.buf = encodeInteger(e.buf, 0x20, 5, uint64(e.minTableSize))
			e.dynTable.SetMaxSize(e.minTableSize)
		}
		e.buf = encodeInteger(e.buf, 0x20, 5, uint64(e.maxTableSize))
		e.dynTable.SetMaxSize(e.maxTableSize)
		e.tableSizeChanged = false
		e.minTableSize = e.maxTableSize
	}

	for _, hf := range headers {
		e.encodeField(hf)
	}
	dst := make([]byte, len(e.buf))
	copy(dst, e.buf)
	return dst
}

// encodeField encodes a single header field.
func (e *Encoder) encodeField(hf HeaderField) {
	if hf.Sensitive {
		e.encodeLiteralNeverIndexed(hf)
		return
	}

	// Search static table first.
	if idx, nameOnly := searchStaticTable(hf.Name, hf.Value); idx > 0 {
		if !nameOnly {
			// Full match in static table — emit indexed.
			e.buf = encodeInteger(e.buf, 0x80, 7, idx)
			return
		}
		// Name match only in static — check dynamic for full match.
		if dynIdx, dynNameOnly := e.dynTable.Search(hf.Name, hf.Value); dynIdx >= 0 && !dynNameOnly {
			absIdx := uint64(dynIdx) + staticTableLen + 1
			e.buf = encodeInteger(e.buf, 0x80, 7, absIdx)
			return
		}
		// Literal with incremental indexing, using static name index.
		e.encodeLiteralWithIndex(idx, hf)
		return
	}

	// Search dynamic table.
	if dynIdx, nameOnly := e.dynTable.Search(hf.Name, hf.Value); dynIdx >= 0 {
		absIdx := uint64(dynIdx) + staticTableLen + 1
		if !nameOnly {
			e.buf = encodeInteger(e.buf, 0x80, 7, absIdx)
			return
		}
		e.encodeLiteralWithIndex(absIdx, hf)
		return
	}

	// No match — literal with incremental indexing, new name.
	e.encodeLiteralNewName(hf)
}

// encodeLiteralWithIndex encodes a literal header field with incremental
// indexing using the given name index.
func (e *Encoder) encodeLiteralWithIndex(nameIdx uint64, hf HeaderField) {
	e.buf = encodeInteger(e.buf, 0x40, 6, nameIdx)
	e.buf = e.encodeString(e.buf, hf.Value)
	e.dynTable.Add(hf)
}

// encodeLiteralNewName encodes a literal header field with incremental
// indexing and a new name.
func (e *Encoder) encodeLiteralNewName(hf HeaderField) {
	e.buf = append(e.buf, 0x40)
	e.buf = e.encodeString(e.buf, hf.Name)
	e.buf = e.encodeString(e.buf, hf.Value)
	e.dynTable.Add(hf)
}

// encodeLiteralNeverIndexed encodes a literal header field that must never
// be indexed (Section 6.2.3).
func (e *Encoder) encodeLiteralNeverIndexed(hf HeaderField) {
	// Search for name index.
	if idx, _ := searchStaticTable(hf.Name, hf.Value); idx > 0 {
		e.buf = encodeInteger(e.buf, 0x10, 4, idx)
	} else if dynIdx, _ := e.dynTable.Search(hf.Name, hf.Value); dynIdx >= 0 {
		absIdx := uint64(dynIdx) + staticTableLen + 1
		e.buf = encodeInteger(e.buf, 0x10, 4, absIdx)
	} else {
		e.buf = append(e.buf, 0x10)
		e.buf = e.encodeString(e.buf, hf.Name)
	}
	e.buf = e.encodeString(e.buf, hf.Value)
}

// encodeString encodes a string literal, optionally with Huffman encoding.
func (e *Encoder) encodeString(dst []byte, s string) []byte {
	if e.useHuffman {
		huffLen := huffmanEncodedLen([]byte(s))
		if huffLen < len(s) {
			dst = encodeInteger(dst, 0x80, 7, uint64(huffLen))
			dst = huffmanEncode(dst, []byte(s))
			return dst
		}
	}
	dst = encodeInteger(dst, 0x00, 7, uint64(len(s)))
	dst = append(dst, s...)
	return dst
}
