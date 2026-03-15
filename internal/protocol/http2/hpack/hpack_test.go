package hpack

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// --- Static Table Tests ---

func TestStaticTable_Size(t *testing.T) {
	// Verify static table has 61 entries.
	count := 0
	for i := 1; i <= staticTableLen; i++ {
		if staticTable[i].Name == "" {
			t.Errorf("static table entry %d has empty name", i)
		}
		count++
	}
	if count != 61 {
		t.Errorf("static table has %d entries, want 61", count)
	}
}

func TestStaticTable_SearchExact(t *testing.T) {
	tests := []struct {
		name  string
		value string
		idx   uint64
	}{
		{":method", "GET", 2},
		{":method", "POST", 3},
		{":path", "/", 4},
		{":path", "/index.html", 5},
		{":scheme", "http", 6},
		{":scheme", "https", 7},
		{":status", "200", 8},
	}
	for _, tt := range tests {
		t.Run(tt.name+"="+tt.value, func(t *testing.T) {
			idx, nameOnly := searchStaticTable(tt.name, tt.value)
			if idx != tt.idx || nameOnly {
				t.Errorf("searchStaticTable(%q, %q) = (%d, %v), want (%d, false)", tt.name, tt.value, idx, nameOnly, tt.idx)
			}
		})
	}
}

func TestStaticTable_SearchNameOnly(t *testing.T) {
	idx, nameOnly := searchStaticTable(":method", "PUT")
	if idx == 0 || !nameOnly {
		t.Errorf("searchStaticTable(':method', 'PUT') = (%d, %v), want (>0, true)", idx, nameOnly)
	}
}

func TestStaticTable_SearchMiss(t *testing.T) {
	idx, _ := searchStaticTable("x-custom", "value")
	if idx != 0 {
		t.Errorf("searchStaticTable('x-custom', 'value') = %d, want 0", idx)
	}
}

// --- HeaderField Tests ---

func TestHeaderField_Size(t *testing.T) {
	hf := HeaderField{Name: "content-type", Value: "text/html"}
	// 12 + 9 + 32 = 53
	if got := hf.Size(); got != 53 {
		t.Errorf("HeaderField.Size() = %d, want 53", got)
	}
}

// --- Dynamic Table Tests ---

func TestDynamicTable_AddAndEntry(t *testing.T) {
	dt := NewDynamicTable(4096)
	dt.Add(HeaderField{Name: "foo", Value: "bar"})
	dt.Add(HeaderField{Name: "baz", Value: "qux"})

	if dt.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", dt.Len())
	}
	// Most recently added is at index 0.
	hf, ok := dt.Entry(0)
	if !ok || hf.Name != "baz" || hf.Value != "qux" {
		t.Errorf("Entry(0) = %+v, %v", hf, ok)
	}
	hf, ok = dt.Entry(1)
	if !ok || hf.Name != "foo" || hf.Value != "bar" {
		t.Errorf("Entry(1) = %+v, %v", hf, ok)
	}
}

func TestDynamicTable_Eviction(t *testing.T) {
	// Minimum entry size is 32 (empty name+value) + actual name+value lengths.
	// Set maxSize so only one entry of size 35 (name=1, value=2, +32) fits.
	dt := NewDynamicTable(35)
	dt.Add(HeaderField{Name: "a", Value: "bb"}) // size = 1+2+32 = 35
	if dt.Len() != 1 {
		t.Fatalf("Len() = %d, want 1", dt.Len())
	}
	dt.Add(HeaderField{Name: "c", Value: "dd"}) // size = 1+2+32 = 35; evicts first
	if dt.Len() != 1 {
		t.Fatalf("Len() = %d after eviction, want 1", dt.Len())
	}
	hf, ok := dt.Entry(0)
	if !ok || hf.Name != "c" {
		t.Errorf("Entry(0) after eviction = %+v, %v", hf, ok)
	}
}

func TestDynamicTable_OversizedEntry(t *testing.T) {
	dt := NewDynamicTable(30) // too small for any entry (min 32 overhead)
	dt.Add(HeaderField{Name: "a", Value: "b"})
	if dt.Len() != 0 {
		t.Errorf("Len() = %d, want 0 (entry too large)", dt.Len())
	}
}

func TestDynamicTable_SetMaxSize(t *testing.T) {
	dt := NewDynamicTable(4096)
	dt.Add(HeaderField{Name: "foo", Value: "bar"}) // size = 3+3+32 = 38
	dt.Add(HeaderField{Name: "baz", Value: "qux"}) // size = 3+3+32 = 38, total = 76
	if dt.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", dt.Len())
	}
	dt.SetMaxSize(40) // only room for one entry
	if dt.Len() != 1 {
		t.Errorf("Len() after SetMaxSize(40) = %d, want 1", dt.Len())
	}
	dt.SetMaxSize(0) // clear all
	if dt.Len() != 0 {
		t.Errorf("Len() after SetMaxSize(0) = %d, want 0", dt.Len())
	}
}

func TestDynamicTable_Search(t *testing.T) {
	dt := NewDynamicTable(4096)
	dt.Add(HeaderField{Name: "foo", Value: "bar"})
	dt.Add(HeaderField{Name: "foo", Value: "baz"})

	// Exact match should return most recent (index 0).
	idx, nameOnly := dt.Search("foo", "baz")
	if idx != 0 || nameOnly {
		t.Errorf("Search('foo','baz') = (%d, %v), want (0, false)", idx, nameOnly)
	}

	// Exact match for older entry.
	idx, nameOnly = dt.Search("foo", "bar")
	if idx != 1 || nameOnly {
		t.Errorf("Search('foo','bar') = (%d, %v), want (1, false)", idx, nameOnly)
	}

	// Name-only match.
	idx, nameOnly = dt.Search("foo", "other")
	if idx < 0 || !nameOnly {
		t.Errorf("Search('foo','other') = (%d, %v), want (>=0, true)", idx, nameOnly)
	}

	// No match.
	idx, _ = dt.Search("nope", "nope")
	if idx != -1 {
		t.Errorf("Search('nope','nope') = %d, want -1", idx)
	}
}

func TestDynamicTable_EntryOutOfRange(t *testing.T) {
	dt := NewDynamicTable(4096)
	_, ok := dt.Entry(0)
	if ok {
		t.Error("Entry(0) on empty table should return false")
	}
	_, ok = dt.Entry(-1)
	if ok {
		t.Error("Entry(-1) should return false")
	}
}

// --- Integer Encoding/Decoding Tests ---

func TestIntegerEncodeDecode(t *testing.T) {
	tests := []struct {
		name   string
		prefix uint8
		value  uint64
	}{
		{"zero_5bit", 5, 0},
		{"small_5bit", 5, 10},
		{"boundary_5bit", 5, 30},
		{"one_over_5bit", 5, 31},
		{"large_5bit", 5, 1337},
		{"zero_7bit", 7, 0},
		{"boundary_7bit", 7, 127},
		{"large_7bit", 7, 12345},
		{"max_4bit", 4, 15},
		{"large_4bit", 4, 256},
		{"very_large", 5, 100000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := encodeInteger(nil, 0, tt.prefix, tt.value)
			decoded, consumed, err := decodeInteger(encoded, tt.prefix)
			if err != nil {
				t.Fatalf("decodeInteger() error = %v", err)
			}
			if consumed != len(encoded) {
				t.Errorf("consumed %d bytes, encoded %d bytes", consumed, len(encoded))
			}
			if decoded != tt.value {
				t.Errorf("decodeInteger() = %d, want %d", decoded, tt.value)
			}
		})
	}
}

// RFC 7541 Section 5.1 example: encoding 10 with 5-bit prefix.
func TestIntegerEncode_RFC_C1_Example1(t *testing.T) {
	encoded := encodeInteger(nil, 0, 5, 10)
	if len(encoded) != 1 || encoded[0] != 10 {
		t.Errorf("encode 10 with 5-bit prefix = %v, want [10]", encoded)
	}
}

// RFC 7541 Section 5.1 example: encoding 1337 with 5-bit prefix.
func TestIntegerEncode_RFC_C1_Example2(t *testing.T) {
	encoded := encodeInteger(nil, 0, 5, 1337)
	want := []byte{31, 154, 10}
	if !bytes.Equal(encoded, want) {
		t.Errorf("encode 1337 with 5-bit prefix = %v, want %v", encoded, want)
	}
}

// RFC 7541 Section 5.1 example: encoding 42 starting at an octet boundary.
func TestIntegerEncode_RFC_C1_Example3(t *testing.T) {
	encoded := encodeInteger(nil, 0, 8, 42)
	if len(encoded) != 1 || encoded[0] != 42 {
		t.Errorf("encode 42 with 8-bit prefix = %v, want [42]", encoded)
	}
}

func TestIntegerDecode_Truncated(t *testing.T) {
	// 5-bit prefix, value >= 31 but no continuation byte.
	_, _, err := decodeInteger([]byte{31}, 5)
	if err == nil {
		t.Error("expected error for truncated integer")
	}
}

func TestIntegerDecode_Empty(t *testing.T) {
	_, _, err := decodeInteger(nil, 5)
	if err == nil {
		t.Error("expected error for empty buffer")
	}
}

func TestIntegerDecode_PreservesHighBits(t *testing.T) {
	// Encode with high bits set in prefix byte.
	encoded := encodeInteger(nil, 0xe0, 5, 10)
	if encoded[0] != 0xea { // 0xe0 | 10
		t.Errorf("prefix byte = 0x%02x, want 0xea", encoded[0])
	}
	decoded, _, err := decodeInteger(encoded, 5)
	if err != nil {
		t.Fatalf("decodeInteger() error = %v", err)
	}
	if decoded != 10 {
		t.Errorf("decoded = %d, want 10", decoded)
	}
}

// --- Huffman Tests ---

func TestHuffman_RoundTrip(t *testing.T) {
	tests := []string{
		"",
		"www.example.com",
		"no-cache",
		"custom-key",
		"custom-value",
		"302",
		"private",
		"Mon, 21 Oct 2013 20:13:21 GMT",
		"https://www.example.com",
	}
	for _, s := range tests {
		t.Run(s, func(t *testing.T) {
			encoded := huffmanEncode(nil, []byte(s))
			decoded, err := huffmanDecode(nil, encoded)
			if err != nil {
				t.Fatalf("huffmanDecode() error = %v", err)
			}
			if string(decoded) != s {
				t.Errorf("huffmanDecode() = %q, want %q", decoded, s)
			}
		})
	}
}

func TestHuffman_KnownEncoding(t *testing.T) {
	// RFC 7541 Appendix C.4.1: "www.example.com" Huffman-encoded.
	input := "www.example.com"
	encoded := huffmanEncode(nil, []byte(input))
	want := mustDecodeHex("f1e3c2e5f23a6ba0ab90f4ff")
	if !bytes.Equal(encoded, want) {
		t.Errorf("huffmanEncode(%q) = %x, want %x", input, encoded, want)
	}
}

func TestHuffmanEncodedLen(t *testing.T) {
	s := []byte("www.example.com")
	got := huffmanEncodedLen(s)
	encoded := huffmanEncode(nil, s)
	if got != len(encoded) {
		t.Errorf("huffmanEncodedLen() = %d, actual encoded len = %d", got, len(encoded))
	}
}

// --- Decoder Tests ---

func TestDecoder_IndexedField(t *testing.T) {
	// Encode :method GET (index 2).
	data := encodeInteger(nil, 0x80, 7, 2)
	dec := NewDecoder(4096)
	headers, err := dec.Decode(data)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(headers) != 1 {
		t.Fatalf("Decode() returned %d headers, want 1", len(headers))
	}
	if headers[0].Name != ":method" || headers[0].Value != "GET" {
		t.Errorf("Decode() = %+v, want :method=GET", headers[0])
	}
}

func TestDecoder_LiteralWithIndexing(t *testing.T) {
	dec := NewDecoder(4096)
	// 0x40 = literal with incremental indexing, new name.
	var data []byte
	data = append(data, 0x40) // index 0 = new name
	data = encodeInteger(data, 0x00, 7, 10)
	data = append(data, "custom-key"...)
	data = encodeInteger(data, 0x00, 7, 12)
	data = append(data, "custom-value"...)

	headers, err := dec.Decode(data)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(headers) != 1 {
		t.Fatalf("Decode() returned %d headers, want 1", len(headers))
	}
	if headers[0].Name != "custom-key" || headers[0].Value != "custom-value" {
		t.Errorf("header = %+v", headers[0])
	}
	// Should be added to dynamic table.
	if dec.DynamicTable().Len() != 1 {
		t.Errorf("dynamic table len = %d, want 1", dec.DynamicTable().Len())
	}
}

func TestDecoder_LiteralNeverIndexed(t *testing.T) {
	dec := NewDecoder(4096)
	var data []byte
	data = append(data, 0x10) // never indexed, new name
	data = encodeInteger(data, 0x00, 7, 8)
	data = append(data, "password"...)
	data = encodeInteger(data, 0x00, 7, 6)
	data = append(data, "secret"...)

	headers, err := dec.Decode(data)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(headers) != 1 {
		t.Fatalf("got %d headers, want 1", len(headers))
	}
	if !headers[0].Sensitive {
		t.Error("expected Sensitive=true for never-indexed field")
	}
	if dec.DynamicTable().Len() != 0 {
		t.Error("never-indexed field should not be added to dynamic table")
	}
}

func TestDecoder_LiteralWithoutIndexing(t *testing.T) {
	dec := NewDecoder(4096)
	var data []byte
	data = append(data, 0x00) // without indexing, new name
	data = encodeInteger(data, 0x00, 7, 4)
	data = append(data, "path"...)
	data = encodeInteger(data, 0x00, 7, 5)
	data = append(data, "/test"...)

	headers, err := dec.Decode(data)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(headers) != 1 || headers[0].Name != "path" || headers[0].Value != "/test" {
		t.Errorf("got %+v", headers)
	}
	if headers[0].Sensitive {
		t.Error("expected Sensitive=false for without-indexing field")
	}
	if dec.DynamicTable().Len() != 0 {
		t.Error("without-indexing field should not be added to dynamic table")
	}
}

func TestDecoder_TableSizeUpdate(t *testing.T) {
	dec := NewDecoder(4096)
	// Table size update to 256.
	data := encodeInteger(nil, 0x20, 5, 256)
	headers, err := dec.Decode(data)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(headers) != 0 {
		t.Errorf("table size update should not produce headers, got %d", len(headers))
	}
	if dec.DynamicTable().MaxSize() != 256 {
		t.Errorf("dynamic table max size = %d, want 256", dec.DynamicTable().MaxSize())
	}
}

func TestDecoder_TableSizeUpdate_ExceedsMax(t *testing.T) {
	dec := NewDecoder(4096)
	data := encodeInteger(nil, 0x20, 5, 8192) // exceeds max
	_, err := dec.Decode(data)
	if err == nil {
		t.Error("expected error for table size update exceeding maximum")
	}
}

func TestDecoder_IndexZero(t *testing.T) {
	data := encodeInteger(nil, 0x80, 7, 0)
	dec := NewDecoder(4096)
	_, err := dec.Decode(data)
	if err == nil {
		t.Error("expected error for index 0")
	}
}

func TestDecoder_IndexOutOfRange(t *testing.T) {
	data := encodeInteger(nil, 0x80, 7, 100) // beyond static + empty dynamic
	dec := NewDecoder(4096)
	_, err := dec.Decode(data)
	if err == nil {
		t.Error("expected error for out-of-range index")
	}
}

func TestDecoder_EmptyInput(t *testing.T) {
	dec := NewDecoder(4096)
	headers, err := dec.Decode(nil)
	if err != nil {
		t.Fatalf("Decode(nil) error = %v", err)
	}
	if len(headers) != 0 {
		t.Errorf("Decode(nil) returned %d headers, want 0", len(headers))
	}
}

// --- Encoder Tests ---

func TestEncoder_IndexedField(t *testing.T) {
	enc := NewEncoder(4096, false)
	dec := NewDecoder(4096)

	headers := []HeaderField{
		{Name: ":method", Value: "GET"},
	}
	data := enc.Encode(headers)
	decoded, err := dec.Decode(data)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(decoded) != 1 || decoded[0].Name != ":method" || decoded[0].Value != "GET" {
		t.Errorf("round-trip failed: %+v", decoded)
	}
}

func TestEncoder_LiteralNewName(t *testing.T) {
	enc := NewEncoder(4096, false)
	dec := NewDecoder(4096)

	headers := []HeaderField{
		{Name: "x-custom", Value: "hello"},
	}
	data := enc.Encode(headers)
	decoded, err := dec.Decode(data)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(decoded) != 1 || decoded[0].Name != "x-custom" || decoded[0].Value != "hello" {
		t.Errorf("round-trip failed: %+v", decoded)
	}
}

func TestEncoder_DynamicTableReuse(t *testing.T) {
	enc := NewEncoder(4096, false)
	dec := NewDecoder(4096)

	// First encode adds to dynamic table.
	headers1 := []HeaderField{
		{Name: "x-custom", Value: "hello"},
	}
	data1 := enc.Encode(headers1)
	_, err := dec.Decode(data1)
	if err != nil {
		t.Fatalf("first Decode() error = %v", err)
	}

	// Second encode should reuse from dynamic table.
	data2 := enc.Encode(headers1)
	decoded2, err := dec.Decode(data2)
	if err != nil {
		t.Fatalf("second Decode() error = %v", err)
	}
	if len(decoded2) != 1 || decoded2[0].Name != "x-custom" || decoded2[0].Value != "hello" {
		t.Errorf("second round-trip failed: %+v", decoded2)
	}

	// Second encoding should be smaller (indexed reference).
	if len(data2) >= len(data1) {
		t.Errorf("second encoding (%d bytes) should be smaller than first (%d bytes)", len(data2), len(data1))
	}
}

func TestEncoder_SensitiveField(t *testing.T) {
	enc := NewEncoder(4096, false)
	dec := NewDecoder(4096)

	headers := []HeaderField{
		{Name: "authorization", Value: "Bearer secret", Sensitive: true},
	}
	data := enc.Encode(headers)
	decoded, err := dec.Decode(data)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("got %d headers, want 1", len(decoded))
	}
	if !decoded[0].Sensitive {
		t.Error("sensitive field should be decoded with Sensitive=true")
	}
	// Should NOT be in encoder's dynamic table.
	if enc.DynamicTable().Len() != 0 {
		t.Errorf("sensitive field should not be added to encoder dynamic table, got len=%d", enc.DynamicTable().Len())
	}
}

func TestEncoder_HuffmanEncoding(t *testing.T) {
	encHuff := NewEncoder(4096, true)
	encPlain := NewEncoder(4096, false)
	dec := NewDecoder(4096)

	headers := []HeaderField{
		{Name: "x-example", Value: "this is a longer value for Huffman efficiency"},
	}
	dataHuff := encHuff.Encode(headers)
	dataPlain := encPlain.Encode(headers)

	// Huffman should generally be shorter.
	if len(dataHuff) >= len(dataPlain) {
		t.Logf("huffman=%d, plain=%d (Huffman not shorter for this input)", len(dataHuff), len(dataPlain))
	}

	// Both should decode correctly.
	decoded, err := dec.Decode(dataHuff)
	if err != nil {
		t.Fatalf("Decode(huffman) error = %v", err)
	}
	if len(decoded) != 1 || decoded[0].Name != "x-example" {
		t.Errorf("huffman round-trip failed: %+v", decoded)
	}
}

func TestEncoder_TableSizeUpdate(t *testing.T) {
	enc := NewEncoder(4096, false)
	dec := NewDecoder(4096)

	// Add an entry to dynamic table.
	headers := []HeaderField{{Name: "x-foo", Value: "bar"}}
	data := enc.Encode(headers)
	_, _ = dec.Decode(data)

	// Reduce table size.
	enc.SetMaxTableSize(0)
	dec.SetMaxTableSize(0)

	// Next encode should emit table size update.
	data2 := enc.Encode([]HeaderField{{Name: ":method", Value: "GET"}})
	decoded, err := dec.Decode(data2)
	if err != nil {
		t.Fatalf("Decode() after size change error = %v", err)
	}
	if len(decoded) != 1 || decoded[0].Name != ":method" {
		t.Errorf("decoded = %+v", decoded)
	}
	if dec.DynamicTable().MaxSize() != 0 {
		t.Errorf("decoder dynamic table max size = %d, want 0", dec.DynamicTable().MaxSize())
	}
}

// --- RFC 7541 Appendix C Test Vectors ---

// C.2.1: Literal Header Field with Indexing
func TestDecoder_RFC_C2_1(t *testing.T) {
	data := mustDecodeHex("400a637573746f6d2d6b65790d637573746f6d2d686561646572")
	dec := NewDecoder(4096)
	headers, err := dec.Decode(data)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(headers) != 1 {
		t.Fatalf("got %d headers, want 1", len(headers))
	}
	assertHeader(t, headers[0], "custom-key", "custom-header")
	if dec.DynamicTable().Len() != 1 {
		t.Errorf("dynamic table len = %d, want 1", dec.DynamicTable().Len())
	}
}

// C.2.2: Literal Header Field without Indexing
func TestDecoder_RFC_C2_2(t *testing.T) {
	data := mustDecodeHex("040c2f73616d706c652f70617468")
	dec := NewDecoder(4096)
	headers, err := dec.Decode(data)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(headers) != 1 {
		t.Fatalf("got %d headers, want 1", len(headers))
	}
	assertHeader(t, headers[0], ":path", "/sample/path")
	if dec.DynamicTable().Len() != 0 {
		t.Errorf("dynamic table len = %d, want 0", dec.DynamicTable().Len())
	}
}

// C.2.3: Literal Header Field Never Indexed
func TestDecoder_RFC_C2_3(t *testing.T) {
	data := mustDecodeHex("100870617373776f726406736563726574")
	dec := NewDecoder(4096)
	headers, err := dec.Decode(data)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(headers) != 1 {
		t.Fatalf("got %d headers, want 1", len(headers))
	}
	assertHeader(t, headers[0], "password", "secret")
	if !headers[0].Sensitive {
		t.Error("expected Sensitive=true")
	}
}

// C.2.4: Indexed Header Field
func TestDecoder_RFC_C2_4(t *testing.T) {
	data := mustDecodeHex("82")
	dec := NewDecoder(4096)
	headers, err := dec.Decode(data)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(headers) != 1 {
		t.Fatalf("got %d headers, want 1", len(headers))
	}
	assertHeader(t, headers[0], ":method", "GET")
}

// C.3: Request Examples without Huffman Coding
func TestDecoder_RFC_C3(t *testing.T) {
	dec := NewDecoder(4096)

	// C.3.1: First Request
	data1 := mustDecodeHex("828684410f7777772e6578616d706c652e636f6d")
	headers1, err := dec.Decode(data1)
	if err != nil {
		t.Fatalf("C.3.1 Decode() error = %v", err)
	}
	assertHeaders(t, "C.3.1", headers1, []HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "http"},
		{Name: ":path", Value: "/"},
		{Name: ":authority", Value: "www.example.com"},
	})

	// C.3.2: Second Request
	data2 := mustDecodeHex("828684be58086e6f2d6361636865")
	headers2, err := dec.Decode(data2)
	if err != nil {
		t.Fatalf("C.3.2 Decode() error = %v", err)
	}
	assertHeaders(t, "C.3.2", headers2, []HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "http"},
		{Name: ":path", Value: "/"},
		{Name: ":authority", Value: "www.example.com"},
		{Name: "cache-control", Value: "no-cache"},
	})

	// C.3.3: Third Request
	data3 := mustDecodeHex("828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565")
	headers3, err := dec.Decode(data3)
	if err != nil {
		t.Fatalf("C.3.3 Decode() error = %v", err)
	}
	assertHeaders(t, "C.3.3", headers3, []HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/index.html"},
		{Name: ":authority", Value: "www.example.com"},
		{Name: "custom-key", Value: "custom-value"},
	})
}

// C.4: Request Examples with Huffman Coding
func TestDecoder_RFC_C4(t *testing.T) {
	dec := NewDecoder(4096)

	// C.4.1: First Request
	data1 := mustDecodeHex("828684418cf1e3c2e5f23a6ba0ab90f4ff")
	headers1, err := dec.Decode(data1)
	if err != nil {
		t.Fatalf("C.4.1 Decode() error = %v", err)
	}
	assertHeaders(t, "C.4.1", headers1, []HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "http"},
		{Name: ":path", Value: "/"},
		{Name: ":authority", Value: "www.example.com"},
	})

	// C.4.2: Second Request
	data2 := mustDecodeHex("828684be5886a8eb10649cbf")
	headers2, err := dec.Decode(data2)
	if err != nil {
		t.Fatalf("C.4.2 Decode() error = %v", err)
	}
	assertHeaders(t, "C.4.2", headers2, []HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "http"},
		{Name: ":path", Value: "/"},
		{Name: ":authority", Value: "www.example.com"},
		{Name: "cache-control", Value: "no-cache"},
	})

	// C.4.3: Third Request
	data3 := mustDecodeHex("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf")
	headers3, err := dec.Decode(data3)
	if err != nil {
		t.Fatalf("C.4.3 Decode() error = %v", err)
	}
	assertHeaders(t, "C.4.3", headers3, []HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/index.html"},
		{Name: ":authority", Value: "www.example.com"},
		{Name: "custom-key", Value: "custom-value"},
	})
}

// C.5: Response Examples without Huffman Coding
func TestDecoder_RFC_C5(t *testing.T) {
	dec := NewDecoder(256)

	// C.5.1: First Response
	data1 := mustDecodeHex(
		"4803333032580770726976617465611d" +
			"4d6f6e2c203231204f637420323031" +
			"332032303a31333a323120474d54" +
			"6e1768747470733a2f2f7777772e65" +
			"78616d706c652e636f6d")
	headers1, err := dec.Decode(data1)
	if err != nil {
		t.Fatalf("C.5.1 Decode() error = %v", err)
	}
	assertHeaders(t, "C.5.1", headers1, []HeaderField{
		{Name: ":status", Value: "302"},
		{Name: "cache-control", Value: "private"},
		{Name: "date", Value: "Mon, 21 Oct 2013 20:13:21 GMT"},
		{Name: "location", Value: "https://www.example.com"},
	})

	// C.5.2: Second Response
	data2 := mustDecodeHex("4803333037c1c0bf")
	headers2, err := dec.Decode(data2)
	if err != nil {
		t.Fatalf("C.5.2 Decode() error = %v", err)
	}
	assertHeaders(t, "C.5.2", headers2, []HeaderField{
		{Name: ":status", Value: "307"},
		{Name: "cache-control", Value: "private"},
		{Name: "date", Value: "Mon, 21 Oct 2013 20:13:21 GMT"},
		{Name: "location", Value: "https://www.example.com"},
	})

	// C.5.3: Third Response
	data3 := mustDecodeHex(
		"88c1611d4d6f6e2c203231204f6374" +
			"20323031332032303a31333a323220" +
			"474d54c05a04677a69707738666f6f" +
			"3d4153444a4b48514b425a584f5157" +
			"454f50495541585157454f49553b20" +
			"6d61782d6167653d333630303b2076" +
			"657273696f6e3d31")
	headers3, err := dec.Decode(data3)
	if err != nil {
		t.Fatalf("C.5.3 Decode() error = %v", err)
	}
	assertHeaders(t, "C.5.3", headers3, []HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "cache-control", Value: "private"},
		{Name: "date", Value: "Mon, 21 Oct 2013 20:13:22 GMT"},
		{Name: "location", Value: "https://www.example.com"},
		{Name: "content-encoding", Value: "gzip"},
		{Name: "set-cookie", Value: "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"},
	})
}

// C.6: Response Examples with Huffman Coding
func TestDecoder_RFC_C6(t *testing.T) {
	dec := NewDecoder(256)

	// C.6.1: First Response
	data1 := mustDecodeHex(
		"488264025885aec3771a4b6196d07abe" +
			"941054d444a8200595040b8166e082a6" +
			"2d1bff6e919d29ad171863c78f0b97c8" +
			"e9ae82ae43d3")
	headers1, err := dec.Decode(data1)
	if err != nil {
		t.Fatalf("C.6.1 Decode() error = %v", err)
	}
	assertHeaders(t, "C.6.1", headers1, []HeaderField{
		{Name: ":status", Value: "302"},
		{Name: "cache-control", Value: "private"},
		{Name: "date", Value: "Mon, 21 Oct 2013 20:13:21 GMT"},
		{Name: "location", Value: "https://www.example.com"},
	})

	// C.6.2: Second Response
	data2 := mustDecodeHex("4883640effc1c0bf")
	headers2, err := dec.Decode(data2)
	if err != nil {
		t.Fatalf("C.6.2 Decode() error = %v", err)
	}
	assertHeaders(t, "C.6.2", headers2, []HeaderField{
		{Name: ":status", Value: "307"},
		{Name: "cache-control", Value: "private"},
		{Name: "date", Value: "Mon, 21 Oct 2013 20:13:21 GMT"},
		{Name: "location", Value: "https://www.example.com"},
	})

	// C.6.3: Third Response
	data3 := mustDecodeHex(
		"88c16196d07abe941054d444a8200595" +
			"040b8166e084a62d1bffc05a839bd9ab" +
			"77ad94e7821dd7f2e6c7b335dfdfcd5b" +
			"3960d5af27087f3672c1ab270fb5291f" +
			"9587316065c003ed4ee5b1063d5007")
	headers3, err := dec.Decode(data3)
	if err != nil {
		t.Fatalf("C.6.3 Decode() error = %v", err)
	}
	assertHeaders(t, "C.6.3", headers3, []HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "cache-control", Value: "private"},
		{Name: "date", Value: "Mon, 21 Oct 2013 20:13:22 GMT"},
		{Name: "location", Value: "https://www.example.com"},
		{Name: "content-encoding", Value: "gzip"},
		{Name: "set-cookie", Value: "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"},
	})
}

// --- Encoder-Decoder Round-Trip Tests ---

func TestRoundTrip_MultipleHeaders(t *testing.T) {
	enc := NewEncoder(4096, true)
	dec := NewDecoder(4096)

	headers := []HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":path", Value: "/api/v1/users"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "api.example.com"},
		{Name: "content-type", Value: "application/json"},
		{Name: "authorization", Value: "Bearer token123", Sensitive: true},
		{Name: "x-request-id", Value: "abc-123-def-456"},
	}

	data := enc.Encode(headers)
	decoded, err := dec.Decode(data)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	assertHeaders(t, "round-trip", decoded, headers)
}

func TestRoundTrip_MultipleBlocks(t *testing.T) {
	enc := NewEncoder(4096, false)
	dec := NewDecoder(4096)

	blocks := [][]HeaderField{
		{
			{Name: ":method", Value: "GET"},
			{Name: ":path", Value: "/"},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: "example.com"},
		},
		{
			{Name: ":method", Value: "GET"},
			{Name: ":path", Value: "/style.css"},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: "example.com"},
		},
		{
			{Name: ":method", Value: "GET"},
			{Name: ":path", Value: "/script.js"},
			{Name: ":scheme", Value: "https"},
			{Name: ":authority", Value: "example.com"},
			{Name: "accept-encoding", Value: "gzip, deflate"},
		},
	}

	for i, headers := range blocks {
		data := enc.Encode(headers)
		decoded, err := dec.Decode(data)
		if err != nil {
			t.Fatalf("block %d: Decode() error = %v", i, err)
		}
		assertHeaders(t, "block", decoded, headers)
	}
}

func TestRoundTrip_EmptyHeaders(t *testing.T) {
	enc := NewEncoder(4096, false)
	dec := NewDecoder(4096)

	data := enc.Encode(nil)
	decoded, err := dec.Decode(data)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(decoded) != 0 {
		t.Errorf("got %d headers, want 0", len(decoded))
	}
}

func TestRoundTrip_EmptyNameValue(t *testing.T) {
	enc := NewEncoder(4096, false)
	dec := NewDecoder(4096)

	headers := []HeaderField{
		{Name: "x-empty", Value: ""},
	}
	data := enc.Encode(headers)
	decoded, err := dec.Decode(data)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	assertHeaders(t, "empty-value", decoded, headers)
}

// --- Resource Limit Tests ---

func TestDecoder_HeaderListSizeLimit(t *testing.T) {
	dec := NewDecoder(4096)
	dec.SetMaxHeaderListSize(100) // very small limit

	// Build a header block with multiple fields that exceed 100 bytes total.
	enc := NewEncoder(4096, false)
	headers := []HeaderField{
		{Name: "x-header-1", Value: "value-1"}, // size = 10+7+32 = 49
		{Name: "x-header-2", Value: "value-2"}, // size = 10+7+32 = 49; total = 98
		{Name: "x-header-3", Value: "value-3"}, // size = 10+7+32 = 49; total = 147 > 100
	}
	data := enc.Encode(headers)
	_, err := dec.Decode(data)
	if err == nil {
		t.Error("expected error for header list size exceeding limit")
	}
	if !errors.Is(err, ErrHeaderListTooLarge) {
		t.Errorf("expected ErrHeaderListTooLarge, got: %v", err)
	}
}

func TestDecoder_StringLengthLimit(t *testing.T) {
	dec := NewDecoder(4096)
	dec.SetMaxStringLength(10) // very small limit

	// Build a literal header with a value longer than 10 bytes.
	var data []byte
	data = append(data, 0x40) // literal with incremental indexing, new name
	data = encodeInteger(data, 0x00, 7, 3)
	data = append(data, "foo"...)
	data = encodeInteger(data, 0x00, 7, 20) // value length = 20 > limit of 10
	data = append(data, "01234567890123456789"...)

	_, err := dec.Decode(data)
	if err == nil {
		t.Error("expected error for string length exceeding limit")
	}
	if !errors.Is(err, ErrStringTooLong) {
		t.Errorf("expected ErrStringTooLong, got: %v", err)
	}
}

func TestHuffman_InvalidPadding(t *testing.T) {
	// Valid Huffman encoding of "a" is 0x03 (5 bits: 00011) padded with
	// 3 bits of 1s = 0001 1111 = 0x1f. If we change padding to 0s,
	// it should be rejected.
	validEncoded := huffmanEncode(nil, []byte("a"))
	// Verify valid encoding works.
	_, err := huffmanDecode(nil, validEncoded)
	if err != nil {
		t.Fatalf("valid encoding failed: %v", err)
	}

	// Create invalid padding: "a" (00011) + 000 instead of 111
	invalidPadding := []byte{0x18} // 00011 000 — padding bits are 0s, not 1s
	_, err = huffmanDecode(nil, invalidPadding)
	if err == nil {
		t.Error("expected error for non-EOS padding bits")
	}
}

// --- Helpers ---

func mustDecodeHex(s string) []byte {
	s = strings.ReplaceAll(s, " ", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid hex: " + err.Error())
	}
	return b
}

func assertHeader(t *testing.T, got HeaderField, wantName, wantValue string) {
	t.Helper()
	if got.Name != wantName || got.Value != wantValue {
		t.Errorf("header = {%q, %q}, want {%q, %q}", got.Name, got.Value, wantName, wantValue)
	}
}

func assertHeaders(t *testing.T, label string, got, want []HeaderField) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %d headers, want %d", label, len(got), len(want))
	}
	for i := range want {
		if got[i].Name != want[i].Name || got[i].Value != want[i].Value {
			t.Errorf("%s[%d]: got {%q, %q}, want {%q, %q}",
				label, i, got[i].Name, got[i].Value, want[i].Name, want[i].Value)
		}
		if want[i].Sensitive && !got[i].Sensitive {
			t.Errorf("%s[%d]: expected Sensitive=true", label, i)
		}
	}
}
