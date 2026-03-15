package protobuf

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func hexToBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex %q: %v", s, err)
	}
	return b
}

// TestDecode_Varint150 mirrors PacketProxy's testVarint150.
func TestDecode_Varint150(t *testing.T) {
	data := hexToBytes(t, "089601")
	jsonStr, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	// Verify round-trip
	result, err := Encode(jsonStr)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	assertBytesEqual(t, data, result)
}

// TestDecode_String mirrors PacketProxy's testString.
func TestDecode_String(t *testing.T) {
	data := hexToBytes(t, "120774657374696e67")
	jsonStr, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	// Should contain "testing"
	if !strings.Contains(jsonStr, "testing") {
		t.Errorf("expected JSON to contain 'testing', got: %s", jsonStr)
	}
	result, err := Encode(jsonStr)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	assertBytesEqual(t, data, result)
}

// TestDecode_64Bit mirrors PacketProxy's testLong.
func TestDecode_64Bit(t *testing.T) {
	data := hexToBytes(t, "090102030405060708")
	jsonStr, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	result, err := Encode(jsonStr)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	assertBytesEqual(t, data, result)
}

// TestDecode_VarintNegative mirrors PacketProxy's testVarintMinus.
func TestDecode_VarintNegative(t *testing.T) {
	data := hexToBytes(t, "08feffffffffffffffff01107b18ffffffffffffffffff01207b")
	jsonStr, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	result, err := Encode(jsonStr)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	assertBytesEqual(t, data, result)
}

// TestDecode_Complex mirrors PacketProxy's testComplex.
func TestDecode_Complex(t *testing.T) {
	data := hexToBytes(t, "0a410a09e3828fe3819fe3819710d20922105a643bdf4f8df33f2db29defa7c609402a1208011207303830303030301a050dbab126442a0b080112073038303030303015c3f54840")
	jsonStr, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	result, err := Encode(jsonStr)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	assertBytesEqual(t, data, result)
}

// TestDecode_ComplexUnordered mirrors PacketProxy's testComplexUnordered.
func TestDecode_ComplexUnordered(t *testing.T) {
	data := hexToBytes(t, "15c3f548400a410a09e3828fe3819fe3819710d20922105a643bdf4f8df33f2db29defa7c609402a1208011207303830303030301a050dbab126442a0b0801120730383030303030")
	jsonStr, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	result, err := Encode(jsonStr)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	assertBytesEqual(t, data, result)
}

// TestDecode_ManyFields mirrors PacketProxy's testManyField.
func TestDecode_ManyFields(t *testing.T) {
	data := hexToBytes(t, "08011002180320042805600c380740084809500a580b3006")
	jsonStr, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	result, err := Encode(jsonStr)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	assertBytesEqual(t, data, result)
}

// TestDecode_Bytes mirrors PacketProxy's testEncodeDecodeBytes2.
func TestDecode_Bytes(t *testing.T) {
	testCases := []string{
		"220100", "220101", "220102", "220103",
		"220104", "220105", "220106", "220107", "220108",
	}
	for _, tc := range testCases {
		t.Run(tc, func(t *testing.T) {
			data := hexToBytes(t, tc)
			jsonStr, err := Decode(data)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			result, err := Encode(jsonStr)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			assertBytesEqual(t, data, result)
		})
	}
}

// TestDecode_EmptyInput tests decoding empty input.
func TestDecode_EmptyInput(t *testing.T) {
	jsonStr, err := Decode([]byte{})
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	// Should produce empty object
	if !strings.Contains(jsonStr, "{}") {
		t.Errorf("expected empty object, got: %s", jsonStr)
	}
}

// TestDecode_InvalidWireType tests that unsupported wire types return an error.
func TestDecode_InvalidWireType(t *testing.T) {
	// Wire type 3 (StartGroup) - deprecated and unsupported
	data := hexToBytes(t, "0b") // field 1, wire type 3
	_, err := Decode(data)
	if err == nil {
		t.Error("expected error for unsupported wire type")
	}
}

// TestDecode_TruncatedVarint tests truncated varint input.
func TestDecode_TruncatedVarint(t *testing.T) {
	// Varint with continuation bit set but no more data
	data := hexToBytes(t, "0880")
	_, err := Decode(data)
	if err == nil {
		t.Error("expected error for truncated varint")
	}
}

// TestDecode_LengthExceedsData tests length-delimited field with insufficient data.
func TestDecode_LengthExceedsData(t *testing.T) {
	// Field 2, length-delimited, length=10, but only 3 bytes of data
	data := hexToBytes(t, "120a414243")
	_, err := Decode(data)
	if err == nil {
		t.Error("expected error for length exceeding data")
	}
}

// TestDecode_32Bit tests 32-bit fixed-width field.
func TestDecode_32Bit(t *testing.T) {
	data := hexToBytes(t, "0d01020304")
	jsonStr, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	result, err := Encode(jsonStr)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	assertBytesEqual(t, data, result)
}

// TestIsPrintableUTF8 tests the printable UTF-8 validation function.
func TestIsPrintableUTF8(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"empty", []byte{}, false},
		{"ascii", []byte("hello world"), true},
		{"with newlines", []byte("hello\r\nworld"), true},
		{"control char", []byte{0x01}, false},
		{"null byte", []byte{0x00}, false},
		{"del", []byte{0x7F}, false},
		{"tab", []byte{0x09}, false},
		{"utf8 japanese", []byte("テスト"), true},
		{"invalid utf8", []byte{0xff, 0xfe}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPrintableUTF8(tt.data)
			if got != tt.want {
				t.Errorf("isPrintableUTF8(%q) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

// TestHexColon_RoundTrip tests hex colon encoding/decoding round-trip.
func TestHexColon_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		hex  string
	}{
		{"single byte", []byte{0x01}, "01"},
		{"multiple bytes", []byte{0x01, 0x02, 0x03, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12}, "01:02:03:0a:0b:0c:0d:0e:0f:10:11:12"},
		{"empty", []byte{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := encodeHexColon(tt.data)
			if encoded != tt.hex {
				t.Errorf("encodeHexColon = %q, want %q", encoded, tt.hex)
			}
			decoded, err := decodeHexColon(encoded)
			if err != nil {
				t.Fatalf("decodeHexColon: %v", err)
			}
			assertBytesEqual(t, tt.data, decoded)
		})
	}
}

// TestDecodeHexColon_PacketProxy mirrors PacketProxy's testEncodeDecodeBytes.
func TestDecodeHexColon_PacketProxy(t *testing.T) {
	data := hexToBytes(t, "0102030405060708090a0b0c0d0e0f101112")
	encoded := encodeHexColon(data)
	decoded, err := decodeHexColon(encoded)
	if err != nil {
		t.Fatalf("decodeHexColon: %v", err)
	}
	assertBytesEqual(t, data, decoded)
}

// TestValidateRepeatedStrictly tests packed repeated varint validation.
func TestValidateRepeatedStrictly(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"empty", []byte{}, false},
		{"single varint", []byte{0x01}, true},
		{"two varints", []byte{0x01, 0x02}, true},
		{"multi-byte varint", []byte{0x96, 0x01}, true},
		{"invalid trailing zero", []byte{0x80, 0x00}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateRepeatedStrictly(tt.data)
			if got != tt.want {
				t.Errorf("validateRepeatedStrictly(%x) = %v, want %v", tt.data, got, tt.want)
			}
		})
	}
}

// TestDecode_JSONStructure verifies the JSON key format.
func TestDecode_JSONStructure(t *testing.T) {
	// Simple varint: field 1 = 150
	data := hexToBytes(t, "089601")
	jsonStr, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// Key should be "0001:0000:Varint"
	val, ok := m["0001:0000:Varint"]
	if !ok {
		t.Fatalf("expected key '0001:0000:Varint' in %v", m)
	}
	// Value should be 150
	if v, ok := val.(float64); !ok || v != 150 {
		t.Errorf("expected value 150, got %v", val)
	}
}

func assertBytesEqual(t *testing.T, expected, actual []byte) {
	t.Helper()
	if len(expected) != len(actual) {
		t.Fatalf("byte length mismatch: expected %d, got %d\nexpected: %x\nactual:   %x", len(expected), len(actual), expected, actual)
	}
	for i := range expected {
		if expected[i] != actual[i] {
			t.Fatalf("byte mismatch at index %d: expected %02x, got %02x\nexpected: %x\nactual:   %x", i, expected[i], actual[i], expected, actual)
		}
	}
}
