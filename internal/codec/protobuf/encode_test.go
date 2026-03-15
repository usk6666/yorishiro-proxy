package protobuf

import (
	"encoding/json"
	"testing"
)

// TestEncode_InvalidJSON tests encoding with invalid JSON input.
func TestEncode_InvalidJSON(t *testing.T) {
	_, err := Encode("not json")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

// TestEncode_UnknownType tests encoding with an unknown type in key.
func TestEncode_UnknownType(t *testing.T) {
	_, err := Encode(`{"0001:0000:unknown": 42}`)
	if err == nil {
		t.Error("expected error for unknown type")
	}
}

// TestEncode_InvalidKeyFormat tests encoding with malformed key.
func TestEncode_InvalidKeyFormat(t *testing.T) {
	_, err := Encode(`{"badkey": 42}`)
	if err == nil {
		t.Error("expected error for invalid key format")
	}
}

// TestEncode_InvalidHexField tests encoding with invalid hex field number.
func TestEncode_InvalidHexField(t *testing.T) {
	_, err := Encode(`{"gggg:0000:Varint": 42}`)
	if err == nil {
		t.Error("expected error for invalid hex field number")
	}
}

// TestEncode_EmptyObject tests encoding an empty JSON object.
func TestEncode_EmptyObject(t *testing.T) {
	result, err := Encode("{}")
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty bytes, got %x", result)
	}
}

// TestEncode_StringField tests encoding a string field.
func TestEncode_StringField(t *testing.T) {
	jsonStr := `{"0002:0000:String": "testing"}`
	result, err := Encode(jsonStr)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	expected := hexToBytes(t, "120774657374696e67")
	assertBytesEqual(t, expected, result)
}

// TestEncode_BytesField tests encoding a bytes field.
func TestEncode_BytesField(t *testing.T) {
	jsonStr := `{"0004:0000:bytes": "de:ad:be:ef"}`
	result, err := Encode(jsonStr)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Verify round-trip
	decoded, err := Decode(result)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(decoded), &m); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	val, ok := m["0004:0000:bytes"]
	if !ok {
		t.Fatal("expected bytes field in decoded output")
	}
	if val != "de:ad:be:ef" {
		t.Errorf("expected 'de:ad:be:ef', got %v", val)
	}
}

// TestEncode_RepeatedField tests encoding a packed repeated varint field.
func TestEncode_RepeatedField(t *testing.T) {
	jsonStr := `{"0001:0000:repeated": [1, 2, 3]}`
	result, err := Encode(jsonStr)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Round-trip
	decoded, err := Decode(result)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	result2, err := Encode(decoded)
	if err != nil {
		t.Fatalf("Encode round-trip: %v", err)
	}
	assertBytesEqual(t, result, result2)
}

// TestEncode_EmbeddedMessage tests encoding a nested message.
func TestEncode_EmbeddedMessage(t *testing.T) {
	jsonStr := `{"0001:0000:embedded message": {"0001:0000:Varint": 42}}`
	result, err := Encode(jsonStr)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Round-trip
	decoded, err := Decode(result)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	result2, err := Encode(decoded)
	if err != nil {
		t.Fatalf("Encode round-trip: %v", err)
	}
	assertBytesEqual(t, result, result2)
}

// TestParseJSONNumber_LargeUint64 tests that large uint64 values are parsed precisely.
func TestParseJSONNumber_LargeUint64(t *testing.T) {
	tests := []struct {
		name string
		num  json.Number
		want uint64
	}{
		{"max_uint64", json.Number("18446744073709551615"), 18446744073709551615},
		{"large_uint64", json.Number("18446744073709551614"), 18446744073709551614},
		{"above_int64_max", json.Number("9223372036854775808"), 9223372036854775808},
		{"normal", json.Number("42"), 42},
		{"negative", json.Number("-1"), ^uint64(0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseJSONNumber(tt.num)
			if err != nil {
				t.Fatalf("parseJSONNumber(%q): %v", tt.num, err)
			}
			if got != tt.want {
				t.Errorf("parseJSONNumber(%q) = %d, want %d", tt.num, got, tt.want)
			}
		})
	}
}

// TestParseKeyParts tests key parsing.
func TestParseKeyParts(t *testing.T) {
	tests := []struct {
		key    string
		want   []string
		nilExp bool
	}{
		{"0001:0000:Varint", []string{"0001", "0000", "Varint"}, false},
		{"000a:0003:embedded message", []string{"000a", "0003", "embedded message"}, false},
		{"badkey", nil, true},
		{"only:one", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := parseKeyParts(tt.key)
			if tt.nilExp {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil result")
			}
			for i, want := range tt.want {
				if got[i] != want {
					t.Errorf("part[%d] = %q, want %q", i, got[i], want)
				}
			}
		})
	}
}

// TestEncode_32BitOverflow tests that 32-bit fields reject values exceeding uint32.
func TestEncode_32BitOverflow(t *testing.T) {
	// Value 4294967296 = math.MaxUint32 + 1
	jsonStr := `{"0001:0000:32-bit": 4294967296}`
	_, err := Encode(jsonStr)
	if err == nil {
		t.Error("expected error for 32-bit value exceeding uint32 range")
	}
}

// TestParseJSONNumber_NonInteger tests that non-integer values are rejected.
func TestParseJSONNumber_NonInteger(t *testing.T) {
	_, err := parseJSONNumber(json.Number("1.9"))
	if err == nil {
		t.Error("expected error for non-integer JSON number")
	}
}

// TestParseHex_Overflow tests that overly long hex strings are rejected.
func TestParseHex_Overflow(t *testing.T) {
	// 17 hex digits would overflow uint64
	_, err := parseHex("12345678901234567")
	if err == nil {
		t.Error("expected error for hex string exceeding 16 digits")
	}
}

// TestParseHex_Empty tests that empty hex strings are rejected.
func TestParseHex_Empty(t *testing.T) {
	_, err := parseHex("")
	if err == nil {
		t.Error("expected error for empty hex string")
	}
}

// TestParseHex tests hex parsing.
func TestParseHex(t *testing.T) {
	tests := []struct {
		input string
		want  uint64
		err   bool
	}{
		{"0001", 1, false},
		{"000a", 10, false},
		{"00ff", 255, false},
		{"FFFF", 65535, false},
		{"gggg", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseHex(tt.input)
			if tt.err {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("parseHex(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}
