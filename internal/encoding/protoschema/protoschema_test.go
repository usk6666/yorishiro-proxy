package protoschema

import (
	_ "embed"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

// test.desc is generated from testdata/test.proto via
//
//	protoc --include_imports --descriptor_set_out=test.desc test.proto
//
// We embed the compiled bytes so protoc is not required at test runtime.
//
//go:embed testdata/test.desc
var testDescBytes []byte

// with_imports_missing.desc is generated WITHOUT --include_imports so
// it intentionally trips the missing-dependency error path.
//
//go:embed testdata/with_imports_missing.desc
var withImportsMissingBytes []byte

// loadTestRegistry returns a Registry populated with the test.desc
// services and returns the input/output descriptors for SayHello as a
// convenience to most tests.
func loadTestRegistry(t *testing.T) (*Registry, protoreflect.MessageDescriptor, protoreflect.MessageDescriptor) {
	t.Helper()
	r := NewRegistry()
	specs, err := LoadFileDescriptorSet(testDescBytes, nil)
	if err != nil {
		t.Fatalf("LoadFileDescriptorSet: %v", err)
	}
	r.Register(specs)
	m := r.LookupMethod("usk.test.Greeter", "SayHello")
	if m == nil {
		t.Fatal("SayHello not registered")
	}
	return r, m.InputDesc, m.OutputDesc
}

// buildHelloRequestBytes builds a HelloRequest proto wire payload from
// field values using a fresh DynamicMessage. This avoids hand-encoding
// wire bytes in tests.
func buildHelloRequestBytes(t *testing.T, desc protoreflect.MessageDescriptor, fString string, fInt32 int32, fRepeated []string) []byte {
	t.Helper()
	msg := dynamicpb.NewMessage(desc)
	if fString != "" {
		fd := desc.Fields().ByName("f_string")
		msg.Set(fd, protoreflect.ValueOfString(fString))
	}
	if fInt32 != 0 {
		fd := desc.Fields().ByName("f_int32")
		msg.Set(fd, protoreflect.ValueOfInt32(fInt32))
	}
	if len(fRepeated) > 0 {
		fd := desc.Fields().ByName("f_repeated")
		list := msg.Mutable(fd).List()
		for _, v := range fRepeated {
			list.Append(protoreflect.ValueOfString(v))
		}
	}
	wire, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	return wire
}

func TestDecode_Happy(t *testing.T) {
	t.Parallel()
	_, in, _ := loadTestRegistry(t)
	wire := buildHelloRequestBytes(t, in, "hi", 42, []string{"a", "b"})

	got, err := Decode(wire, in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.Contains(got, `"f_string"`) {
		t.Errorf("Decode output missing f_string: %s", got)
	}
	if !strings.Contains(got, `"hi"`) {
		t.Errorf("Decode output missing value 'hi': %s", got)
	}
	if !strings.Contains(got, `"f_int32"`) || !strings.Contains(got, "42") {
		t.Errorf("Decode output missing f_int32=42: %s", got)
	}
	if !strings.Contains(got, `"f_repeated"`) {
		t.Errorf("Decode output missing f_repeated: %s", got)
	}
}

func TestDecode_Empty(t *testing.T) {
	t.Parallel()
	_, in, _ := loadTestRegistry(t)
	got, err := Decode(nil, in)
	if err != nil {
		t.Fatalf("Decode empty: %v", err)
	}
	// Empty input parses to an empty message; with EmitUnpopulated=false
	// protojson emits "{}".
	if strings.TrimSpace(got) != "{}" {
		t.Errorf("Decode empty = %q, want {}", got)
	}
}

func TestDecode_NilDescriptor(t *testing.T) {
	t.Parallel()
	if _, err := Decode([]byte{0x0a, 0x00}, nil); err == nil {
		t.Error("expected error for nil descriptor")
	}
}

func TestDecode_MalformedWireBytes(t *testing.T) {
	t.Parallel()
	_, in, _ := loadTestRegistry(t)
	// Trailing varint byte with continuation bit set but no follow-up:
	// proto.Unmarshal rejects this as malformed.
	bad := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	_, err := Decode(bad, in)
	if err == nil {
		t.Error("expected error for malformed wire bytes")
	}
}

func TestDecode_UnknownFields_AreCaptured(t *testing.T) {
	t.Parallel()
	_, in, _ := loadTestRegistry(t)
	// Add a wire field number 99 that is not in HelloRequest. The
	// DynamicMessage parses it into UnknownFields().
	known := buildHelloRequestBytes(t, in, "hi", 0, nil)
	// Tag for field 99, wire type 0 (varint), value 0x01.
	extra := []byte{0x98, 0x06, 0x01}
	wire := append([]byte(nil), known...)
	wire = append(wire, extra...)

	got, err := Decode(wire, in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.Contains(got, `"hi"`) {
		t.Errorf("Decode dropped known field: %s", got)
	}
	if !HasUnknownFields(wire, in) {
		t.Error("HasUnknownFields = false; want true for extra field 99")
	}
}

func TestEncode_Happy(t *testing.T) {
	t.Parallel()
	_, in, _ := loadTestRegistry(t)
	jsonStr := `{"f_string":"hi","f_int32":42}`

	wire, err := Encode(jsonStr, in)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Round-trip: decode and check fields.
	msg := dynamicpb.NewMessage(in)
	if err := proto.Unmarshal(wire, msg); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	got := msg.Get(in.Fields().ByName("f_string")).String()
	if got != "hi" {
		t.Errorf("f_string = %q, want hi", got)
	}
	if i := msg.Get(in.Fields().ByName("f_int32")).Int(); i != 42 {
		t.Errorf("f_int32 = %d, want 42", i)
	}
}

func TestEncode_DiscardUnknownJSONKeys(t *testing.T) {
	t.Parallel()
	_, in, _ := loadTestRegistry(t)
	// "f_typo" is not a field name; DiscardUnknown=true silently ignores it.
	jsonStr := `{"f_string":"hi","f_typo":"value"}`
	wire, err := Encode(jsonStr, in)
	if err != nil {
		t.Fatalf("Encode with unknown JSON key: %v", err)
	}
	msg := dynamicpb.NewMessage(in)
	if err := proto.Unmarshal(wire, msg); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	if got := msg.Get(in.Fields().ByName("f_string")).String(); got != "hi" {
		t.Errorf("f_string = %q", got)
	}
}

func TestEncode_TypeMismatchHardError(t *testing.T) {
	t.Parallel()
	_, in, _ := loadTestRegistry(t)
	// String for int32 — protojson rejects with a type mismatch.
	_, err := Encode(`{"f_int32":"not-a-number"}`, in)
	if err == nil {
		t.Error("expected error for type mismatch")
	}
}

func TestEncode_NilDescriptor(t *testing.T) {
	t.Parallel()
	if _, err := Encode(`{}`, nil); err == nil {
		t.Error("expected error for nil descriptor")
	}
}

func TestEncode_MalformedJSON(t *testing.T) {
	t.Parallel()
	_, in, _ := loadTestRegistry(t)
	if _, err := Encode(`{not json}`, in); err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestRoundtrip_DecodeEncode(t *testing.T) {
	t.Parallel()
	_, in, _ := loadTestRegistry(t)
	original := buildHelloRequestBytes(t, in, "round", 7, []string{"x"})

	js, err := Decode(original, in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	re, err := Encode(js, in)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Round-trip the freshly-encoded bytes; structural equality is checked
	// via decoded fields rather than byte equality (proto.Marshal is not
	// guaranteed to produce deterministic byte output across runs).
	msg := dynamicpb.NewMessage(in)
	if err := proto.Unmarshal(re, msg); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	if got := msg.Get(in.Fields().ByName("f_string")).String(); got != "round" {
		t.Errorf("round-trip f_string = %q, want round", got)
	}
}
