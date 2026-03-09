package codec

import (
	"errors"
	"testing"
)

func TestAllCodecs_Roundtrip(t *testing.T) {
	tests := []struct {
		name  string
		codec string
		input string
	}{
		{name: "base64 ascii", codec: "base64", input: "hello world"},
		{name: "base64 empty", codec: "base64", input: ""},
		{name: "base64 binary-like", codec: "base64", input: "\x00\x01\x02\xff"},
		{name: "base64url ascii", codec: "base64url", input: "hello world"},
		{name: "base64url with special chars", codec: "base64url", input: "abc+/=def"},
		{name: "url_encode_query spaces", codec: "url_encode_query", input: "hello world"},
		{name: "url_encode_query special", codec: "url_encode_query", input: "key=value&foo=bar"},
		{name: "url_encode_query empty", codec: "url_encode_query", input: ""},
		{name: "url_encode_path spaces", codec: "url_encode_path", input: "hello world"},
		{name: "url_encode_path slashes", codec: "url_encode_path", input: "path/to/file"},
		{name: "url_encode_full special", codec: "url_encode_full", input: "<script>alert(1)</script>"},
		{name: "url_encode_full empty", codec: "url_encode_full", input: ""},
		{name: "double_url_encode basic", codec: "double_url_encode", input: "hello world"},
		{name: "double_url_encode special", codec: "double_url_encode", input: "a=b&c=d"},
		{name: "hex ascii", codec: "hex", input: "abc"},
		{name: "hex empty", codec: "hex", input: ""},
		{name: "html_entity basic", codec: "html_entity", input: "<script>"},
		{name: "html_entity unicode", codec: "html_entity", input: "日本語"},
		{name: "html_entity empty", codec: "html_entity", input: ""},
		{name: "html_escape basic", codec: "html_escape", input: `<script>alert("xss")</script>`},
		{name: "html_escape ampersand", codec: "html_escape", input: "a & b"},
		{name: "html_escape empty", codec: "html_escape", input: ""},
		{name: "unicode_escape ascii", codec: "unicode_escape", input: "hello"},
		{name: "unicode_escape unicode", codec: "unicode_escape", input: "日本語"},
		{name: "unicode_escape empty", codec: "unicode_escape", input: ""},
	}

	r := NewRegistry()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, ok := r.Get(tt.codec)
			if !ok {
				t.Fatalf("codec %q not found", tt.codec)
			}
			encoded, err := c.Encode(tt.input)
			if err != nil {
				t.Fatalf("Encode(%q) error = %v", tt.input, err)
			}
			decoded, err := c.Decode(encoded)
			if err != nil {
				t.Fatalf("Decode(%q) error = %v", encoded, err)
			}
			if decoded != tt.input {
				t.Errorf("roundtrip failed: input=%q, encoded=%q, decoded=%q", tt.input, encoded, decoded)
			}
		})
	}
}

func TestCodecs_EncodeValues(t *testing.T) {
	tests := []struct {
		name    string
		codec   string
		input   string
		want    string
		wantErr bool
	}{
		{name: "base64", codec: "base64", input: "hello", want: "aGVsbG8="},
		{name: "base64url", codec: "base64url", input: "hello", want: "aGVsbG8="},
		{name: "url_encode_query spaces", codec: "url_encode_query", input: "hello world", want: "hello+world"},
		{name: "url_encode_query special", codec: "url_encode_query", input: "key=value&foo=bar", want: "key%3Dvalue%26foo%3Dbar"},
		{name: "url_encode_path spaces", codec: "url_encode_path", input: "hello world", want: "hello%20world"},
		{name: "url_encode_full angle brackets", codec: "url_encode_full", input: "<>", want: "%3C%3E"},
		{name: "url_encode_full alpha passthrough", codec: "url_encode_full", input: "abc", want: "abc"},
		{name: "double_url_encode", codec: "double_url_encode", input: "a b", want: "a%2Bb"},
		{name: "hex", codec: "hex", input: "abc", want: "616263"},
		{name: "html_entity a", codec: "html_entity", input: "a", want: "&#x61;"},
		{name: "html_escape", codec: "html_escape", input: `<script>alert("xss")</script>`, want: "&lt;script&gt;alert(&#34;xss&#34;)&lt;/script&gt;"},
		{name: "unicode_escape", codec: "unicode_escape", input: "A", want: "\\u0041"},
		{name: "lower", codec: "lower", input: "Hello World", want: "hello world"},
		{name: "upper", codec: "upper", input: "Hello World", want: "HELLO WORLD"},
		{name: "md5", codec: "md5", input: "hello", want: "5d41402abc4b2a76b9719d911017c592"},
		{name: "sha256", codec: "sha256", input: "hello", want: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
	}

	r := NewRegistry()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, ok := r.Get(tt.codec)
			if !ok {
				t.Fatalf("codec %q not found", tt.codec)
			}
			got, err := c.Encode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Encode(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIrreversibleCodecs_DecodeError(t *testing.T) {
	irreversible := []string{"md5", "sha256", "lower", "upper"}
	r := NewRegistry()
	for _, name := range irreversible {
		t.Run(name, func(t *testing.T) {
			c, ok := r.Get(name)
			if !ok {
				t.Fatalf("codec %q not found", name)
			}
			_, err := c.Decode("anything")
			if err == nil {
				t.Error("Decode() expected error for irreversible codec")
			}
			if !errors.Is(err, ErrIrreversible) {
				t.Errorf("Decode() error = %v, want ErrIrreversible", err)
			}
		})
	}
}

func TestCodecs_DecodeErrors(t *testing.T) {
	tests := []struct {
		name  string
		codec string
		input string
	}{
		{name: "base64 invalid", codec: "base64", input: "not-valid-base64!!!"},
		{name: "hex invalid", codec: "hex", input: "xyz"},
		{name: "hex odd length", codec: "hex", input: "abc"},
	}

	r := NewRegistry()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, ok := r.Get(tt.codec)
			if !ok {
				t.Fatalf("codec %q not found", tt.codec)
			}
			_, err := c.Decode(tt.input)
			if err == nil {
				t.Errorf("Decode(%q) expected error", tt.input)
			}
		})
	}
}

func TestRegistry_List(t *testing.T) {
	r := NewRegistry()
	names := r.List()
	if len(names) != 14 {
		t.Errorf("List() returned %d codecs, want 14", len(names))
	}
	// Verify sorted order.
	for i := 1; i < len(names); i++ {
		if names[i] < names[i-1] {
			t.Errorf("List() not sorted: %q before %q", names[i-1], names[i])
		}
	}
}

func TestRegistry_Get_NotFound(t *testing.T) {
	r := NewRegistry()
	_, ok := r.Get("nonexistent")
	if ok {
		t.Error("Get(nonexistent) returned true, want false")
	}
}

func TestRegistry_Register(t *testing.T) {
	r := NewRegistry()

	custom := &mockCodec{name: "custom_test"}
	err := r.Register("custom_test", custom)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	c, ok := r.Get("custom_test")
	if !ok {
		t.Fatal("Get(custom_test) returned false after Register")
	}
	if c.Name() != "custom_test" {
		t.Errorf("Name() = %q, want %q", c.Name(), "custom_test")
	}
}

func TestRegistry_Register_Duplicate(t *testing.T) {
	r := NewRegistry()

	// Registering a name that conflicts with a builtin should fail.
	err := r.Register("base64", &mockCodec{name: "base64"})
	if err == nil {
		t.Error("Register(base64) expected error for duplicate name")
	}
}

func TestRegistry_Encode_Chain(t *testing.T) {
	r := NewRegistry()

	result, err := r.Encode("hello world", []string{"url_encode_query", "base64"})
	if err != nil {
		t.Fatalf("Encode chain error = %v", err)
	}
	want := "aGVsbG8rd29ybGQ="
	if result != want {
		t.Errorf("Encode chain = %q, want %q", result, want)
	}
}

func TestRegistry_Decode_Chain(t *testing.T) {
	r := NewRegistry()

	// Decode reverses the chain: first base64 decode, then url decode.
	result, err := r.Decode("aGVsbG8rd29ybGQ=", []string{"url_encode_query", "base64"})
	if err != nil {
		t.Fatalf("Decode chain error = %v", err)
	}
	want := "hello world"
	if result != want {
		t.Errorf("Decode chain = %q, want %q", result, want)
	}
}

func TestRegistry_Encode_UnknownCodec(t *testing.T) {
	r := NewRegistry()
	_, err := r.Encode("hello", []string{"nonexistent"})
	if err == nil {
		t.Error("Encode with unknown codec expected error")
	}
}

func TestRegistry_Decode_UnknownCodec(t *testing.T) {
	r := NewRegistry()
	_, err := r.Decode("hello", []string{"nonexistent"})
	if err == nil {
		t.Error("Decode with unknown codec expected error")
	}
}

func TestRegistry_Encode_EmptyChain(t *testing.T) {
	r := NewRegistry()
	result, err := r.Encode("hello", nil)
	if err != nil {
		t.Fatalf("Encode empty chain error = %v", err)
	}
	if result != "hello" {
		t.Errorf("Encode empty chain = %q, want %q", result, "hello")
	}
}

func TestPackageLevelFunctions(t *testing.T) {
	encoded, err := Encode("hello", []string{"base64"})
	if err != nil {
		t.Fatalf("Encode error = %v", err)
	}
	if encoded != "aGVsbG8=" {
		t.Errorf("Encode = %q, want %q", encoded, "aGVsbG8=")
	}

	decoded, err := Decode(encoded, []string{"base64"})
	if err != nil {
		t.Fatalf("Decode error = %v", err)
	}
	if decoded != "hello" {
		t.Errorf("Decode = %q, want %q", decoded, "hello")
	}
}

func TestChain(t *testing.T) {
	r := NewRegistry()
	chain := NewChain(r, "url_encode_query", "base64")

	encoded, err := chain.Encode("hello world")
	if err != nil {
		t.Fatalf("Chain.Encode error = %v", err)
	}
	want := "aGVsbG8rd29ybGQ="
	if encoded != want {
		t.Errorf("Chain.Encode = %q, want %q", encoded, want)
	}

	decoded, err := chain.Decode(encoded)
	if err != nil {
		t.Fatalf("Chain.Decode error = %v", err)
	}
	if decoded != "hello world" {
		t.Errorf("Chain.Decode = %q, want %q", decoded, "hello world")
	}
}

func TestDefaultRegistry(t *testing.T) {
	r1 := DefaultRegistry()
	r2 := DefaultRegistry()
	if r1 != r2 {
		t.Error("DefaultRegistry() should return the same instance")
	}
}

func TestHTMLEntity_Decode_MixedContent(t *testing.T) {
	r := NewRegistry()
	c, _ := r.Get("html_entity")

	// Mixed literal and entity text.
	decoded, err := c.Decode("hello &#x3C;world&#x3E;")
	if err != nil {
		t.Fatalf("Decode error = %v", err)
	}
	if decoded != "hello <world>" {
		t.Errorf("Decode = %q, want %q", decoded, "hello <world>")
	}
}

func TestHTMLEntity_Decode_DecimalEntity(t *testing.T) {
	r := NewRegistry()
	c, _ := r.Get("html_entity")

	decoded, err := c.Decode("&#60;script&#62;")
	if err != nil {
		t.Fatalf("Decode error = %v", err)
	}
	if decoded != "<script>" {
		t.Errorf("Decode = %q, want %q", decoded, "<script>")
	}
}

func TestUnicodeEscape_Supplementary(t *testing.T) {
	r := NewRegistry()
	c, _ := r.Get("unicode_escape")

	// Test with emoji (supplementary plane character).
	input := "🎉"
	encoded, err := c.Encode(input)
	if err != nil {
		t.Fatalf("Encode error = %v", err)
	}
	decoded, err := c.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode error = %v", err)
	}
	if decoded != input {
		t.Errorf("roundtrip = %q, want %q", decoded, input)
	}
}

func TestDoubleURLEncode_Roundtrip(t *testing.T) {
	r := NewRegistry()
	c, _ := r.Get("double_url_encode")

	input := "hello world & <test>"
	encoded, err := c.Encode(input)
	if err != nil {
		t.Fatalf("Encode error = %v", err)
	}
	decoded, err := c.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode error = %v", err)
	}
	if decoded != input {
		t.Errorf("roundtrip = %q, want %q", decoded, input)
	}
}

// mockCodec is a test double for Codec.
type mockCodec struct {
	name string
}

func (m *mockCodec) Name() string                    { return m.name }
func (m *mockCodec) Encode(s string) (string, error) { return s, nil }
func (m *mockCodec) Decode(s string) (string, error) { return s, nil }
