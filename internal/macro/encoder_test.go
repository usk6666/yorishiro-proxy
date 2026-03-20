package macro

import (
	"testing"
)

func TestGetEncoder(t *testing.T) {
	tests := []struct {
		name    string
		encoder string
		wantNil bool
	}{
		{name: "url_encode exists", encoder: "url_encode"},
		{name: "base64 exists", encoder: "base64"},
		{name: "base64_decode exists", encoder: "base64_decode"},
		{name: "html_encode exists", encoder: "html_encode"},
		{name: "hex exists", encoder: "hex"},
		{name: "lower exists", encoder: "lower"},
		{name: "upper exists", encoder: "upper"},
		{name: "md5 exists", encoder: "md5"},
		{name: "sha256 exists", encoder: "sha256"},
		{name: "unknown returns nil", encoder: "nonexistent", wantNil: true},
		{name: "empty returns nil", encoder: "", wantNil: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := GetEncoder(tt.encoder)
			if tt.wantNil && enc != nil {
				t.Errorf("GetEncoder(%q) = non-nil, want nil", tt.encoder)
			}
			if !tt.wantNil && enc == nil {
				t.Errorf("GetEncoder(%q) = nil, want non-nil", tt.encoder)
			}
		})
	}
}

func TestListEncoders(t *testing.T) {
	encoders := ListEncoders()
	if len(encoders) != 9 {
		t.Errorf("ListEncoders() returned %d encoders, want 9", len(encoders))
	}
	expected := map[string]bool{
		"url_encode": true, "base64": true, "base64_decode": true,
		"html_encode": true, "hex": true, "lower": true,
		"upper": true, "md5": true, "sha256": true,
	}
	for _, name := range encoders {
		if !expected[name] {
			t.Errorf("unexpected encoder %q", name)
		}
	}
}

func TestEncoders(t *testing.T) {
	tests := []struct {
		name    string
		encoder string
		input   string
		wantErr bool
	}{
		{name: "url_encode returns result", encoder: "url_encode", input: "hello world"},
		{name: "base64_decode error propagates", encoder: "base64_decode", input: "not-valid-base64!!!", wantErr: true},
		{name: "empty input", encoder: "url_encode", input: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := GetEncoder(tt.encoder)
			if enc == nil {
				t.Fatalf("encoder %q not found", tt.encoder)
			}
			_, err := enc(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("encoder %q(%q) error = %v, wantErr %v", tt.encoder, tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestApplyEncoders(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		encoders []string
		want     string
		wantErr  bool
	}{
		{
			name:     "empty chain",
			value:    "hello",
			encoders: nil,
			want:     "hello",
		},
		{
			name:     "single encoder",
			value:    "hello",
			encoders: []string{"upper"},
			want:     "HELLO",
		},
		{
			name:     "chain: url_encode then base64",
			value:    "hello world",
			encoders: []string{"url_encode", "base64"},
			want:     "aGVsbG8rd29ybGQ=",
		},
		{
			name:     "chain: base64 then upper",
			value:    "abc",
			encoders: []string{"base64", "upper"},
			want:     "YWJJ",
		},
		{
			name:     "unknown encoder in chain",
			value:    "hello",
			encoders: []string{"upper", "nonexistent"},
			wantErr:  true,
		},
		{
			name:     "error in chain propagates",
			value:    "not-base64!!!",
			encoders: []string{"base64_decode"},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ApplyEncoders(tt.value, tt.encoders)
			if (err != nil) != tt.wantErr {
				t.Errorf("ApplyEncoders(%q, %v) error = %v, wantErr %v", tt.value, tt.encoders, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ApplyEncoders(%q, %v) = %q, want %q", tt.value, tt.encoders, got, tt.want)
			}
		})
	}
}
