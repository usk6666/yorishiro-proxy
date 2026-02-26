package macro

import (
	"testing"
)

func TestGetEncoder(t *testing.T) {
	tests := []struct {
		name     string
		encoder  string
		wantNil  bool
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
		want    string
		wantErr bool
	}{
		{
			name:    "url_encode basic",
			encoder: "url_encode",
			input:   "hello world",
			want:    "hello+world",
		},
		{
			name:    "url_encode special chars",
			encoder: "url_encode",
			input:   "key=value&foo=bar",
			want:    "key%3Dvalue%26foo%3Dbar",
		},
		{
			name:    "base64 encode",
			encoder: "base64",
			input:   "hello",
			want:    "aGVsbG8=",
		},
		{
			name:    "base64_decode valid",
			encoder: "base64_decode",
			input:   "aGVsbG8=",
			want:    "hello",
		},
		{
			name:    "base64_decode invalid",
			encoder: "base64_decode",
			input:   "not-valid-base64!!!",
			wantErr: true,
		},
		{
			name:    "html_encode",
			encoder: "html_encode",
			input:   `<script>alert("xss")</script>`,
			want:    "&lt;script&gt;alert(&#34;xss&#34;)&lt;/script&gt;",
		},
		{
			name:    "hex encode",
			encoder: "hex",
			input:   "abc",
			want:    "616263",
		},
		{
			name:    "lower",
			encoder: "lower",
			input:   "Hello World",
			want:    "hello world",
		},
		{
			name:    "upper",
			encoder: "upper",
			input:   "Hello World",
			want:    "HELLO WORLD",
		},
		{
			name:    "md5 hash",
			encoder: "md5",
			input:   "hello",
			want:    "5d41402abc4b2a76b9719d911017c592",
		},
		{
			name:    "sha256 hash",
			encoder: "sha256",
			input:   "hello",
			want:    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
		},
		{
			name:    "empty input",
			encoder: "url_encode",
			input:   "",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := GetEncoder(tt.encoder)
			if enc == nil {
				t.Fatalf("encoder %q not found", tt.encoder)
			}
			got, err := enc(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("encoder %q(%q) error = %v, wantErr %v", tt.encoder, tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("encoder %q(%q) = %q, want %q", tt.encoder, tt.input, got, tt.want)
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
