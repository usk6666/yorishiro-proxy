package mcp

import (
	"encoding/base64"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
)

func TestResolveReleaseMode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    intercept.ReleaseMode
		wantErr bool
	}{
		{name: "empty defaults to structured", input: "", want: intercept.ModeStructured, wantErr: false},
		{name: "structured", input: "structured", want: intercept.ModeStructured, wantErr: false},
		{name: "raw", input: "raw", want: intercept.ModeRaw, wantErr: false},
		{name: "invalid", input: "invalid", want: "", wantErr: true},
		{name: "uppercase invalid", input: "RAW", want: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveReleaseMode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveReleaseMode(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("resolveReleaseMode(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestDecodeRawOverride(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []byte
		wantErr bool
	}{
		{
			name:    "valid base64",
			input:   base64.StdEncoding.EncodeToString([]byte("hello")),
			want:    []byte("hello"),
			wantErr: false,
		},
		{
			name:    "empty string",
			input:   "",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid base64",
			input:   "not-valid-base64!!!",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "base64 encoding of empty",
			input:   base64.StdEncoding.EncodeToString([]byte{}),
			want:    nil,
			wantErr: true,
		},
		{
			name:    "binary data",
			input:   base64.StdEncoding.EncodeToString([]byte{0x00, 0x01, 0xFF, 0xFE}),
			want:    []byte{0x00, 0x01, 0xFF, 0xFE},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeRawOverride(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeRawOverride() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && string(got) != string(tt.want) {
				t.Errorf("decodeRawOverride() = %v, want %v", got, tt.want)
			}
		})
	}
}
