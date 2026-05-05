package grpcweb

import (
	"testing"
)

func TestParseTrailers(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    map[string]string
		wantErr bool
	}{
		{
			name:    "standard grpc-status 0",
			payload: []byte("grpc-status: 0\r\n"),
			want:    map[string]string{"grpc-status": "0"},
		},
		{
			name:    "grpc-status with message",
			payload: []byte("grpc-status: 0\r\ngrpc-message: OK\r\n"),
			want:    map[string]string{"grpc-status": "0", "grpc-message": "OK"},
		},
		{
			name:    "error status with message",
			payload: []byte("grpc-status: 13\r\ngrpc-message: internal error\r\n"),
			want:    map[string]string{"grpc-status": "13", "grpc-message": "internal error"},
		},
		{
			name:    "LF line endings",
			payload: []byte("grpc-status: 0\ngrpc-message: OK\n"),
			want:    map[string]string{"grpc-status": "0", "grpc-message": "OK"},
		},
		{
			name:    "mixed CRLF and LF",
			payload: []byte("grpc-status: 0\r\ngrpc-message: OK\n"),
			want:    map[string]string{"grpc-status": "0", "grpc-message": "OK"},
		},
		{
			name:    "value with colon",
			payload: []byte("grpc-status: 0\r\ngrpc-message: error: something broke\r\n"),
			want:    map[string]string{"grpc-status": "0", "grpc-message": "error: something broke"},
		},
		{
			name:    "empty payload",
			payload: []byte{},
			want:    map[string]string{},
		},
		{
			name:    "nil payload",
			payload: nil,
			want:    map[string]string{},
		},
		{
			name:    "only whitespace/newlines",
			payload: []byte("\r\n\r\n"),
			want:    map[string]string{},
		},
		{
			name:    "duplicate key uses last value",
			payload: []byte("grpc-status: 0\r\ngrpc-status: 13\r\n"),
			want:    map[string]string{"grpc-status": "13"},
		},
		{
			name:    "no space after colon",
			payload: []byte("grpc-status:0\r\n"),
			want:    map[string]string{"grpc-status": "0"},
		},
		{
			name:    "multiple spaces after colon",
			payload: []byte("grpc-status:   0\r\n"),
			want:    map[string]string{"grpc-status": "0"},
		},
		{
			name:    "preserves key casing",
			payload: []byte("Grpc-Status: 0\r\n"),
			want:    map[string]string{"Grpc-Status": "0"},
		},
		{
			name:    "malformed line without colon",
			payload: []byte("grpc-status: 0\r\nmalformed-line\r\n"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTrailers(tt.payload)
			if tt.wantErr {
				if err == nil {
					t.Fatal("ParseTrailers() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTrailers() error = %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ParseTrailers() returned %d entries, want %d: got=%v", len(got), len(tt.want), got)
			}
			for k, wantV := range tt.want {
				gotV, ok := got[k]
				if !ok {
					t.Errorf("ParseTrailers() missing key %q", k)
					continue
				}
				if gotV != wantV {
					t.Errorf("ParseTrailers()[%q] = %q, want %q", k, gotV, wantV)
				}
			}
		})
	}
}
