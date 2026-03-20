package proxy

import "testing"

func TestIsTLSClientHello(t *testing.T) {
	tests := []struct {
		name   string
		peek   []byte
		expect bool
	}{
		{"valid TLS 1.0", []byte{0x16, 0x03, 0x01}, true},
		{"valid TLS 1.2", []byte{0x16, 0x03, 0x03}, true},
		{"valid TLS 1.3", []byte{0x16, 0x03, 0x04}, true},
		{"minimum bytes", []byte{0x16, 0x03}, true},
		{"too short", []byte{0x16}, false},
		{"empty", []byte{}, false},
		{"not TLS - HTTP", []byte("GET /"), false},
		{"wrong content type", []byte{0x15, 0x03}, false},
		{"wrong version", []byte{0x16, 0x04}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTLSClientHello(tt.peek)
			if got != tt.expect {
				t.Fatalf("isTLSClientHello(%v) = %v, want %v", tt.peek, got, tt.expect)
			}
		})
	}
}

func TestExtractHostnameFromTarget(t *testing.T) {
	tests := []struct {
		target string
		want   string
	}{
		{"api.example.com:50051", "api.example.com"},
		{"example.com:443", "example.com"},
		{"192.168.1.1:8080", "192.168.1.1"},
		{"[::1]:443", "::1"},
		{"example.com", "example.com"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			got := extractHostnameFromTarget(tt.target)
			if got != tt.want {
				t.Errorf("extractHostnameFromTarget(%q) = %q, want %q", tt.target, got, tt.want)
			}
		})
	}
}
