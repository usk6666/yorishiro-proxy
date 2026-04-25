package grpcweb

import "testing"

func TestIsGRPCWebContentType(t *testing.T) {
	tests := []struct {
		name string
		ct   string
		want bool
	}{
		// Binary variants.
		{name: "grpc-web", ct: "application/grpc-web", want: true},
		{name: "grpc-web+proto", ct: "application/grpc-web+proto", want: true},
		{name: "grpc-web+json", ct: "application/grpc-web+json", want: true},
		{name: "grpc-web with charset", ct: "application/grpc-web; charset=utf-8", want: true},
		{name: "grpc-web+proto with charset", ct: "application/grpc-web+proto; charset=utf-8", want: true},

		// Text (base64) variants.
		{name: "grpc-web-text", ct: "application/grpc-web-text", want: true},
		{name: "grpc-web-text+proto", ct: "application/grpc-web-text+proto", want: true},
		{name: "grpc-web-text+json", ct: "application/grpc-web-text+json", want: true},
		{name: "grpc-web-text with charset", ct: "application/grpc-web-text; charset=utf-8", want: true},

		// Case insensitivity.
		{name: "uppercase", ct: "APPLICATION/GRPC-WEB", want: true},
		{name: "mixed case", ct: "Application/gRPC-Web-Text+Proto", want: true},

		// Non-matching types.
		{name: "plain grpc", ct: "application/grpc", want: false},
		{name: "application/json", ct: "application/json", want: false},
		{name: "text/html", ct: "text/html", want: false},
		{name: "empty string", ct: "", want: false},
		{name: "grpc-web prefix only", ct: "application/grpc-webx", want: false},
		{name: "application/grpc+proto", ct: "application/grpc+proto", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsGRPCWebContentType(tt.ct)
			if got != tt.want {
				t.Errorf("IsGRPCWebContentType(%q) = %v, want %v", tt.ct, got, tt.want)
			}
		})
	}
}

func TestIsBase64Encoded(t *testing.T) {
	tests := []struct {
		name string
		ct   string
		want bool
	}{
		// Text (base64) variants.
		{name: "grpc-web-text", ct: "application/grpc-web-text", want: true},
		{name: "grpc-web-text+proto", ct: "application/grpc-web-text+proto", want: true},
		{name: "grpc-web-text+json", ct: "application/grpc-web-text+json", want: true},
		{name: "grpc-web-text with charset", ct: "application/grpc-web-text; charset=utf-8", want: true},
		{name: "uppercase", ct: "APPLICATION/GRPC-WEB-TEXT", want: true},

		// Binary variants are NOT base64.
		{name: "grpc-web", ct: "application/grpc-web", want: false},
		{name: "grpc-web+proto", ct: "application/grpc-web+proto", want: false},

		// Non-matching types.
		{name: "application/grpc", ct: "application/grpc", want: false},
		{name: "empty string", ct: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsBase64Encoded(tt.ct)
			if got != tt.want {
				t.Errorf("IsBase64Encoded(%q) = %v, want %v", tt.ct, got, tt.want)
			}
		})
	}
}
