package grpcweb

import (
	"io"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/codec/http1/parser"
)

func TestBuildRequest_Binary(t *testing.T) {
	t.Parallel()

	headers := parser.RawHeaders{
		{Name: "content-type", Value: "application/grpc-web"},
	}
	frames := []Frame{
		{IsTrailer: false, Compressed: false, Payload: []byte("hello")},
	}

	req, err := BuildRequest("POST", "https://example.com/pkg.Svc/Method", headers, frames, WireEncodingBinary)
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}

	if req.Method != "POST" {
		t.Errorf("Method = %q, want POST", req.Method)
	}
	if req.RequestURI != "/pkg.Svc/Method" {
		t.Errorf("RequestURI = %q, want /pkg.Svc/Method", req.RequestURI)
	}
	if req.Proto != "HTTP/1.1" {
		t.Errorf("Proto = %q, want HTTP/1.1", req.Proto)
	}

	// Read body and verify it's binary-encoded frames.
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll body: %v", err)
	}
	expected := EncodeFrame(false, false, []byte("hello"))
	if string(body) != string(expected) {
		t.Errorf("body = %x, want %x", body, expected)
	}

	// Verify Host header is present.
	if req.Headers.Get("Host") != "example.com" {
		t.Errorf("Host = %q, want example.com", req.Headers.Get("Host"))
	}
}

func TestBuildRequest_Base64(t *testing.T) {
	t.Parallel()

	headers := parser.RawHeaders{
		{Name: "content-type", Value: "application/grpc-web-text"},
	}
	frames := []Frame{
		{IsTrailer: false, Compressed: false, Payload: []byte("hello")},
	}

	req, err := BuildRequest("POST", "https://example.com/pkg.Svc/Method", headers, frames, WireEncodingBase64)
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("ReadAll body: %v", err)
	}

	// Verify body is base64-encoded.
	binaryFrames := EncodeFrame(false, false, []byte("hello"))
	expectedBase64 := EncodeBase64Body(binaryFrames)
	if string(body) != string(expectedBase64) {
		t.Errorf("body = %q, want %q", body, expectedBase64)
	}
}

func TestBuildRequest_EmptyFrames(t *testing.T) {
	t.Parallel()

	headers := parser.RawHeaders{
		{Name: "content-type", Value: "application/grpc-web"},
	}

	req, err := BuildRequest("POST", "https://example.com/pkg.Svc/Method", headers, nil, WireEncodingBinary)
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}

	if req.Body != nil {
		t.Error("expected nil body for empty frames")
	}
}

func TestBuildRequest_EmptyMethod(t *testing.T) {
	t.Parallel()

	_, err := BuildRequest("", "https://example.com/path", nil, nil, WireEncodingBinary)
	if err == nil {
		t.Fatal("expected error for empty method")
	}
}

func TestBuildRequest_EmptyURL(t *testing.T) {
	t.Parallel()

	_, err := BuildRequest("POST", "", nil, nil, WireEncodingBinary)
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
}

func TestBuildRequest_ContentLengthSet(t *testing.T) {
	t.Parallel()

	headers := parser.RawHeaders{
		{Name: "content-type", Value: "application/grpc-web"},
		{Name: "Content-Length", Value: "999"}, // should be replaced
	}
	frames := []Frame{
		{IsTrailer: false, Compressed: false, Payload: []byte("data")},
	}

	req, err := BuildRequest("POST", "https://example.com/svc/Method", headers, frames, WireEncodingBinary)
	if err != nil {
		t.Fatalf("BuildRequest: %v", err)
	}

	body, _ := io.ReadAll(req.Body)
	cl := req.Headers.Get("Content-Length")
	if cl == "999" {
		t.Errorf("Content-Length was not updated: still %q", cl)
	}
	if cl != "9" { // 5-byte header + 4-byte payload
		t.Errorf("Content-Length = %q, want %q (body len=%d)", cl, "9", len(body))
	}
}

func TestExtractHostFromURL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		url  string
		want string
	}{
		{"https://example.com/path", "example.com"},
		{"http://host:8080/path", "host:8080"},
		{"https://user@example.com/path", "example.com"},
	}
	for _, tt := range tests {
		got := extractHostFromURL(tt.url)
		if got != tt.want {
			t.Errorf("extractHostFromURL(%q) = %q, want %q", tt.url, got, tt.want)
		}
	}
}

func TestExtractRequestURI(t *testing.T) {
	t.Parallel()
	tests := []struct {
		url  string
		want string
	}{
		{"https://example.com/pkg.Svc/Method", "/pkg.Svc/Method"},
		{"https://example.com/path?q=1", "/path?q=1"},
		{"https://example.com", "/"},
	}
	for _, tt := range tests {
		got := extractRequestURI(tt.url)
		if got != tt.want {
			t.Errorf("extractRequestURI(%q) = %q, want %q", tt.url, got, tt.want)
		}
	}
}
