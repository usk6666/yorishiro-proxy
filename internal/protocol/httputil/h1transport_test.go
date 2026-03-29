package httputil

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
)

func TestSerializeRequest_BasicGET(t *testing.T) {
	req := &parser.RawRequest{
		Method:     "GET",
		RequestURI: "/path?q=1",
		Proto:      "HTTP/1.1",
		Headers: parser.RawHeaders{
			{Name: "Host", Value: "example.com"},
			{Name: "User-Agent", Value: "test/1.0"},
			{Name: "Accept", Value: "*/*"},
		},
	}

	got := string(SerializeRequest(req))
	want := "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test/1.0\r\nAccept: */*\r\n\r\n"
	if got != want {
		t.Errorf("SerializeRequest() =\n%q\nwant\n%q", got, want)
	}
}

func TestSerializeRequest_PreservesHeaderOrder(t *testing.T) {
	req := &parser.RawRequest{
		Method:     "POST",
		RequestURI: "/api",
		Proto:      "HTTP/1.1",
		Headers: parser.RawHeaders{
			{Name: "Content-Type", Value: "application/json"},
			{Name: "X-Custom-First", Value: "1"},
			{Name: "Authorization", Value: "Bearer token"},
			{Name: "X-Custom-Last", Value: "2"},
		},
	}

	got := string(SerializeRequest(req))
	lines := strings.Split(got, "\r\n")
	// Request line + 4 headers + empty line + trailing empty
	if len(lines) < 6 {
		t.Fatalf("expected at least 6 lines, got %d: %q", len(lines), got)
	}

	expectedHeaders := []string{
		"Content-Type: application/json",
		"X-Custom-First: 1",
		"Authorization: Bearer token",
		"X-Custom-Last: 2",
	}
	for i, want := range expectedHeaders {
		if lines[i+1] != want {
			t.Errorf("header line %d = %q, want %q", i, lines[i+1], want)
		}
	}
}

func TestSerializeRequest_RawValue(t *testing.T) {
	req := &parser.RawRequest{
		Method:     "GET",
		RequestURI: "/",
		Proto:      "HTTP/1.1",
		Headers: parser.RawHeaders{
			{Name: "Host", Value: "example.com", RawValue: "  example.com  "},
		},
	}

	got := string(SerializeRequest(req))
	if !strings.Contains(got, "Host:  example.com  \r\n") {
		t.Errorf("SerializeRequest should use RawValue when set, got:\n%q", got)
	}
}

func TestSerializeRequest_DefaultProto(t *testing.T) {
	req := &parser.RawRequest{
		Method:     "GET",
		RequestURI: "/",
		// Proto is empty — should default to HTTP/1.1.
	}

	got := string(SerializeRequest(req))
	if !strings.HasPrefix(got, "GET / HTTP/1.1\r\n") {
		t.Errorf("SerializeRequest should default to HTTP/1.1, got:\n%q", got)
	}
}

func TestSerializeRequest_EmptyHeaders(t *testing.T) {
	req := &parser.RawRequest{
		Method:     "GET",
		RequestURI: "/",
		Proto:      "HTTP/1.1",
	}

	got := string(SerializeRequest(req))
	want := "GET / HTTP/1.1\r\n\r\n"
	if got != want {
		t.Errorf("SerializeRequest() = %q, want %q", got, want)
	}
}

func TestH1Transport_RoundTripOnConn_Structured(t *testing.T) {
	// Create a mock server that responds with a fixed HTTP response.
	server, client := net.Pipe()
	defer client.Close()

	responseData := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Test: yes\r\n\r\nhello"

	go func() {
		defer server.Close()
		// Read the request (discard it).
		buf := make([]byte, 4096)
		server.Read(buf)
		// Write the response.
		server.Write([]byte(responseData))
	}()

	transport := &H1Transport{}
	req := &parser.RawRequest{
		Method:     "GET",
		RequestURI: "/test",
		Proto:      "HTTP/1.1",
		Headers: parser.RawHeaders{
			{Name: "Host", Value: "example.com"},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := transport.RoundTripOnConn(ctx, client, req)
	if err != nil {
		t.Fatalf("RoundTripOnConn() error = %v", err)
	}

	if result.Response.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", result.Response.StatusCode)
	}
	if result.Response.Proto != "HTTP/1.1" {
		t.Errorf("Proto = %q, want %q", result.Response.Proto, "HTTP/1.1")
	}
	if got := result.Response.Headers.Get("X-Test"); got != "yes" {
		t.Errorf("X-Test header = %q, want %q", got, "yes")
	}

	// Read body from the response.
	body, err := io.ReadAll(result.Response.Body)
	if err != nil {
		t.Fatalf("ReadAll body error = %v", err)
	}
	if string(body) != "hello" {
		t.Errorf("body = %q, want %q", body, "hello")
	}
}

func TestH1Transport_RoundTripOnConn_RawMode(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	rawRequest := []byte("GET /smuggle HTTP/1.1\r\nHost: evil.com\r\n\r\n")
	responseData := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

	receivedCh := make(chan []byte, 1)
	go func() {
		defer server.Close()
		buf := make([]byte, 4096)
		n, _ := server.Read(buf)
		captured := make([]byte, n)
		copy(captured, buf[:n])
		receivedCh <- captured
		server.Write([]byte(responseData))
	}()

	transport := &H1Transport{}
	req := &parser.RawRequest{
		Method:     "GET",
		RequestURI: "/smuggle",
		Proto:      "HTTP/1.1",
		RawBytes:   rawRequest,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := transport.RoundTripOnConn(ctx, client, req)
	if err != nil {
		t.Fatalf("RoundTripOnConn() error = %v", err)
	}

	if result.Response.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", result.Response.StatusCode)
	}

	// Wait for the server goroutine to send captured bytes before asserting.
	receivedBytes := <-receivedCh

	// Verify that the raw bytes were sent verbatim.
	if !bytes.Equal(receivedBytes, rawRequest) {
		t.Errorf("received bytes = %q, want %q", receivedBytes, rawRequest)
	}
}

func TestH1Transport_RoundTripOnConn_WithBody(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	responseData := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

	var receivedData bytes.Buffer
	go func() {
		defer server.Close()
		buf := make([]byte, 4096)
		for {
			n, err := server.Read(buf)
			if n > 0 {
				receivedData.Write(buf[:n])
			}
			if err != nil {
				break
			}
			// Check if we've received the full request (headers + body).
			if bytes.Contains(receivedData.Bytes(), []byte("test body")) {
				break
			}
		}
		server.Write([]byte(responseData))
	}()

	transport := &H1Transport{}
	bodyContent := "test body"
	req := &parser.RawRequest{
		Method:     "POST",
		RequestURI: "/submit",
		Proto:      "HTTP/1.1",
		Headers: parser.RawHeaders{
			{Name: "Host", Value: "example.com"},
			{Name: "Content-Length", Value: fmt.Sprintf("%d", len(bodyContent))},
		},
		Body: strings.NewReader(bodyContent),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := transport.RoundTripOnConn(ctx, client, req)
	if err != nil {
		t.Fatalf("RoundTripOnConn() error = %v", err)
	}

	if result.Response.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", result.Response.StatusCode)
	}

	// Verify the body was sent.
	received := receivedData.String()
	if !strings.Contains(received, "test body") {
		t.Errorf("server did not receive body, got: %q", received)
	}
	if !strings.Contains(received, "Content-Length: 9") {
		t.Errorf("server did not receive Content-Length header, got: %q", received)
	}
}

func TestH1Transport_RoundTripOnConn_Timing(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	responseData := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

	go func() {
		defer server.Close()
		buf := make([]byte, 4096)
		server.Read(buf)
		// Small delay to ensure timing is measurable.
		time.Sleep(10 * time.Millisecond)
		server.Write([]byte(responseData))
	}()

	transport := &H1Transport{}
	req := &parser.RawRequest{
		Method:     "GET",
		RequestURI: "/",
		Proto:      "HTTP/1.1",
		Headers: parser.RawHeaders{
			{Name: "Host", Value: "example.com"},
		},
	}

	sendStart := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := transport.RoundTripOnConn(ctx, client, req)
	if err != nil {
		t.Fatalf("RoundTripOnConn() error = %v", err)
	}
	receiveEnd := time.Now()

	// Use ComputeTiming to verify timing is recorded.
	sendMs, waitMs, receiveMs := ComputeTiming(sendStart, result.Timing, receiveEnd)
	if sendMs == nil {
		t.Error("sendMs should not be nil")
	}
	if waitMs == nil {
		t.Error("waitMs should not be nil")
	}
	if receiveMs == nil {
		t.Error("receiveMs should not be nil")
	}
}

func TestH1Transport_RoundTripOnConn_ReadError(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		buf := make([]byte, 4096)
		server.Read(buf)
		// Close without writing a response.
		server.Close()
	}()

	transport := &H1Transport{}
	req := &parser.RawRequest{
		Method:     "GET",
		RequestURI: "/",
		Proto:      "HTTP/1.1",
		Headers: parser.RawHeaders{
			{Name: "Host", Value: "example.com"},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := transport.RoundTripOnConn(ctx, client, req)
	if err == nil {
		t.Fatal("RoundTripOnConn() expected error when server closes connection")
	}
}

func TestIsKeepAlive(t *testing.T) {
	tests := []struct {
		name string
		resp *parser.RawResponse
		want bool
	}{
		{
			name: "HTTP/1.1 default is keep-alive",
			resp: &parser.RawResponse{
				Proto:   "HTTP/1.1",
				Headers: parser.RawHeaders{},
			},
			want: true,
		},
		{
			name: "HTTP/1.1 with Connection close",
			resp: &parser.RawResponse{
				Proto: "HTTP/1.1",
				Headers: parser.RawHeaders{
					{Name: "Connection", Value: "close"},
				},
			},
			want: false,
		},
		{
			name: "HTTP/1.0 default is close",
			resp: &parser.RawResponse{
				Proto:   "HTTP/1.0",
				Headers: parser.RawHeaders{},
			},
			want: false,
		},
		{
			name: "HTTP/1.0 with Connection keep-alive",
			resp: &parser.RawResponse{
				Proto: "HTTP/1.0",
				Headers: parser.RawHeaders{
					{Name: "Connection", Value: "keep-alive"},
				},
			},
			want: true,
		},
		{
			name: "HTTP/1.1 with Connection close in comma-separated list",
			resp: &parser.RawResponse{
				Proto: "HTTP/1.1",
				Headers: parser.RawHeaders{
					{Name: "Connection", Value: "upgrade, close"},
				},
			},
			want: false,
		},
		{
			name: "HTTP/1.1 case-insensitive Connection Close",
			resp: &parser.RawResponse{
				Proto: "HTTP/1.1",
				Headers: parser.RawHeaders{
					{Name: "Connection", Value: "Close"},
				},
			},
			want: false,
		},
		{
			name: "HTTP/1.0 case-insensitive Connection Keep-Alive",
			resp: &parser.RawResponse{
				Proto: "HTTP/1.0",
				Headers: parser.RawHeaders{
					{Name: "Connection", Value: "Keep-Alive"},
				},
			},
			want: true,
		},
		{
			name: "HTTP/1.1 Connection keep-alive and close gives close precedence",
			resp: &parser.RawResponse{
				Proto: "HTTP/1.1",
				Headers: parser.RawHeaders{
					{Name: "Connection", Value: "keep-alive, close"},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsKeepAlive(tt.resp)
			if got != tt.want {
				t.Errorf("IsKeepAlive() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWriteRequest_HeaderAndBody(t *testing.T) {
	var buf bytes.Buffer
	conn := &bufConn{Buffer: &buf}

	header := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	body := strings.NewReader("body data")

	err := WriteRequest(conn, header, body)
	if err != nil {
		t.Fatalf("WriteRequest() error = %v", err)
	}

	got := buf.String()
	want := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody data"
	if got != want {
		t.Errorf("WriteRequest() wrote %q, want %q", got, want)
	}
}

func TestWriteRequest_NilBody(t *testing.T) {
	var buf bytes.Buffer
	conn := &bufConn{Buffer: &buf}

	header := []byte("GET / HTTP/1.1\r\n\r\n")

	err := WriteRequest(conn, header, nil)
	if err != nil {
		t.Fatalf("WriteRequest() error = %v", err)
	}

	got := buf.String()
	if got != "GET / HTTP/1.1\r\n\r\n" {
		t.Errorf("WriteRequest() wrote %q", got)
	}
}

// bufConn wraps a bytes.Buffer to implement net.Conn for write-only tests.
type bufConn struct {
	*bytes.Buffer
}

func (c *bufConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *bufConn) Close() error                     { return nil }
func (c *bufConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *bufConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *bufConn) SetDeadline(time.Time) error      { return nil }
func (c *bufConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bufConn) SetWriteDeadline(time.Time) error { return nil }

// Implement Write via the embedded Buffer.
