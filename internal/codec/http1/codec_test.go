package http1

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/codec"
	"github.com/usk6666/yorishiro-proxy/internal/exchange"
)

// Compile-time interface check.
var _ codec.Codec = (*Codec)(nil)

// readWriteCloser wraps a bytes.Buffer for testing, providing io.ReadWriteCloser.
type readWriteCloser struct {
	io.Reader
	io.Writer
	closed bool
}

func (rwc *readWriteCloser) Close() error {
	rwc.closed = true
	return nil
}

func (rwc *readWriteCloser) Read(p []byte) (int, error)  { return rwc.Reader.Read(p) }
func (rwc *readWriteCloser) Write(p []byte) (int, error) { return rwc.Writer.Write(p) }

func newRWC(input string, output *bytes.Buffer) *readWriteCloser {
	return &readWriteCloser{
		Reader: strings.NewReader(input),
		Writer: output,
	}
}

func TestNextRequest_GET(t *testing.T) {
	input := "GET /path HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"
	output := &bytes.Buffer{}
	c := NewCodec(newRWC(input, output), ClientRole)
	defer c.Close()

	ex, err := c.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	if ex.Direction != exchange.Send {
		t.Errorf("Direction = %v, want Send", ex.Direction)
	}
	if ex.Method != "GET" {
		t.Errorf("Method = %q, want GET", ex.Method)
	}
	if ex.URL == nil || ex.URL.Path != "/path" {
		t.Errorf("URL.Path = %v, want /path", ex.URL)
	}
	if ex.Protocol != exchange.HTTP1 {
		t.Errorf("Protocol = %v, want HTTP1", ex.Protocol)
	}
	if len(ex.Headers) != 2 {
		t.Fatalf("Headers len = %d, want 2", len(ex.Headers))
	}
	if ex.Headers[0].Name != "Host" || ex.Headers[0].Value != "example.com" {
		t.Errorf("Header[0] = %+v, want Host: example.com", ex.Headers[0])
	}
	if ex.Headers[1].Name != "Accept" || ex.Headers[1].Value != "*/*" {
		t.Errorf("Header[1] = %+v, want Accept: */*", ex.Headers[1])
	}
	if ex.StreamID == "" {
		t.Error("StreamID is empty")
	}
	if ex.FlowID == "" {
		t.Error("FlowID is empty")
	}
	if ex.Sequence != 0 {
		t.Errorf("Sequence = %d, want 0", ex.Sequence)
	}
	if len(ex.RawBytes) == 0 {
		t.Error("RawBytes is empty")
	}
	// Body should be empty (not nil) for a GET request.
	if ex.Body == nil {
		t.Error("Body is nil, want empty slice")
	}
	if len(ex.Body) != 0 {
		t.Errorf("Body = %q, want empty", ex.Body)
	}
}

func TestNextRequest_POST(t *testing.T) {
	input := "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\n\r\nhello world"
	output := &bytes.Buffer{}
	c := NewCodec(newRWC(input, output), ClientRole)
	defer c.Close()

	ex, err := c.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	if ex.Method != "POST" {
		t.Errorf("Method = %q, want POST", ex.Method)
	}
	if string(ex.Body) != "hello world" {
		t.Errorf("Body = %q, want %q", ex.Body, "hello world")
	}
}

func TestNextResponse_200OK(t *testing.T) {
	input := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"
	output := &bytes.Buffer{}
	c := NewCodec(newRWC(input, output), UpstreamRole)
	defer c.Close()

	ex, err := c.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	if ex.Direction != exchange.Receive {
		t.Errorf("Direction = %v, want Receive", ex.Direction)
	}
	if ex.Status != 200 {
		t.Errorf("Status = %d, want 200", ex.Status)
	}
	if len(ex.Headers) != 2 {
		t.Fatalf("Headers len = %d, want 2", len(ex.Headers))
	}
	if string(ex.Body) != "hello" {
		t.Errorf("Body = %q, want %q", ex.Body, "hello")
	}
	if ex.Protocol != exchange.HTTP1 {
		t.Errorf("Protocol = %v, want HTTP1", ex.Protocol)
	}
	if len(ex.RawBytes) == 0 {
		t.Error("RawBytes is empty")
	}
}

func TestSendRequest_NoChanges_ZeroCopy(t *testing.T) {
	// Parse a request first via Next().
	input := "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n"
	clientBuf := &bytes.Buffer{}
	clientCodec := NewCodec(newRWC(input, clientBuf), ClientRole)
	defer clientCodec.Close()

	ex, err := clientCodec.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	// Send to upstream with no modifications.
	upstreamBuf := &bytes.Buffer{}
	upstreamCodec := NewCodec(newRWC("", upstreamBuf), UpstreamRole)
	defer upstreamCodec.Close()

	if err := upstreamCodec.Send(context.Background(), ex); err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	// The output should be exactly the original RawBytes (zero-copy).
	got := upstreamBuf.String()
	if got != input {
		t.Errorf("Send output:\n%q\nwant:\n%q", got, input)
	}
}

func TestSendResponse_NoChanges_ZeroCopy(t *testing.T) {
	input := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
	upstreamBuf := &bytes.Buffer{}
	upstreamCodec := NewCodec(newRWC(input, upstreamBuf), UpstreamRole)
	defer upstreamCodec.Close()

	ex, err := upstreamCodec.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	// Send back to client with no modifications.
	clientBuf := &bytes.Buffer{}
	clientCodec := NewCodec(newRWC("", clientBuf), ClientRole)
	defer clientCodec.Close()

	if err := clientCodec.Send(context.Background(), ex); err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	// The output should be RawBytes + body.
	got := clientBuf.String()
	want := input
	if got != want {
		t.Errorf("Send output:\n%q\nwant:\n%q", got, want)
	}
}

func TestSendRequest_HeaderChanged(t *testing.T) {
	input := "GET /path HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n"
	clientBuf := &bytes.Buffer{}
	clientCodec := NewCodec(newRWC(input, clientBuf), ClientRole)
	defer clientCodec.Close()

	ex, err := clientCodec.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	// Modify a header.
	ex.Headers[1] = exchange.KeyValue{Name: "Accept", Value: "application/json"}

	upstreamBuf := &bytes.Buffer{}
	upstreamCodec := NewCodec(newRWC("", upstreamBuf), UpstreamRole)
	defer upstreamCodec.Close()

	if err := upstreamCodec.Send(context.Background(), ex); err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	got := upstreamBuf.String()
	// Host should be preserved, Accept should be changed.
	if !strings.Contains(got, "Host: example.com") {
		t.Errorf("output missing unchanged Host header:\n%s", got)
	}
	if !strings.Contains(got, "Accept: application/json") {
		t.Errorf("output missing changed Accept header:\n%s", got)
	}
	if strings.Contains(got, "text/html") {
		t.Errorf("output still contains old Accept value:\n%s", got)
	}
}

func TestSendRequest_HeaderOWSPreserved(t *testing.T) {
	// Header with non-standard OWS: "X-Custom:  value  " (extra spaces).
	input := "GET /path HTTP/1.1\r\nHost: example.com\r\nX-Custom:  value  \r\n\r\n"
	clientBuf := &bytes.Buffer{}
	clientCodec := NewCodec(newRWC(input, clientBuf), ClientRole)
	defer clientCodec.Close()

	ex, err := clientCodec.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	// Don't change anything.
	upstreamBuf := &bytes.Buffer{}
	upstreamCodec := NewCodec(newRWC("", upstreamBuf), UpstreamRole)
	defer upstreamCodec.Close()

	if err := upstreamCodec.Send(context.Background(), ex); err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	got := upstreamBuf.String()
	// Should be exactly the original (zero-copy path).
	if got != input {
		t.Errorf("Send output:\n%q\nwant:\n%q", got, input)
	}
}

func TestSendResponse_BodyChanged_ContentLengthRecalculated(t *testing.T) {
	input := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
	upstreamBuf := &bytes.Buffer{}
	upstreamCodec := NewCodec(newRWC(input, upstreamBuf), UpstreamRole)
	defer upstreamCodec.Close()

	ex, err := upstreamCodec.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	// Modify body.
	ex.Body = []byte("hello world!")

	clientBuf := &bytes.Buffer{}
	clientCodec := NewCodec(newRWC("", clientBuf), ClientRole)
	defer clientCodec.Close()

	if err := clientCodec.Send(context.Background(), ex); err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	got := clientBuf.String()
	if !strings.Contains(got, "Content-Length: 12") {
		t.Errorf("output should have Content-Length: 12:\n%s", got)
	}
	if !strings.HasSuffix(got, "hello world!") {
		t.Errorf("output should end with modified body:\n%s", got)
	}
}

func TestSendResponse_BodyChanged_AutoContentLengthDisabled(t *testing.T) {
	input := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
	upstreamBuf := &bytes.Buffer{}
	upstreamCodec := NewCodec(newRWC(input, upstreamBuf), UpstreamRole)
	defer upstreamCodec.Close()

	ex, err := upstreamCodec.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	// Modify body and disable auto content-length.
	ex.Body = []byte("hello world!")
	ex.Metadata = map[string]any{"auto_content_length": false}

	clientBuf := &bytes.Buffer{}
	clientCodec := NewCodec(newRWC("", clientBuf), ClientRole)
	defer clientCodec.Close()

	if err := clientCodec.Send(context.Background(), ex); err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	got := clientBuf.String()
	// Content-Length should remain at 5 (original).
	if !strings.Contains(got, "Content-Length: 5") {
		t.Errorf("output should have original Content-Length: 5:\n%s", got)
	}
}

func TestKeepAlive_TwoRequests(t *testing.T) {
	input := "GET /first HTTP/1.1\r\nHost: example.com\r\n\r\n" +
		"GET /second HTTP/1.1\r\nHost: example.com\r\n\r\n"
	output := &bytes.Buffer{}
	c := NewCodec(newRWC(input, output), ClientRole)
	defer c.Close()

	// First request.
	ex1, err := c.Next(context.Background())
	if err != nil {
		t.Fatalf("First Next() error: %v", err)
	}
	if ex1.URL == nil || ex1.URL.Path != "/first" {
		t.Errorf("First URL = %v, want /first", ex1.URL)
	}
	streamID1 := ex1.StreamID

	// Second request.
	ex2, err := c.Next(context.Background())
	if err != nil {
		t.Fatalf("Second Next() error: %v", err)
	}
	if ex2.URL == nil || ex2.URL.Path != "/second" {
		t.Errorf("Second URL = %v, want /second", ex2.URL)
	}
	streamID2 := ex2.StreamID

	// StreamIDs must be different.
	if streamID1 == streamID2 {
		t.Errorf("StreamIDs should differ: %s == %s", streamID1, streamID2)
	}

	// Sequences should both be 0 (each request is a new stream).
	if ex1.Sequence != 0 || ex2.Sequence != 0 {
		t.Errorf("Sequences = (%d, %d), want (0, 0)", ex1.Sequence, ex2.Sequence)
	}
}

func TestConnectionClose_EOF(t *testing.T) {
	input := "GET /path HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
	output := &bytes.Buffer{}
	c := NewCodec(newRWC(input, output), ClientRole)
	defer c.Close()

	// First request succeeds.
	_, err := c.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	// Second call should return EOF.
	_, err = c.Next(context.Background())
	if err != io.EOF {
		t.Errorf("expected io.EOF, got %v", err)
	}
}

func TestHTTP10_DefaultClose(t *testing.T) {
	input := "GET /path HTTP/1.0\r\nHost: example.com\r\n\r\n"
	output := &bytes.Buffer{}
	c := NewCodec(newRWC(input, output), ClientRole)
	defer c.Close()

	_, err := c.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	// HTTP/1.0 defaults to close.
	_, err = c.Next(context.Background())
	if err != io.EOF {
		t.Errorf("expected io.EOF for HTTP/1.0 default close, got %v", err)
	}
}

func TestPassthrough_LargeBody(t *testing.T) {
	// Create a body larger than the threshold.
	bodySize := passthroughThreshold + 1000
	bodyData := bytes.Repeat([]byte("x"), bodySize)

	// Use net.Pipe for a more realistic scenario with large bodies.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Write the request in a goroutine.
	go func() {
		defer clientConn.Close()
		var buf bytes.Buffer
		buf.WriteString("POST /upload HTTP/1.1\r\n")
		buf.WriteString("Host: example.com\r\n")
		buf.WriteString("Content-Length: ")
		buf.WriteString(fmt.Sprintf("%d", bodySize))
		buf.WriteString("\r\n\r\n")
		buf.Write(bodyData)
		clientConn.Write(buf.Bytes())
	}()

	c := NewCodec(serverConn, ClientRole)
	defer c.Close()

	ex, err := c.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	// Body should be nil (passthrough mode).
	if ex.Body != nil {
		t.Errorf("Body should be nil in passthrough mode, got %d bytes", len(ex.Body))
	}

	// Opaque should have a bodyReader.
	opaque, ok := ex.Opaque.(*opaqueHTTP1)
	if !ok {
		t.Fatal("Opaque is not *opaqueHTTP1")
	}
	if opaque.bodyReader == nil {
		t.Fatal("bodyReader should be non-nil in passthrough mode")
	}

	// Verify we can read the full body from the bodyReader.
	allBody, err := io.ReadAll(opaque.bodyReader)
	if err != nil {
		t.Fatalf("reading bodyReader: %v", err)
	}
	if len(allBody) != bodySize {
		t.Errorf("bodyReader yielded %d bytes, want %d", len(allBody), bodySize)
	}
}

func TestStreamID_FlowID_Unique(t *testing.T) {
	input := "GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n" +
		"GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n"
	output := &bytes.Buffer{}
	c := NewCodec(newRWC(input, output), ClientRole)
	defer c.Close()

	ex1, err := c.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() 1 error: %v", err)
	}
	ex2, err := c.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() 2 error: %v", err)
	}

	if ex1.StreamID == ex2.StreamID {
		t.Error("StreamIDs should be unique across requests")
	}
	if ex1.FlowID == ex2.FlowID {
		t.Error("FlowIDs should be unique across exchanges")
	}
	if ex1.FlowID == ex1.StreamID {
		t.Error("FlowID should differ from StreamID")
	}
}

func TestUpgradeHint_WebSocket(t *testing.T) {
	input := "GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
	output := &bytes.Buffer{}
	c := NewCodec(newRWC(input, output), ClientRole)
	defer c.Close()

	_, err := c.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	if c.UpgradeHint() != UpgradeWebSocket {
		t.Errorf("UpgradeHint = %v, want UpgradeWebSocket", c.UpgradeHint())
	}
}

func TestUpgradeHint_GRPCWeb(t *testing.T) {
	input := "POST /service HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: 0\r\n\r\n"
	output := &bytes.Buffer{}
	c := NewCodec(newRWC(input, output), ClientRole)
	defer c.Close()

	_, err := c.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	if c.UpgradeHint() != UpgradeGRPCWeb {
		t.Errorf("UpgradeHint = %v, want UpgradeGRPCWeb", c.UpgradeHint())
	}
}

func TestUpgradeHint_SSE(t *testing.T) {
	input := "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"
	output := &bytes.Buffer{}
	c := NewCodec(newRWC(input, output), UpstreamRole)
	defer c.Close()

	_, err := c.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	if c.UpgradeHint() != UpgradeSSE {
		t.Errorf("UpgradeHint = %v, want UpgradeSSE", c.UpgradeHint())
	}
}

func TestClose_Idempotent(t *testing.T) {
	output := &bytes.Buffer{}
	rwc := newRWC("", output)
	c := NewCodec(rwc, ClientRole)

	if err := c.Close(); err != nil {
		t.Fatalf("first Close() error: %v", err)
	}
	if !rwc.closed {
		t.Error("underlying connection not closed")
	}

	// Second close should be no-op.
	if err := c.Close(); err != nil {
		t.Fatalf("second Close() error: %v", err)
	}
}

func TestSendRequest_AddHeader(t *testing.T) {
	input := "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n"
	clientBuf := &bytes.Buffer{}
	clientCodec := NewCodec(newRWC(input, clientBuf), ClientRole)
	defer clientCodec.Close()

	ex, err := clientCodec.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	// Add a new header.
	ex.Headers = append(ex.Headers, exchange.KeyValue{Name: "X-Added", Value: "new"})

	upstreamBuf := &bytes.Buffer{}
	upstreamCodec := NewCodec(newRWC("", upstreamBuf), UpstreamRole)
	defer upstreamCodec.Close()

	if err := upstreamCodec.Send(context.Background(), ex); err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	got := upstreamBuf.String()
	if !strings.Contains(got, "X-Added: new") {
		t.Errorf("output missing added header:\n%s", got)
	}
	if !strings.Contains(got, "Host: example.com") {
		t.Errorf("output missing original header:\n%s", got)
	}
}

func TestSendRequest_RemoveHeader(t *testing.T) {
	input := "GET /path HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n"
	clientBuf := &bytes.Buffer{}
	clientCodec := NewCodec(newRWC(input, clientBuf), ClientRole)
	defer clientCodec.Close()

	ex, err := clientCodec.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	// Remove Accept header.
	ex.Headers = ex.Headers[:1] // Keep only Host.

	upstreamBuf := &bytes.Buffer{}
	upstreamCodec := NewCodec(newRWC("", upstreamBuf), UpstreamRole)
	defer upstreamCodec.Close()

	if err := upstreamCodec.Send(context.Background(), ex); err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	got := upstreamBuf.String()
	if strings.Contains(got, "Accept") {
		t.Errorf("output should not contain removed header:\n%s", got)
	}
	if !strings.Contains(got, "Host: example.com") {
		t.Errorf("output missing retained header:\n%s", got)
	}
}

func TestSendRequest_BodyChanged_ContentLengthRecalculated(t *testing.T) {
	input := "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello"
	clientBuf := &bytes.Buffer{}
	clientCodec := NewCodec(newRWC(input, clientBuf), ClientRole)
	defer clientCodec.Close()

	ex, err := clientCodec.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	// Modify body.
	ex.Body = []byte("hello world!")

	upstreamBuf := &bytes.Buffer{}
	upstreamCodec := NewCodec(newRWC("", upstreamBuf), UpstreamRole)
	defer upstreamCodec.Close()

	if err := upstreamCodec.Send(context.Background(), ex); err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	got := upstreamBuf.String()
	if !strings.Contains(got, "Content-Length: 12") {
		t.Errorf("output should have Content-Length: 12:\n%s", got)
	}
	if !strings.HasSuffix(got, "hello world!") {
		t.Errorf("output should end with modified body:\n%s", got)
	}
}

func TestSendResponse_PassthroughBody(t *testing.T) {
	// Test sending a response with passthrough body via net.Pipe.
	bodySize := passthroughThreshold + 500
	bodyData := bytes.Repeat([]byte("y"), bodySize)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Write the response in a goroutine.
	go func() {
		defer clientConn.Close()
		var buf bytes.Buffer
		buf.WriteString("HTTP/1.1 200 OK\r\n")
		buf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", bodySize))
		buf.WriteString("\r\n")
		buf.Write(bodyData)
		clientConn.Write(buf.Bytes())
	}()

	upstreamCodec := NewCodec(serverConn, UpstreamRole)
	defer upstreamCodec.Close()

	ex, err := upstreamCodec.Next(context.Background())
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	// Should be in passthrough mode.
	if ex.Body != nil {
		t.Fatalf("Body should be nil in passthrough mode, got %d bytes", len(ex.Body))
	}

	// Send to a buffer (client side).
	outBuf := &bytes.Buffer{}
	clientCodec := NewCodec(newRWC("", outBuf), ClientRole)
	defer clientCodec.Close()

	if err := clientCodec.Send(context.Background(), ex); err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	got := outBuf.String()
	if !strings.Contains(got, "200 OK") {
		t.Errorf("output missing status line:\n%s", got[:100])
	}
	// Should contain full body.
	if !strings.HasSuffix(got, string(bodyData)) {
		t.Errorf("output body length mismatch, got %d total bytes", len(got))
	}
}

func TestSendRequest_MissingOpaque(t *testing.T) {
	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Protocol:  exchange.HTTP1,
	}

	upstreamBuf := &bytes.Buffer{}
	c := NewCodec(newRWC("", upstreamBuf), UpstreamRole)
	defer c.Close()

	err := c.Send(context.Background(), ex)
	if err == nil {
		t.Fatal("expected error for missing opaque data")
	}
}

func TestSendResponse_MissingOpaque(t *testing.T) {
	ex := &exchange.Exchange{
		Direction: exchange.Receive,
		Protocol:  exchange.HTTP1,
	}

	clientBuf := &bytes.Buffer{}
	c := NewCodec(newRWC("", clientBuf), ClientRole)
	defer c.Close()

	err := c.Send(context.Background(), ex)
	if err == nil {
		t.Fatal("expected error for missing opaque data")
	}
}
