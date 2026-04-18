package http2

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// driveOneRequest sends a single request through the peer (HEADERS+optional
// DATA(END_STREAM)) and returns the envelope received on the server side.
func driveOneRequest(t *testing.T, peer *h2Peer, l *Layer, streamID uint32, headers []hpack.HeaderField, body []byte) *envelope.Envelope {
	t.Helper()
	encoded := peer.encoder.Encode(headers)
	headersEndStream := body == nil
	if err := peer.wr.WriteHeaders(streamID, headersEndStream, true, encoded); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
	if body != nil {
		if err := peer.wr.WriteData(streamID, true, body); err != nil {
			t.Fatalf("WriteData: %v", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ch := waitForChannel(t, l, time.Second)
	if ch == nil {
		t.Fatal("no channel")
	}
	env, err := ch.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	return env
}

func TestAssembler_HeadersOnlyMessage(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/foo?q=1"},
		{Name: "user-agent", Value: "test"},
	}
	env := driveOneRequest(t, peer, l, 1, headers, nil)
	msg := env.Message.(*envelope.HTTPMessage)

	if msg.Method != "GET" {
		t.Errorf("method = %q", msg.Method)
	}
	if msg.Scheme != "https" {
		t.Errorf("scheme = %q", msg.Scheme)
	}
	if msg.Authority != "example.com" {
		t.Errorf("authority = %q", msg.Authority)
	}
	if msg.Path != "/foo" {
		t.Errorf("path = %q", msg.Path)
	}
	if msg.RawQuery != "q=1" {
		t.Errorf("rawQuery = %q", msg.RawQuery)
	}
	if len(msg.Headers) != 1 || msg.Headers[0].Name != "user-agent" {
		t.Errorf("headers = %+v", msg.Headers)
	}
	if env.Sequence != 0 {
		t.Errorf("sequence = %d, want 0", env.Sequence)
	}
	if env.Direction != envelope.Send {
		t.Errorf("direction = %s, want send", env.Direction)
	}
	if len(env.Raw) == 0 {
		t.Errorf("raw bytes empty")
	}
}

func TestAssembler_HeadersDataEndStream(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/upload"},
	}
	body := []byte("hello world")
	env := driveOneRequest(t, peer, l, 1, headers, body)
	msg := env.Message.(*envelope.HTTPMessage)
	if string(msg.Body) != "hello world" {
		t.Errorf("body = %q, want hello world", msg.Body)
	}
}

func TestAssembler_DuplicatePseudoHeader(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "x"},
		{Name: ":path", Value: "/"},
		{Name: ":method", Value: "POST"}, // duplicate
	}
	env := driveOneRequest(t, peer, l, 1, headers, nil)
	msg := env.Message.(*envelope.HTTPMessage)
	hasDup := false
	for _, a := range msg.Anomalies {
		if a.Type == envelope.H2DuplicatePseudoHeader {
			hasDup = true
		}
	}
	if !hasDup {
		t.Errorf("expected H2DuplicatePseudoHeader anomaly, got %+v", msg.Anomalies)
	}
}

func TestAssembler_PseudoAfterRegular(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "x"},
		{Name: "x-custom", Value: "1"},
		{Name: ":path", Value: "/"}, // pseudo after regular
	}
	env := driveOneRequest(t, peer, l, 1, headers, nil)
	msg := env.Message.(*envelope.HTTPMessage)
	hasOrder := false
	for _, a := range msg.Anomalies {
		if a.Type == envelope.H2PseudoHeaderAfterRegular {
			hasOrder = true
		}
	}
	if !hasOrder {
		t.Errorf("expected H2PseudoHeaderAfterRegular anomaly, got %+v", msg.Anomalies)
	}
}

func TestAssembler_MultipleCookieHeaders(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "x"},
		{Name: ":path", Value: "/"},
		{Name: "cookie", Value: "a=1"},
		{Name: "cookie", Value: "b=2"},
	}
	env := driveOneRequest(t, peer, l, 1, headers, nil)
	msg := env.Message.(*envelope.HTTPMessage)
	count := 0
	for _, h := range msg.Headers {
		if h.Name == "cookie" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("cookie count = %d, want 2 (headers: %+v)", count, msg.Headers)
	}
}

func TestAssembler_ConnectionSpecificHeaderFlagged(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "x"},
		{Name: ":path", Value: "/"},
		{Name: "connection", Value: "close"},
	}
	env := driveOneRequest(t, peer, l, 1, headers, nil)
	msg := env.Message.(*envelope.HTTPMessage)

	// Header preserved.
	hasConn := false
	for _, h := range msg.Headers {
		if h.Name == "connection" {
			hasConn = true
		}
	}
	if !hasConn {
		t.Errorf("connection header not preserved: %+v", msg.Headers)
	}

	// Anomaly attached.
	hasAnom := false
	for _, a := range msg.Anomalies {
		if a.Type == envelope.H2ConnectionSpecificHeader {
			hasAnom = true
		}
	}
	if !hasAnom {
		t.Errorf("expected H2ConnectionSpecificHeader anomaly, got %+v", msg.Anomalies)
	}
}

func TestAssembler_TrailersAttached(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	// HEADERS (no end_stream) + DATA (no end_stream) + HEADERS (trailers, end_stream).
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "x"},
		{Name: ":path", Value: "/"},
	}
	encoded := peer.encoder.Encode(headers)
	if err := peer.wr.WriteHeaders(1, false, true, encoded); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
	if err := peer.wr.WriteData(1, false, []byte("body")); err != nil {
		t.Fatalf("WriteData: %v", err)
	}
	trailerBlock := peer.encoder.Encode([]hpack.HeaderField{
		{Name: "x-trailer", Value: "yes"},
	})
	if err := peer.wr.WriteHeaders(1, true, true, trailerBlock); err != nil {
		t.Fatalf("WriteHeaders trailers: %v", err)
	}

	ch := waitForChannel(t, l, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	env, err := ch.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	msg := env.Message.(*envelope.HTTPMessage)
	if string(msg.Body) != "body" {
		t.Errorf("body = %q, want body", msg.Body)
	}
	if len(msg.Trailers) != 1 || msg.Trailers[0].Name != "x-trailer" || msg.Trailers[0].Value != "yes" {
		t.Errorf("trailers = %+v", msg.Trailers)
	}
}

func TestAssembler_PassthroughThreshold(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large body test in short mode")
	}
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	// Run the entire peer-side I/O from a goroutine since net.Pipe is
	// unbuffered and the layer reads concurrently.
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "x"},
		{Name: ":path", Value: "/big"},
	}
	chunkSize := int(frame.DefaultMaxFrameSize)
	totalChunks := (12 * 1024 * 1024) / chunkSize

	peerErr := make(chan error, 1)
	go func() {
		// Initial SETTINGS from peer + ACK exchange so the layer is happy.
		if err := peer.wr.WriteSettings(nil); err != nil {
			peerErr <- err
			return
		}
		// Drain frames coming back (settings ACK + window updates).
		go func() {
			for {
				_, err := peer.rd.ReadFrame()
				if err != nil {
					return
				}
			}
		}()
		encoded := peer.encoder.Encode(headers)
		if err := peer.wr.WriteHeaders(1, false, true, encoded); err != nil {
			peerErr <- err
			return
		}
		chunk := make([]byte, chunkSize)
		for i := range chunk {
			chunk[i] = 'a'
		}
		for i := 0; i < totalChunks; i++ {
			if err := peer.wr.WriteData(1, false, chunk); err != nil {
				peerErr <- err
				return
			}
		}
		if err := peer.wr.WriteData(1, true, nil); err != nil {
			peerErr <- err
			return
		}
		peerErr <- nil
	}()

	ch := waitForChannel(t, l, 5*time.Second)
	if ch == nil {
		t.Fatal("no channel emitted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	env, err := ch.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v (lastReaderErr=%v)", err, l.LastReaderError())
	}
	msg := env.Message.(*envelope.HTTPMessage)
	if msg.BodyStream == nil {
		t.Fatalf("expected BodyStream != nil for passthrough mode (Body=%d bytes)", len(msg.Body))
	}
	if msg.Body != nil {
		t.Errorf("Body should be nil in passthrough mode, got %d bytes", len(msg.Body))
	}

	n, err := io.Copy(io.Discard, msg.BodyStream)
	if err != nil {
		t.Fatalf("io.Copy body: %v", err)
	}
	if n < passthroughThreshold {
		t.Errorf("body copied only %d bytes, want >= %d", n, passthroughThreshold)
	}
}

func TestSplitPath(t *testing.T) {
	cases := []struct {
		in          string
		path, query string
		hasQuestion bool
	}{
		{"/foo", "/foo", "", false},
		{"/foo?bar", "/foo", "bar", true},
		{"/foo?a=1&b=2", "/foo", "a=1&b=2", true},
		{"/", "/", "", false},
		{"/?", "/", "", true},
	}
	for _, c := range cases {
		p, q := splitPath(c.in)
		if p != c.path || q != c.query {
			t.Errorf("splitPath(%q) = (%q, %q), want (%q, %q)", c.in, p, q, c.path, c.query)
		}
	}
}

func TestSplitHeaders_ResponseStatus(t *testing.T) {
	decoded := []hpack.HeaderField{
		{Name: ":status", Value: "418"},
		{Name: "content-type", Value: "text/plain"},
	}
	msg, _ := buildHTTPMessage(decoded, envelope.Receive)
	if msg.Status != 418 {
		t.Errorf("status = %d, want 418", msg.Status)
	}
	if len(msg.Headers) != 1 {
		t.Errorf("headers = %+v", msg.Headers)
	}
}
