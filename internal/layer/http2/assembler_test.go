package http2

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
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
	// Small body surfaces as msg.Body (memory track; mirrors HTTP/1.x
	// behavior — USK-631 precedent). BodyBuffer stays nil.
	if msg.BodyBuffer != nil {
		t.Errorf("BodyBuffer non-nil for small body, expected nil")
	}
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
	if msg.BodyBuffer != nil {
		t.Errorf("BodyBuffer non-nil for small trailed body, expected nil (memory track)")
	}
	if string(msg.Body) != "body" {
		t.Errorf("body = %q, want body", msg.Body)
	}
	if len(msg.Trailers) != 1 || msg.Trailers[0].Name != "x-trailer" || msg.Trailers[0].Value != "yes" {
		t.Errorf("trailers = %+v", msg.Trailers)
	}
}

// TestAssembler_BodyBufferMemoryMode verifies that bodies smaller than the
// configured spill threshold surface as msg.Body (memory track — the
// assembler materializes the buffer to bytes and releases it, matching
// the HTTP/1.x USK-631 precedent).
func TestAssembler_BodyBufferMemoryMode(t *testing.T) {
	// Default threshold is 10 MiB — send 1 MiB of body to stay well below.
	const bodySize = 1 << 20

	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "x"},
		{Name: ":path", Value: "/mem"},
	}
	chunk := make([]byte, int(frame.DefaultMaxFrameSize))
	for i := range chunk {
		chunk[i] = 'm'
	}
	totalChunks := bodySize / len(chunk)

	peerErr := make(chan error, 1)
	go func() {
		if err := peer.wr.WriteSettings(nil); err != nil {
			peerErr <- err
			return
		}
		go func() {
			for {
				if _, err := peer.rd.ReadFrame(); err != nil {
					return
				}
			}
		}()
		encoded := peer.encoder.Encode(headers)
		if err := peer.wr.WriteHeaders(1, false, true, encoded); err != nil {
			peerErr <- err
			return
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
	if msg.BodyBuffer != nil {
		t.Errorf("BodyBuffer non-nil below threshold; expected msg.Body materialization")
	}
	if int64(len(msg.Body)) != int64(bodySize) {
		t.Errorf("msg.Body len = %d, want %d", len(msg.Body), bodySize)
	}
}

// TestAssembler_PromoteToFileAtThreshold verifies that a body crossing the
// configured spill threshold promotes to a file-backed BodyBuffer.
func TestAssembler_PromoteToFileAtThreshold(t *testing.T) {
	// Use a small threshold so we don't have to stream 10 MiB through
	// net.Pipe. 64 KiB works well against a 16 KiB default max frame size.
	const threshold = 64 << 10

	l, peer, cleanup := startServerLayer(t, WithBodySpillThreshold(threshold))
	defer cleanup()
	peer.consumePeerSettings(t)

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "x"},
		{Name: ":path", Value: "/spill"},
	}
	chunk := make([]byte, int(frame.DefaultMaxFrameSize))
	for i := range chunk {
		chunk[i] = 's'
	}
	// Send 5× threshold to guarantee promotion well past the edge.
	const totalBytes = threshold * 5
	totalChunks := totalBytes / len(chunk)

	peerErr := make(chan error, 1)
	go func() {
		if err := peer.wr.WriteSettings(nil); err != nil {
			peerErr <- err
			return
		}
		go func() {
			for {
				if _, err := peer.rd.ReadFrame(); err != nil {
					return
				}
			}
		}()
		encoded := peer.encoder.Encode(headers)
		if err := peer.wr.WriteHeaders(1, false, true, encoded); err != nil {
			peerErr <- err
			return
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
	if msg.BodyBuffer == nil {
		t.Fatal("BodyBuffer = nil, want file-backed buffer after threshold crossing")
	}
	if !msg.BodyBuffer.IsFileBacked() {
		t.Errorf("BodyBuffer not file-backed after %d > %d threshold (len=%d)",
			totalBytes, threshold, msg.BodyBuffer.Len())
	}
	if got, want := msg.BodyBuffer.Len(), int64(totalBytes); got != want {
		t.Errorf("BodyBuffer.Len = %d, want %d", got, want)
	}
}

// TestAssembler_MaxBodySizeStreamError verifies that a body exceeding
// MaxBodySize surfaces as a *layer.StreamError on the Channel and drops the
// stream without corrupting the connection. The peer splits the body into
// DEFAULT_MAX_FRAME_SIZE chunks; once cumulative Writes cross the cap the
// assembler surfaces ErrorInternalError via Channel.Next.
func TestAssembler_MaxBodySizeStreamError(t *testing.T) {
	// Small cap chosen to fit a handful of default 16 KiB DATA frames.
	const maxBody = 32 << 10

	l, peer, cleanup := startServerLayer(t,
		WithBodySpillThreshold(16<<10),
		WithMaxBodySize(maxBody),
	)
	defer cleanup()
	peer.consumePeerSettings(t)

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "x"},
		{Name: ":path", Value: "/toobig"},
	}
	chunk := make([]byte, int(frame.DefaultMaxFrameSize))
	for i := range chunk {
		chunk[i] = 'x'
	}
	// Stream four 16 KiB DATA frames = 64 KiB — double the cap.
	const numChunks = 4

	peerErr := make(chan error, 1)
	go func() {
		if err := peer.wr.WriteSettings(nil); err != nil {
			peerErr <- err
			return
		}
		go func() {
			for {
				if _, err := peer.rd.ReadFrame(); err != nil {
					return
				}
			}
		}()
		encoded := peer.encoder.Encode(headers)
		if err := peer.wr.WriteHeaders(1, false, true, encoded); err != nil {
			peerErr <- err
			return
		}
		for i := 0; i < numChunks; i++ {
			// Late DATA frames may race with the layer's RST_STREAM after
			// the cap is crossed; ignore net.ErrClosed / io.EOF on write
			// so the race does not spuriously fail the test.
			if err := peer.wr.WriteData(1, false, chunk); err != nil {
				peerErr <- nil
				return
			}
		}
		_ = peer.wr.WriteData(1, true, nil)
		peerErr <- nil
	}()

	ch := waitForChannel(t, l, 5*time.Second)
	if ch == nil {
		t.Fatal("no channel emitted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := ch.Next(ctx)
	if err == nil {
		t.Fatal("Next: want error (body exceeds max size), got nil")
	}
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("Next err = %T %v, want *layer.StreamError", err, err)
	}
	if se.Code != layer.ErrorInternalError {
		t.Errorf("StreamError.Code = %v, want ErrorInternalError", se.Code)
	}
}

// TestAssembler_MaxBodySizeStreamError_MemoryMode verifies that the
// MaxBodySize cap is enforced even before a file-mode promotion has
// occurred. With spillThreshold > maxBody, PromoteToFile will never be
// attempted (Len() stays below threshold as the writeBody guard fires
// first), so cap enforcement must come from the assembler-level check —
// not from bodybuf's own maxSize enforcement which is set only at
// NewFile/PromoteToFile time. Without the assembler-level guard, a
// malicious peer could exhaust temp-dir space (causing PromoteToFile to
// fail silently) and then flood memory unbounded via DATA frames
// (USK-632 security review S-1, CWE-770).
func TestAssembler_MaxBodySizeStreamError_MemoryMode(t *testing.T) {
	// Invariants: spillThreshold > maxBody so promotion never triggers
	// before the cap. maxBody is sized to admit a few default 16 KiB
	// DATA frames before overflow.
	const maxBody = 32 << 10
	const threshold = 128 << 10

	l, peer, cleanup := startServerLayer(t,
		WithBodySpillThreshold(threshold),
		WithMaxBodySize(maxBody),
	)
	defer cleanup()
	peer.consumePeerSettings(t)

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "x"},
		{Name: ":path", Value: "/mem-toobig"},
	}
	chunk := make([]byte, int(frame.DefaultMaxFrameSize))
	for i := range chunk {
		chunk[i] = 'm'
	}
	// Four 16 KiB frames = 64 KiB, double the maxBody cap and well below
	// the 128 KiB spill threshold.
	const numChunks = 4

	peerErr := make(chan error, 1)
	go func() {
		if err := peer.wr.WriteSettings(nil); err != nil {
			peerErr <- err
			return
		}
		go func() {
			for {
				if _, err := peer.rd.ReadFrame(); err != nil {
					return
				}
			}
		}()
		encoded := peer.encoder.Encode(headers)
		if err := peer.wr.WriteHeaders(1, false, true, encoded); err != nil {
			peerErr <- err
			return
		}
		for i := 0; i < numChunks; i++ {
			if err := peer.wr.WriteData(1, false, chunk); err != nil {
				peerErr <- nil
				return
			}
		}
		_ = peer.wr.WriteData(1, true, nil)
		peerErr <- nil
	}()

	ch := waitForChannel(t, l, 5*time.Second)
	if ch == nil {
		t.Fatal("no channel emitted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := ch.Next(ctx)
	if err == nil {
		t.Fatal("Next: want error (memory-mode body exceeds max size), got nil")
	}
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("Next err = %T %v, want *layer.StreamError", err, err)
	}
	if se.Code != layer.ErrorInternalError {
		t.Errorf("StreamError.Code = %v, want ErrorInternalError", se.Code)
	}
}

// TestAssembler_HeadersOnlyNoBodyBuffer verifies that a request with no DATA
// frames produces an envelope with both Body and BodyBuffer nil.
func TestAssembler_HeadersOnlyNoBodyBuffer(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "x"},
		{Name: ":path", Value: "/empty"},
	}
	env := driveOneRequest(t, peer, l, 1, headers, nil)
	msg := env.Message.(*envelope.HTTPMessage)
	if msg.Body != nil {
		t.Errorf("Body = %v, want nil (headers-only)", msg.Body)
	}
	if msg.BodyBuffer != nil {
		t.Errorf("BodyBuffer = %v, want nil (headers-only; no DATA frames)", msg.BodyBuffer)
	}
}

// TestAssembler_TrailersPreservedWithFileBody verifies that trailers are
// still projected onto msg.Trailers when the body has spilled to disk —
// previously passthrough mode silently dropped trailers (fixed by USK-632).
func TestAssembler_TrailersPreservedWithFileBody(t *testing.T) {
	const threshold = 32 << 10

	l, peer, cleanup := startServerLayer(t, WithBodySpillThreshold(threshold))
	defer cleanup()
	peer.consumePeerSettings(t)

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "x"},
		{Name: ":path", Value: "/bigtrailer"},
	}
	chunk := make([]byte, int(frame.DefaultMaxFrameSize))
	for i := range chunk {
		chunk[i] = 'x'
	}
	// 4× threshold forces promotion to file.
	const totalBytes = threshold * 4
	totalChunks := totalBytes / len(chunk)

	peerErr := make(chan error, 1)
	go func() {
		if err := peer.wr.WriteSettings(nil); err != nil {
			peerErr <- err
			return
		}
		go func() {
			for {
				if _, err := peer.rd.ReadFrame(); err != nil {
					return
				}
			}
		}()
		encoded := peer.encoder.Encode(headers)
		if err := peer.wr.WriteHeaders(1, false, true, encoded); err != nil {
			peerErr <- err
			return
		}
		for i := 0; i < totalChunks; i++ {
			if err := peer.wr.WriteData(1, false, chunk); err != nil {
				peerErr <- err
				return
			}
		}
		// Send trailers (END_STREAM on trailer HEADERS, not on DATA).
		trailerBlock := peer.encoder.Encode([]hpack.HeaderField{
			{Name: "x-checksum", Value: "abc123"},
		})
		if err := peer.wr.WriteHeaders(1, true, true, trailerBlock); err != nil {
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
	if msg.BodyBuffer == nil {
		t.Fatal("BodyBuffer = nil, expected file-backed buffer for large body")
	}
	if !msg.BodyBuffer.IsFileBacked() {
		t.Errorf("BodyBuffer not file-backed (len=%d, threshold=%d)",
			msg.BodyBuffer.Len(), threshold)
	}
	if len(msg.Trailers) != 1 {
		t.Fatalf("Trailers = %+v, want 1 entry", msg.Trailers)
	}
	if msg.Trailers[0].Name != "x-checksum" || msg.Trailers[0].Value != "abc123" {
		t.Errorf("Trailers[0] = %+v, want {x-checksum, abc123}", msg.Trailers[0])
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
