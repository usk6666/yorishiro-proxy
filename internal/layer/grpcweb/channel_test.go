package grpcweb

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// mockChannel is a programmable layer.Channel used to drive both the
// http1-style (single envelope, then EOF) and aggregator-style (multiple
// envelopes) inner Channels.
type mockChannel struct {
	streamID string

	mu      sync.Mutex
	queue   []*envelope.Envelope // envelopes Next will return in order
	queErr  []error              // optional terminal error after queue drains (one entry)
	sent    []*envelope.Envelope // captures Send calls
	sendErr error

	closed   bool
	doneCh   chan struct{}
	doneOnce sync.Once
}

func newMockChannel(streamID string, queue ...*envelope.Envelope) *mockChannel {
	return &mockChannel{
		streamID: streamID,
		queue:    queue,
		doneCh:   make(chan struct{}),
	}
}

func (m *mockChannel) StreamID() string { return m.streamID }
func (m *mockChannel) Next(ctx context.Context) (*envelope.Envelope, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.queue) == 0 {
		if len(m.queErr) > 0 {
			err := m.queErr[0]
			m.queErr = m.queErr[1:]
			return nil, err
		}
		return nil, io.EOF
	}
	out := m.queue[0]
	m.queue = m.queue[1:]
	return out, nil
}

func (m *mockChannel) Send(ctx context.Context, env *envelope.Envelope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sent = append(m.sent, env)
	return nil
}

func (m *mockChannel) Close() error {
	m.doneOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		m.mu.Unlock()
		close(m.doneCh)
	})
	return nil
}

func (m *mockChannel) Closed() <-chan struct{} { return m.doneCh }

func (m *mockChannel) Err() error { return nil }

// --- Helpers ---

func mustHTTPRequestEnv(streamID string, headers []envelope.KeyValue, body []byte, path string) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  streamID,
		Sequence:  0,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method:  "POST",
			Path:    path,
			Headers: headers,
			Body:    body,
		},
	}
}

func mustHTTPResponseEnv(streamID string, headers []envelope.KeyValue, body []byte, status int) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  streamID,
		Sequence:  0,
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Status:       status,
			StatusReason: "OK",
			Headers:      headers,
			Body:         body,
		},
	}
}

// drainEnvelopes pulls envelopes via Next until ctx-aware EOF is returned or
// max envelopes have been read.
func drainEnvelopes(t *testing.T, ch layer.Channel, max int) []*envelope.Envelope {
	t.Helper()
	out := []*envelope.Envelope{}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for i := 0; i < max; i++ {
		env, err := ch.Next(ctx)
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("Next() error at i=%d: %v", i, err)
		}
		out = append(out, env)
	}
	return out
}

// --- Acceptance: round-trip over http1-style (single inbound HTTPMessage) ---

func TestRoundTrip_BinaryHTTP1Style(t *testing.T) {
	// Server-side: inner emits one Send-direction HTTPMessage (the request)
	// and then EOF. We verify Start + Data + (no End for request) emission.
	payload := []byte("hello-grpcweb")
	body := EncodeFrame(false, false, payload)

	headers := []envelope.KeyValue{
		{Name: "content-type", Value: "application/grpc-web+proto"},
		{Name: "x-custom-meta", Value: "abc"},
		{Name: ":authority", Value: "example.test"},
		{Name: "grpc-encoding", Value: "identity"},
		{Name: "grpc-accept-encoding", Value: "gzip, identity"},
		{Name: "grpc-timeout", Value: "5S"},
	}
	in := mustHTTPRequestEnv("s1", headers, body, "/pkg.Svc/Method")

	mock := newMockChannel("s1", in)
	ch := Wrap(mock, RoleServer)

	envs := drainEnvelopes(t, ch, 4)
	if len(envs) != 2 {
		t.Fatalf("got %d envelopes, want 2 (Start + 1 Data)", len(envs))
	}

	start, ok := envs[0].Message.(*envelope.GRPCStartMessage)
	if !ok {
		t.Fatalf("envs[0].Message = %T, want *GRPCStartMessage", envs[0].Message)
	}
	if start.Service != "pkg.Svc" || start.Method != "Method" {
		t.Errorf("Service/Method = %q/%q, want pkg.Svc/Method", start.Service, start.Method)
	}
	if start.ContentType != "application/grpc-web+proto" {
		t.Errorf("ContentType = %q", start.ContentType)
	}
	if start.Encoding != "identity" {
		t.Errorf("Encoding = %q", start.Encoding)
	}
	if got := strings.Join(start.AcceptEncoding, ","); got != "gzip,identity" {
		t.Errorf("AcceptEncoding = %v", start.AcceptEncoding)
	}
	if start.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", start.Timeout)
	}
	// D7 strip: the four control headers + the pseudo-header should not be in Metadata
	if hasHeader(start.Metadata, "content-type") ||
		hasHeader(start.Metadata, "grpc-encoding") ||
		hasHeader(start.Metadata, "grpc-accept-encoding") ||
		hasHeader(start.Metadata, "grpc-timeout") ||
		hasHeader(start.Metadata, ":authority") {
		t.Errorf("Metadata leaked stripped header: %v", start.Metadata)
	}
	// Custom metadata preserved with original casing/order.
	if !hasHeader(start.Metadata, "x-custom-meta") {
		t.Errorf("Metadata missing x-custom-meta: %v", start.Metadata)
	}

	// D8: emitted envelope.Protocol == ProtocolGRPCWeb
	if envs[0].Protocol != envelope.ProtocolGRPCWeb {
		t.Errorf("envs[0].Protocol = %q, want %q", envs[0].Protocol, envelope.ProtocolGRPCWeb)
	}
	// Message.Protocol() returns ProtocolGRPC (intentional asymmetry)
	if start.Protocol() != envelope.ProtocolGRPC {
		t.Errorf("start.Protocol() = %q, want %q", start.Protocol(), envelope.ProtocolGRPC)
	}

	// Direction propagated.
	if envs[0].Direction != envelope.Send {
		t.Errorf("envs[0].Direction = %v", envs[0].Direction)
	}
	// FlowID is fresh, Sequence monotonic.
	if envs[0].Sequence != 0 || envs[1].Sequence != 1 {
		t.Errorf("Sequence = %d,%d; want 0,1", envs[0].Sequence, envs[1].Sequence)
	}
	if envs[0].FlowID == envs[1].FlowID {
		t.Errorf("FlowID not unique: %q", envs[0].FlowID)
	}
	if envs[0].StreamID != "s1" {
		t.Errorf("StreamID = %q", envs[0].StreamID)
	}

	data, ok := envs[1].Message.(*envelope.GRPCDataMessage)
	if !ok {
		t.Fatalf("envs[1].Message = %T", envs[1].Message)
	}
	if !bytes.Equal(data.Payload, payload) {
		t.Errorf("Payload = %q, want %q", data.Payload, payload)
	}
	if data.Compressed {
		t.Errorf("Compressed = true, want false")
	}
	if data.Service != "pkg.Svc" {
		t.Errorf("data.Service = %q", data.Service)
	}
	// Raw is binary 5-byte prefix + payload.
	if !bytes.Equal(envs[1].Raw, body) {
		t.Errorf("Data Raw = %x, want %x", envs[1].Raw, body)
	}
	// Start envelope has no Raw (belongs to inner HTTPMessage).
	if len(envs[0].Raw) != 0 {
		t.Errorf("Start envelope Raw should be nil/empty, got %d bytes", len(envs[0].Raw))
	}
}

// --- Acceptance: aggregator-style inner producing response with embedded trailer ---

func TestRoundTrip_BinaryAggregatorStyleResponse(t *testing.T) {
	payload := []byte("response-msg")
	trailer := []byte("grpc-status: 0\r\ngrpc-message: OK\r\n")

	body := append([]byte{}, EncodeFrame(false, false, payload)...)
	body = append(body, EncodeFrame(true, false, trailer)...)

	headers := []envelope.KeyValue{
		{Name: "content-type", Value: "application/grpc-web+proto"},
		{Name: "x-trace", Value: "abc-123"},
	}
	in := mustHTTPResponseEnv("s2", headers, body, 200)

	mock := newMockChannel("s2", in)
	ch := Wrap(mock, RoleClient)

	envs := drainEnvelopes(t, ch, 5)
	if len(envs) != 3 {
		t.Fatalf("got %d envelopes, want 3 (Start+Data+End)", len(envs))
	}

	if _, ok := envs[0].Message.(*envelope.GRPCStartMessage); !ok {
		t.Fatalf("envs[0] = %T", envs[0].Message)
	}
	if _, ok := envs[1].Message.(*envelope.GRPCDataMessage); !ok {
		t.Fatalf("envs[1] = %T", envs[1].Message)
	}
	end, ok := envs[2].Message.(*envelope.GRPCEndMessage)
	if !ok {
		t.Fatalf("envs[2] = %T", envs[2].Message)
	}
	if end.Status != 0 {
		t.Errorf("end.Status = %d, want 0", end.Status)
	}
	if end.Message != "OK" {
		t.Errorf("end.Message = %q, want OK", end.Message)
	}
	// All envelopes carry Direction=Receive (response side).
	for i, env := range envs {
		if env.Direction != envelope.Receive {
			t.Errorf("envs[%d].Direction = %v, want Receive", i, env.Direction)
		}
		if env.Protocol != envelope.ProtocolGRPCWeb {
			t.Errorf("envs[%d].Protocol = %q", i, env.Protocol)
		}
	}
}

// --- Acceptance: base64 wire round-trip ---

func TestRoundTrip_Base64Response(t *testing.T) {
	payload := []byte("base64-response")
	trailer := []byte("grpc-status: 0\r\n")

	binary := append([]byte{}, EncodeFrame(false, false, payload)...)
	binary = append(binary, EncodeFrame(true, false, trailer)...)
	body := EncodeBase64Body(binary)

	headers := []envelope.KeyValue{
		{Name: "content-type", Value: "application/grpc-web-text+proto"},
	}
	in := mustHTTPResponseEnv("s3", headers, body, 200)

	mock := newMockChannel("s3", in)
	ch := Wrap(mock, RoleClient)

	envs := drainEnvelopes(t, ch, 5)
	if len(envs) != 3 {
		t.Fatalf("got %d envelopes, want 3", len(envs))
	}

	data := envs[1].Message.(*envelope.GRPCDataMessage)
	if !bytes.Equal(data.Payload, payload) {
		t.Errorf("Payload = %q", data.Payload)
	}
	// For base64 wire, Envelope.Raw is kept in its base64-encoded form.
	if len(envs[1].Raw) == 0 {
		t.Fatalf("Data Raw should be non-empty")
	}
	// Re-decoding the per-frame base64 Raw should give the binary frame
	// bytes for that message.
	rawBinary, err := decodeBase64(envs[1].Raw)
	if err != nil {
		t.Fatalf("decode per-frame base64 Raw: %v", err)
	}
	wantBinary := EncodeFrame(false, false, payload)
	if !bytes.Equal(rawBinary, wantBinary) {
		t.Errorf("base64-decoded Data Raw = %x, want %x", rawBinary, wantBinary)
	}
	// The trailer envelope's Raw is also base64-encoded.
	rawTrailer, err := decodeBase64(envs[2].Raw)
	if err != nil {
		t.Fatalf("decode trailer base64 Raw: %v", err)
	}
	wantTrailer := EncodeFrame(true, false, trailer)
	if !bytes.Equal(rawTrailer, wantTrailer) {
		t.Errorf("base64-decoded Trailer Raw = %x, want %x", rawTrailer, wantTrailer)
	}
}

// --- Empty-body request → Start only ---

func TestEmptyRequestBody_StartOnly(t *testing.T) {
	headers := []envelope.KeyValue{
		{Name: "content-type", Value: "application/grpc-web+proto"},
	}
	in := mustHTTPRequestEnv("s4", headers, nil, "/svc/m")
	mock := newMockChannel("s4", in)
	ch := Wrap(mock, RoleServer)

	envs := drainEnvelopes(t, ch, 5)
	if len(envs) != 1 {
		t.Fatalf("got %d envelopes, want 1 (Start only)", len(envs))
	}
	if _, ok := envs[0].Message.(*envelope.GRPCStartMessage); !ok {
		t.Fatalf("envs[0] = %T", envs[0].Message)
	}
}

// --- Trailers-only response: Start + End, no Data ---

func TestTrailersOnlyResponse(t *testing.T) {
	trailer := []byte("grpc-status: 13\r\ngrpc-message: internal\r\n")
	body := EncodeFrame(true, false, trailer)
	headers := []envelope.KeyValue{
		{Name: "content-type", Value: "application/grpc-web+proto"},
	}
	in := mustHTTPResponseEnv("s5", headers, body, 200)
	mock := newMockChannel("s5", in)
	ch := Wrap(mock, RoleClient)

	envs := drainEnvelopes(t, ch, 5)
	if len(envs) != 2 {
		t.Fatalf("got %d envelopes, want 2 (Start + End)", len(envs))
	}
	end := envs[1].Message.(*envelope.GRPCEndMessage)
	if end.Status != 13 || end.Message != "internal" {
		t.Errorf("end status/message = %d/%q", end.Status, end.Message)
	}
}

// --- Compressed (gzip) round-trip ---

func TestGzipRoundTrip(t *testing.T) {
	original := []byte("compressed payload data")
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	if _, err := gw.Write(original); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	gw.Close()
	body := EncodeFrame(false, true, gz.Bytes())

	headers := []envelope.KeyValue{
		{Name: "content-type", Value: "application/grpc-web+proto"},
		{Name: "grpc-encoding", Value: "gzip"},
	}
	in := mustHTTPResponseEnv("s6", headers, body, 200)
	mock := newMockChannel("s6", in)
	ch := Wrap(mock, RoleClient)

	envs := drainEnvelopes(t, ch, 5)
	if len(envs) != 2 {
		t.Fatalf("got %d envelopes", len(envs))
	}
	data := envs[1].Message.(*envelope.GRPCDataMessage)
	if !data.Compressed {
		t.Errorf("Compressed flag not propagated")
	}
	if !bytes.Equal(data.Payload, original) {
		t.Errorf("Payload = %q, want %q (decompressed)", data.Payload, original)
	}
	if data.WireLength != uint32(len(gz.Bytes())) {
		t.Errorf("WireLength = %d, want %d", data.WireLength, len(gz.Bytes()))
	}
}

// --- Unsupported grpc-encoding produces StreamError ---

func TestUnsupportedEncoding_StreamError(t *testing.T) {
	body := EncodeFrame(false, true, []byte("\x00\x01\x02"))
	headers := []envelope.KeyValue{
		{Name: "content-type", Value: "application/grpc-web+proto"},
		{Name: "grpc-encoding", Value: "snappy"},
	}
	in := mustHTTPResponseEnv("s7", headers, body, 200)
	mock := newMockChannel("s7", in)
	ch := Wrap(mock, RoleClient)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	for {
		_, err := ch.Next(ctx)
		if err == nil {
			continue
		}
		var se *layer.StreamError
		if !errors.As(err, &se) {
			t.Fatalf("err = %v, want *layer.StreamError", err)
		}
		if se.Code != layer.ErrorInternalError {
			t.Errorf("Code = %v, want ErrorInternalError", se.Code)
		}
		if !strings.Contains(se.Reason, "unsupported grpc-encoding") {
			t.Errorf("Reason = %q", se.Reason)
		}
		return
	}
}

// --- Inner emits non-HTTPMessage → StreamError(Protocol) ---

func TestNonHTTPMessageInner_StreamError(t *testing.T) {
	bad := &envelope.Envelope{
		StreamID:  "s8",
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolRaw,
		Message:   &envelope.RawMessage{Bytes: []byte("not http")},
	}
	mock := newMockChannel("s8", bad)
	ch := Wrap(mock, RoleClient)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, err := ch.Next(ctx)
	if err == nil {
		t.Fatal("Next() should have errored")
	}
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v", err)
	}
	if se.Code != layer.ErrorProtocol {
		t.Errorf("Code = %v, want ErrorProtocol", se.Code)
	}
}

// --- LPM cap exceeded propagates as StreamError ---

func TestLPMCapExceeded(t *testing.T) {
	// Forge an LPM header claiming a length larger than MaxGRPCMessageSize
	// (MaxGRPCMessageSize+1, packed in 4-byte big-endian).
	// MaxGRPCMessageSize = 254 << 20.
	hdr := []byte{0x00, 0xFE, 0x00, 0x00, 0x01} // flags=0x00, length=0xFE000001 (way over cap)
	body := hdr
	headers := []envelope.KeyValue{{Name: "content-type", Value: "application/grpc-web"}}
	in := mustHTTPResponseEnv("s9", headers, body, 200)
	mock := newMockChannel("s9", in)
	ch := Wrap(mock, RoleClient)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, _ = ch.Next(ctx) // Start
	_, err := ch.Next(ctx)
	// We expect an error somewhere along the emit (Start was emitted from
	// the queue first, so the second Next pulls again and the parse fails).
	// However the implementation parses up-front in refillFromHTTPMessage,
	// so the FIRST Next may already fail. Accept either ordering.
	if err == nil {
		// Try one more.
		_, err = ch.Next(ctx)
	}
	if err == nil {
		t.Fatal("expected StreamError for LPM cap exceeded")
	}
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v", err)
	}
}

// --- Send-side D6: GRPCEndMessage(Send) sentinel triggers HTTPMessage assembly ---

func TestSend_RequestFlushSentinel(t *testing.T) {
	mock := newMockChannel("s10")
	ch := Wrap(mock, RoleClient)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Caller pushes Start + Data + End(Send).
	startEnv := &envelope.Envelope{
		StreamID:  "s10",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPCWeb,
		Message: &envelope.GRPCStartMessage{
			Service:     "pkg.Svc",
			Method:      "Do",
			ContentType: "application/grpc-web+proto",
			Metadata:    []envelope.KeyValue{{Name: "x-token", Value: "foo"}},
		},
	}
	dataEnv := &envelope.Envelope{
		StreamID:  "s10",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPCWeb,
		Message: &envelope.GRPCDataMessage{
			Payload: []byte("payload-1"),
		},
	}
	endEnv := &envelope.Envelope{
		StreamID:  "s10",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPCWeb,
		Message:   &envelope.GRPCEndMessage{},
	}

	if err := ch.Send(ctx, startEnv); err != nil {
		t.Fatalf("Send(Start): %v", err)
	}
	if err := ch.Send(ctx, dataEnv); err != nil {
		t.Fatalf("Send(Data): %v", err)
	}
	// At this point inner.Send should NOT have been called yet.
	if got := len(mock.sent); got != 0 {
		t.Errorf("inner.Send fired prematurely: %d", got)
	}
	if err := ch.Send(ctx, endEnv); err != nil {
		t.Fatalf("Send(End): %v", err)
	}

	if got := len(mock.sent); got != 1 {
		t.Fatalf("inner.Send fired %d times, want 1", got)
	}
	out := mock.sent[0]
	hm, ok := out.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("inner.Send Message = %T", out.Message)
	}
	if hm.Method != "POST" {
		t.Errorf("Method = %q, want POST", hm.Method)
	}
	if hm.Path != "/pkg.Svc/Do" {
		t.Errorf("Path = %q", hm.Path)
	}
	// Body should be a single LPM frame (no embedded trailer for request).
	if len(hm.Body) == 0 {
		t.Fatalf("Body empty")
	}
	res, err := DecodeBody(hm.Body, false)
	if err != nil {
		t.Fatalf("DecodeBody: %v", err)
	}
	if len(res.DataFrames) != 1 {
		t.Errorf("DataFrames = %d, want 1", len(res.DataFrames))
	}
	if res.TrailerFrame != nil {
		t.Errorf("Trailer should NOT be present in request body (D6)")
	}
	if !bytes.Equal(res.DataFrames[0].Payload, []byte("payload-1")) {
		t.Errorf("payload mismatch: %q", res.DataFrames[0].Payload)
	}
	// Headers should reconstitute content-type.
	gotCT := ""
	for _, kv := range hm.Headers {
		if strings.EqualFold(kv.Name, "content-type") {
			gotCT = kv.Value
		}
	}
	if gotCT != "application/grpc-web+proto" {
		t.Errorf("content-type header = %q", gotCT)
	}
}

// --- Send-side response with embedded trailer (RoleServer) ---

func TestSend_ResponseWithEmbeddedTrailer(t *testing.T) {
	mock := newMockChannel("s11")
	ch := Wrap(mock, RoleServer)
	ctx := context.Background()

	startEnv := &envelope.Envelope{
		StreamID:  "s11",
		Direction: envelope.Receive,
		Message: &envelope.GRPCStartMessage{
			ContentType: "application/grpc-web+proto",
		},
	}
	dataEnv := &envelope.Envelope{
		StreamID:  "s11",
		Direction: envelope.Receive,
		Message: &envelope.GRPCDataMessage{
			Payload: []byte("response-data"),
		},
	}
	endEnv := &envelope.Envelope{
		StreamID:  "s11",
		Direction: envelope.Receive,
		Message: &envelope.GRPCEndMessage{
			Status:  0,
			Message: "OK",
		},
	}

	if err := ch.Send(ctx, startEnv); err != nil {
		t.Fatalf("Send(Start): %v", err)
	}
	if err := ch.Send(ctx, dataEnv); err != nil {
		t.Fatalf("Send(Data): %v", err)
	}
	if err := ch.Send(ctx, endEnv); err != nil {
		t.Fatalf("Send(End): %v", err)
	}

	if got := len(mock.sent); got != 1 {
		t.Fatalf("inner.Send fired %d times, want 1", got)
	}
	hm := mock.sent[0].Message.(*envelope.HTTPMessage)
	res, err := DecodeBody(hm.Body, false)
	if err != nil {
		t.Fatalf("DecodeBody: %v", err)
	}
	if len(res.DataFrames) != 1 {
		t.Fatalf("DataFrames = %d", len(res.DataFrames))
	}
	if res.TrailerFrame == nil {
		t.Fatal("response body should contain embedded trailer")
	}
	if res.Trailers["grpc-status"] != "0" {
		t.Errorf("grpc-status = %q", res.Trailers["grpc-status"])
	}
	if res.Trailers["grpc-message"] != "OK" {
		t.Errorf("grpc-message = %q", res.Trailers["grpc-message"])
	}
}

// --- Send-side response in base64 wire form ---

func TestSend_ResponseBase64WireForm(t *testing.T) {
	mock := newMockChannel("s12")
	ch := Wrap(mock, RoleServer)
	ctx := context.Background()

	if err := ch.Send(ctx, &envelope.Envelope{
		StreamID:  "s12",
		Direction: envelope.Receive,
		Message: &envelope.GRPCStartMessage{
			ContentType: "application/grpc-web-text+proto",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := ch.Send(ctx, &envelope.Envelope{
		StreamID:  "s12",
		Direction: envelope.Receive,
		Message:   &envelope.GRPCDataMessage{Payload: []byte("base64-data")},
	}); err != nil {
		t.Fatal(err)
	}
	if err := ch.Send(ctx, &envelope.Envelope{
		StreamID:  "s12",
		Direction: envelope.Receive,
		Message:   &envelope.GRPCEndMessage{Status: 0},
	}); err != nil {
		t.Fatal(err)
	}

	hm := mock.sent[0].Message.(*envelope.HTTPMessage)
	// Body should be base64-encoded; DecodeBody with isBase64=true should
	// return a single data frame and a trailer.
	res, err := DecodeBody(hm.Body, true)
	if err != nil {
		t.Fatalf("DecodeBody base64: %v", err)
	}
	if len(res.DataFrames) != 1 {
		t.Fatalf("DataFrames = %d", len(res.DataFrames))
	}
	if !bytes.Equal(res.DataFrames[0].Payload, []byte("base64-data")) {
		t.Errorf("payload = %q", res.DataFrames[0].Payload)
	}
	if res.TrailerFrame == nil {
		t.Fatal("expected trailer frame")
	}
}

// --- Service/Method extraction including malformed paths ---

func TestServiceMethodExtraction(t *testing.T) {
	tests := []struct {
		path string
		ok   bool
		svc  string
		mth  string
	}{
		{"/pkg.Service/Method", true, "pkg.Service", "Method"},
		{"/foo/bar", true, "foo", "bar"},
		{"", false, "", ""},
		{"/", false, "", ""},
		{"/onlyone", false, "", ""},
		{"/svc/", false, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			s, m, ok := parseServiceMethod(tt.path)
			if ok != tt.ok || s != tt.svc || m != tt.mth {
				t.Errorf("parseServiceMethod(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tt.path, s, m, ok, tt.svc, tt.mth, tt.ok)
			}
		})
	}
}

func TestMalformedPath_EmitsEmptyServiceMethod(t *testing.T) {
	headers := []envelope.KeyValue{{Name: "content-type", Value: "application/grpc-web"}}
	in := mustHTTPRequestEnv("s13", headers, nil, "/onlyone-no-slash")
	mock := newMockChannel("s13", in)
	ch := Wrap(mock, RoleServer)
	envs := drainEnvelopes(t, ch, 5)
	if len(envs) != 1 {
		t.Fatalf("got %d envs", len(envs))
	}
	start := envs[0].Message.(*envelope.GRPCStartMessage)
	if start.Service != "" || start.Method != "" {
		t.Errorf("Service/Method should be empty for malformed path; got %q/%q", start.Service, start.Method)
	}
}

// --- Channel.Close cascade ---

func TestClose_Cascades(t *testing.T) {
	mock := newMockChannel("s14")
	ch := Wrap(mock, RoleClient)

	if err := ch.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	mock.mu.Lock()
	closed := mock.closed
	mock.mu.Unlock()
	if !closed {
		t.Error("inner.Close not invoked")
	}

	// Idempotent.
	if err := ch.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// --- StreamID delegation ---

func TestStreamID_Delegated(t *testing.T) {
	mock := newMockChannel("super-id")
	ch := Wrap(mock, RoleClient)
	if got := ch.StreamID(); got != "super-id" {
		t.Errorf("StreamID = %q", got)
	}
}

// --- Helpers ---

func hasHeader(kvs []envelope.KeyValue, name string) bool {
	for _, kv := range kvs {
		if strings.EqualFold(kv.Name, name) {
			return true
		}
	}
	return false
}
