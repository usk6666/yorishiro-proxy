package grpc

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// stubInner is an in-memory layer.Channel that the gRPC wrapper sees as
// its underlying HTTP/2 event stream. Tests pre-fill recv with the events
// they want the wrapper to read; sent envelopes accumulate in sent.
type stubInner struct {
	streamID string

	mu       sync.Mutex
	recv     []*envelope.Envelope
	recvIdx  int
	recvErr  error // returned after recv is drained
	sent     []*envelope.Envelope
	closed   atomic.Int32
	rstCode  uint32
	rstErr   error
	termDone chan struct{}
	termErr  error
}

func newStubInner(streamID string) *stubInner {
	return &stubInner{
		streamID: streamID,
		termDone: make(chan struct{}),
	}
}

func (s *stubInner) StreamID() string { return s.streamID }

func (s *stubInner) Next(ctx context.Context) (*envelope.Envelope, error) {
	s.mu.Lock()
	if s.recvIdx < len(s.recv) {
		env := s.recv[s.recvIdx]
		s.recvIdx++
		s.mu.Unlock()
		return env, nil
	}
	err := s.recvErr
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return nil, io.EOF
}

func (s *stubInner) Send(ctx context.Context, env *envelope.Envelope) error {
	s.mu.Lock()
	s.sent = append(s.sent, env)
	s.mu.Unlock()
	return nil
}

func (s *stubInner) Close() error {
	s.closed.Add(1)
	select {
	case <-s.termDone:
	default:
		close(s.termDone)
	}
	return nil
}

func (s *stubInner) Closed() <-chan struct{} { return s.termDone }
func (s *stubInner) Err() error              { return s.termErr }

func (s *stubInner) MarkTerminatedWithRST(code uint32, err error) {
	s.rstCode = code
	s.rstErr = err
}

// pushHeaders adds an H2HeadersEvent envelope to the inner queue.
func (s *stubInner) pushHeaders(dir envelope.Direction, raw []byte, evt *http2.H2HeadersEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recv = append(s.recv, &envelope.Envelope{
		StreamID:  s.streamID,
		FlowID:    "",
		Sequence:  s.recvIdx,
		Direction: dir,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       raw,
		Message:   evt,
	})
}

// pushData adds an H2DataEvent envelope to the inner queue.
func (s *stubInner) pushData(dir envelope.Direction, payload []byte, endStream bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recv = append(s.recv, &envelope.Envelope{
		StreamID:  s.streamID,
		FlowID:    "",
		Sequence:  s.recvIdx,
		Direction: dir,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       append([]byte(nil), payload...),
		Message: &http2.H2DataEvent{
			Payload:   payload,
			EndStream: endStream,
		},
	})
}

// pushTrailers adds an H2TrailersEvent envelope to the inner queue.
func (s *stubInner) pushTrailers(dir envelope.Direction, raw []byte, trailers []envelope.KeyValue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recv = append(s.recv, &envelope.Envelope{
		StreamID:  s.streamID,
		FlowID:    "",
		Sequence:  s.recvIdx,
		Direction: dir,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       raw,
		Message: &http2.H2TrailersEvent{
			Trailers: trailers,
		},
	})
}

// makeLPM builds a length-prefixed gRPC message wire-form: 5-byte prefix +
// payload. compressed sets the leading flag byte.
func makeLPM(compressed bool, payload []byte) []byte {
	out := make([]byte, lpmPrefixLen+len(payload))
	if compressed {
		out[0] = 1
	}
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[lpmPrefixLen:], payload)
	return out
}

// gzipCompress is a test helper.
func gzipCompress(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// requestStartHeaders builds a request-side H2HeadersEvent with realistic
// gRPC pseudo-headers + content-type.
func requestStartHeaders(path string, extra ...envelope.KeyValue) *http2.H2HeadersEvent {
	hdrs := []envelope.KeyValue{
		{Name: "content-type", Value: "application/grpc+proto"},
		{Name: "te", Value: "trailers"},
	}
	hdrs = append(hdrs, extra...)
	return &http2.H2HeadersEvent{
		Method:    "POST",
		Scheme:    "https",
		Authority: "api.example.com",
		Path:      path,
		Headers:   hdrs,
	}
}

// drainNext pulls n envelopes from ch, failing the test on error or
// io.EOF before all are received.
func drainNext(t *testing.T, ch layer.Channel, n int) []*envelope.Envelope {
	t.Helper()
	out := make([]*envelope.Envelope, 0, n)
	for i := 0; i < n; i++ {
		env, err := ch.Next(context.Background())
		if err != nil {
			t.Fatalf("Next #%d: %v", i, err)
		}
		out = append(out, env)
	}
	return out
}

// ----------------------------------------------------------------------
// LPM reassembler — split, combined, 1:N, N:1 (acceptance criterion).
// ----------------------------------------------------------------------

func TestChannel_LPMSingleEvent(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	first := requestStartHeaders("/svc.S/M")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), first)
	payload := []byte("hello")
	stub.pushData(envelope.Send, makeLPM(false, payload), true)

	ch := Wrap(stub, nil, RoleServer)
	defer ch.Close()

	// 1) GRPCStartMessage.
	envs := drainNext(t, ch, 2)
	if _, ok := envs[0].Message.(*envelope.GRPCStartMessage); !ok {
		t.Fatalf("envs[0].Message = %T, want *GRPCStartMessage", envs[0].Message)
	}
	dm, ok := envs[1].Message.(*envelope.GRPCDataMessage)
	if !ok {
		t.Fatalf("envs[1].Message = %T, want *GRPCDataMessage", envs[1].Message)
	}
	if string(dm.Payload) != "hello" {
		t.Errorf("Payload = %q, want %q", dm.Payload, "hello")
	}
	if dm.WireLength != 5 || dm.Compressed {
		t.Errorf("WireLength=%d Compressed=%v, want 5/false", dm.WireLength, dm.Compressed)
	}
	if len(envs[1].Raw) != lpmPrefixLen+len(payload) {
		t.Errorf("Raw length = %d, want %d", len(envs[1].Raw), lpmPrefixLen+len(payload))
	}
}

func TestChannel_LPMSplitAcrossDataEvents(t *testing.T) {
	t.Parallel()
	// One LPM split into 3 H2DataEvents: prefix-only, partial-payload,
	// rest-of-payload.
	stub := newStubInner("stream-1")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))

	wire := makeLPM(false, []byte("abcdefghij")) // 5 + 10 = 15 bytes
	// Split into prefix-only [0..5), then 6 bytes [5..11), then rest [11..15).
	stub.pushData(envelope.Send, wire[:5], false)
	stub.pushData(envelope.Send, wire[5:11], false)
	stub.pushData(envelope.Send, wire[11:], true)

	ch := Wrap(stub, nil, RoleServer)
	defer ch.Close()

	envs := drainNext(t, ch, 2)
	dm := envs[1].Message.(*envelope.GRPCDataMessage)
	if string(dm.Payload) != "abcdefghij" {
		t.Errorf("Payload = %q, want abcdefghij", dm.Payload)
	}
}

func TestChannel_MultipleLPMsInOneDataEvent(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))

	a := makeLPM(false, []byte("aaaa"))
	b := makeLPM(false, []byte("bb"))
	c := makeLPM(false, []byte("ccccccc"))
	all := append(append(append([]byte{}, a...), b...), c...)
	stub.pushData(envelope.Send, all, true)

	ch := Wrap(stub, nil, RoleServer)
	defer ch.Close()

	envs := drainNext(t, ch, 4) // Start + 3 Data
	for i, want := range []string{"aaaa", "bb", "ccccccc"} {
		dm := envs[i+1].Message.(*envelope.GRPCDataMessage)
		if string(dm.Payload) != want {
			t.Errorf("envs[%d].Payload = %q, want %q", i+1, dm.Payload, want)
		}
	}
}

func TestChannel_LPMSplitPrefixAcrossDataEvents(t *testing.T) {
	t.Parallel()
	// Prefix split into 3 separate 1-byte / 2-byte / 2-byte H2DataEvents.
	stub := newStubInner("stream-1")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))

	wire := makeLPM(false, []byte("xy"))
	stub.pushData(envelope.Send, wire[0:1], false)
	stub.pushData(envelope.Send, wire[1:3], false)
	stub.pushData(envelope.Send, wire[3:5], false)
	stub.pushData(envelope.Send, wire[5:], true)

	ch := Wrap(stub, nil, RoleServer)
	defer ch.Close()

	envs := drainNext(t, ch, 2)
	dm := envs[1].Message.(*envelope.GRPCDataMessage)
	if string(dm.Payload) != "xy" {
		t.Errorf("Payload = %q, want xy", dm.Payload)
	}
}

// ----------------------------------------------------------------------
// gzip round-trip on Receive then Send re-encode.
// ----------------------------------------------------------------------

func TestChannel_GzipDecodeOnReceive(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	hdrs := requestStartHeaders("/svc.S/M",
		envelope.KeyValue{Name: "grpc-encoding", Value: "gzip"},
	)
	stub.pushHeaders(envelope.Send, []byte("HPACK"), hdrs)

	original := []byte("compressed body")
	compressed := gzipCompress(t, original)
	stub.pushData(envelope.Send, makeLPM(true, compressed), true)

	ch := Wrap(stub, nil, RoleServer)
	defer ch.Close()

	envs := drainNext(t, ch, 2)
	dm := envs[1].Message.(*envelope.GRPCDataMessage)
	if !dm.Compressed {
		t.Errorf("Compressed = false, want true")
	}
	if string(dm.Payload) != "compressed body" {
		t.Errorf("decoded Payload = %q, want %q", dm.Payload, "compressed body")
	}
	// Raw must still be the on-wire bytes (compressed).
	wantRaw := makeLPM(true, compressed)
	if !bytes.Equal(envs[1].Raw, wantRaw) {
		t.Errorf("Raw = %x, want %x", envs[1].Raw, wantRaw)
	}
}

func TestChannel_SendDataReEncodesGzip(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	ch := Wrap(stub, nil, RoleClient)
	defer ch.Close()

	// Send Start with grpc-encoding: gzip so the wrapper caches the
	// negotiated encoding.
	startEnv := &envelope.Envelope{
		StreamID:  "stream-1",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message: &envelope.GRPCStartMessage{
			Service:  "svc.S",
			Method:   "M",
			Encoding: "gzip",
		},
	}
	if err := ch.Send(context.Background(), startEnv); err != nil {
		t.Fatalf("Send Start: %v", err)
	}

	dataEnv := &envelope.Envelope{
		StreamID:  "stream-1",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message: &envelope.GRPCDataMessage{
			Compressed: true,
			Payload:    []byte("payload"),
		},
	}
	if err := ch.Send(context.Background(), dataEnv); err != nil {
		t.Fatalf("Send Data: %v", err)
	}

	stub.mu.Lock()
	defer stub.mu.Unlock()
	if len(stub.sent) != 2 {
		t.Fatalf("inner.sent length = %d, want 2", len(stub.sent))
	}
	dataInner, ok := stub.sent[1].Message.(*http2.H2DataEvent)
	if !ok {
		t.Fatalf("inner.sent[1].Message = %T, want *H2DataEvent", stub.sent[1].Message)
	}
	// Wire form must start with compressed=1 and gzip-decompressable
	// payload.
	if dataInner.Payload[0] != 1 {
		t.Errorf("compressed flag = %d, want 1", dataInner.Payload[0])
	}
	wireLen := binary.BigEndian.Uint32(dataInner.Payload[1:5])
	if int(wireLen) != len(dataInner.Payload)-lpmPrefixLen {
		t.Errorf("WireLength=%d, payload bytes after prefix=%d", wireLen, len(dataInner.Payload)-lpmPrefixLen)
	}
	r, err := gzip.NewReader(bytes.NewReader(dataInner.Payload[lpmPrefixLen:]))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	roundtrip, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("gzip ReadAll: %v", err)
	}
	if string(roundtrip) != "payload" {
		t.Errorf("roundtrip = %q, want %q", roundtrip, "payload")
	}
}

// ----------------------------------------------------------------------
// Service / Method extraction (D1: tolerant).
// ----------------------------------------------------------------------

func TestParseGRPCPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path           string
		wantSvc, wantM string
	}{
		{"/pkg.Service/Method", "pkg.Service", "Method"},
		{"/pkg.subpkg.Service/Method", "pkg.subpkg.Service", "Method"},
		{"/svc.S/M", "svc.S", "M"},
		{"", "", ""},
		{"foo", "", ""},
		{"/", "", ""},
		{"/foo", "", ""},
		{"/foo/", "", ""},    // trailing slash → no method
		{"//Method", "", ""}, // empty service before first slash
	}
	for _, tc := range cases {
		gotSvc, gotM := parseGRPCPath(tc.path)
		if gotSvc != tc.wantSvc || gotM != tc.wantM {
			t.Errorf("parseGRPCPath(%q) = (%q, %q), want (%q, %q)",
				tc.path, gotSvc, gotM, tc.wantSvc, tc.wantM)
		}
	}
}

func TestChannel_MalformedPathSurfacesEmptyServiceMethod(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	bad := requestStartHeaders("not-a-path") // no leading slash
	stub.pushHeaders(envelope.Send, []byte("HPACK"), bad)

	ch := Wrap(stub, nil, RoleServer)
	defer ch.Close()

	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	sm := env.Message.(*envelope.GRPCStartMessage)
	if sm.Service != "" || sm.Method != "" {
		t.Errorf("malformed path Service/Method = (%q, %q), want both empty", sm.Service, sm.Method)
	}
}

// ----------------------------------------------------------------------
// D2: Unsupported encoding on Receive → StreamError.
// ----------------------------------------------------------------------

func TestChannel_UnsupportedEncodingOnReceive(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	hdrs := requestStartHeaders("/svc.S/M",
		envelope.KeyValue{Name: "grpc-encoding", Value: "snappy"},
	)
	stub.pushHeaders(envelope.Send, []byte("HPACK"), hdrs)
	stub.pushData(envelope.Send, makeLPM(true, []byte("blob")), true)

	ch := Wrap(stub, nil, RoleServer)
	defer ch.Close()

	// Drain Start (succeeds).
	if _, err := ch.Next(context.Background()); err != nil {
		t.Fatalf("Next Start: %v", err)
	}
	// The next Next on a Compressed=true LPM with snappy encoding must
	// surface a *layer.StreamError(Protocol).
	_, err := ch.Next(context.Background())
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("Next: got %v, want *layer.StreamError", err)
	}
	if se.Code != layer.ErrorProtocol {
		t.Errorf("StreamError.Code = %v, want ErrorProtocol", se.Code)
	}
	// inner.MarkTerminatedWithRST must have been called.
	if stub.rstErr == nil {
		t.Error("inner.MarkTerminatedWithRST was not called")
	}
}

func TestChannel_UnsupportedEncodingOnSend(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	ch := Wrap(stub, nil, RoleClient)
	defer ch.Close()

	startEnv := &envelope.Envelope{
		StreamID:  "stream-1",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message: &envelope.GRPCStartMessage{
			Service:  "svc.S",
			Method:   "M",
			Encoding: "snappy",
		},
	}
	if err := ch.Send(context.Background(), startEnv); err != nil {
		t.Fatalf("Send Start: %v", err)
	}

	dataEnv := &envelope.Envelope{
		StreamID:  "stream-1",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message: &envelope.GRPCDataMessage{
			Compressed: true,
			Payload:    []byte("data"),
		},
	}
	err := ch.Send(context.Background(), dataEnv)
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("Send Data: got %v, want *layer.StreamError", err)
	}
	if se.Code != layer.ErrorProtocol {
		t.Errorf("Send Data StreamError.Code = %v, want ErrorProtocol", se.Code)
	}
}

// ----------------------------------------------------------------------
// D3: Sequence is monotonic on emission order (bidi).
// ----------------------------------------------------------------------

func TestChannel_SequenceIsMonotonic(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	stub.pushHeaders(envelope.Send, []byte("HPACK-req"), requestStartHeaders("/svc.S/M"))
	stub.pushData(envelope.Send, makeLPM(false, []byte("req-1")), false)
	stub.pushHeaders(envelope.Receive, []byte("HPACK-resp"), &http2.H2HeadersEvent{
		Status: 200,
		Headers: []envelope.KeyValue{
			{Name: "content-type", Value: "application/grpc"},
		},
	})
	stub.pushData(envelope.Receive, makeLPM(false, []byte("resp-1")), false)
	stub.pushData(envelope.Send, makeLPM(false, []byte("req-2")), false)
	stub.pushTrailers(envelope.Receive, []byte("HPACK-trailers"), []envelope.KeyValue{
		{Name: "grpc-status", Value: "0"},
	})

	ch := Wrap(stub, nil, RoleServer)
	defer ch.Close()

	envs := drainNext(t, ch, 6)
	for i, env := range envs {
		if env.Sequence != i {
			t.Errorf("envs[%d].Sequence = %d, want %d", i, env.Sequence, i)
		}
	}
}

// ----------------------------------------------------------------------
// D4: Trailers-only response → both Start AND End.
// ----------------------------------------------------------------------

func TestChannel_TrailersOnlyResponseEmitsStartAndEnd(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	// Trailers-only response: a single HEADERS with END_STREAM that
	// carries grpc-status.
	stub.pushHeaders(envelope.Receive, []byte("HPACK-trailers-only"), &http2.H2HeadersEvent{
		Status:    200,
		EndStream: true,
		Headers: []envelope.KeyValue{
			{Name: "content-type", Value: "application/grpc"},
			{Name: "grpc-status", Value: "13"},
			{Name: "grpc-message", Value: "internal failure"},
		},
	})

	ch := Wrap(stub, nil, RoleClient)
	defer ch.Close()

	envs := drainNext(t, ch, 2)
	if _, ok := envs[0].Message.(*envelope.GRPCStartMessage); !ok {
		t.Fatalf("envs[0].Message = %T, want *GRPCStartMessage", envs[0].Message)
	}
	end, ok := envs[1].Message.(*envelope.GRPCEndMessage)
	if !ok {
		t.Fatalf("envs[1].Message = %T, want *GRPCEndMessage", envs[1].Message)
	}
	if end.Status != 13 {
		t.Errorf("End.Status = %d, want 13", end.Status)
	}
	if end.Message != "internal failure" {
		t.Errorf("End.Message = %q, want %q", end.Message, "internal failure")
	}
	// Synthetic end has Raw=nil; start carries the wire bytes.
	if envs[1].Raw != nil {
		t.Errorf("End.Raw = %v, want nil (synthetic)", envs[1].Raw)
	}
	if !bytes.Equal(envs[0].Raw, []byte("HPACK-trailers-only")) {
		t.Errorf("Start.Raw = %x, want HPACK-trailers-only", envs[0].Raw)
	}
	if envs[0].Sequence != 0 || envs[1].Sequence != 1 {
		t.Errorf("Sequence = (%d, %d), want (0, 1)", envs[0].Sequence, envs[1].Sequence)
	}
}

// ----------------------------------------------------------------------
// D5: Synthetic firstHeaders (Raw=empty) is discarded.
// ----------------------------------------------------------------------

func TestChannel_SyntheticFirstHeadersDiscarded(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	// Pre-populate the inner with a real first envelope.
	stub.pushHeaders(envelope.Send, []byte("REAL-HPACK"), requestStartHeaders("/svc.S/M"))

	// Synthetic firstHeaders with Raw=nil — must be discarded.
	synthetic := &envelope.Envelope{
		StreamID:  "stream-1",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       nil,
		Message: &http2.H2HeadersEvent{
			Path: "/synthetic/Discard",
		},
	}
	ch := Wrap(stub, synthetic, RoleClient)
	defer ch.Close()

	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	sm := env.Message.(*envelope.GRPCStartMessage)
	if sm.Service != "svc.S" || sm.Method != "M" {
		t.Errorf("Service/Method = (%q, %q), want (svc.S, M)", sm.Service, sm.Method)
	}
	if !bytes.Equal(env.Raw, []byte("REAL-HPACK")) {
		t.Errorf("env.Raw = %q, want REAL-HPACK", env.Raw)
	}
}

func TestChannel_NonSyntheticFirstHeadersReplayed(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")

	first := &envelope.Envelope{
		StreamID:  "stream-1",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("PEEKED-HPACK"),
		Message:   requestStartHeaders("/svc.X/Y"),
	}
	ch := Wrap(stub, first, RoleServer)
	defer ch.Close()

	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	sm := env.Message.(*envelope.GRPCStartMessage)
	if sm.Service != "svc.X" || sm.Method != "Y" {
		t.Errorf("Service/Method = (%q, %q), want (svc.X, Y)", sm.Service, sm.Method)
	}
}

// ----------------------------------------------------------------------
// GRPCEndMessage: status / message / status-details-bin parsing.
// ----------------------------------------------------------------------

func TestChannel_EndMessageFromTrailers(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))
	stub.pushData(envelope.Send, makeLPM(false, []byte("payload")), true)
	// Status-details-bin: a small protobuf-shaped binary that must
	// survive base64-URL no-padding round-trip.
	rawDetails := []byte{0x08, 0x02, 0x12, 0x05, 'h', 'e', 'l', 'l', 'o'}
	stub.pushTrailers(envelope.Receive, []byte("HPACK-trailer"), []envelope.KeyValue{
		{Name: "grpc-status", Value: "5"},
		{Name: "grpc-message", Value: "user%20not%20found"},
		{Name: "grpc-status-details-bin", Value: base64.RawURLEncoding.EncodeToString(rawDetails)},
		{Name: "x-debug-id", Value: "trace-abc"},
	})

	ch := Wrap(stub, nil, RoleServer)
	defer ch.Close()

	envs := drainNext(t, ch, 3)
	end, ok := envs[2].Message.(*envelope.GRPCEndMessage)
	if !ok {
		t.Fatalf("envs[2].Message = %T, want *GRPCEndMessage", envs[2].Message)
	}
	if end.Status != 5 {
		t.Errorf("Status = %d, want 5", end.Status)
	}
	if end.Message != "user not found" {
		t.Errorf("Message = %q, want %q", end.Message, "user not found")
	}
	if !bytes.Equal(end.StatusDetails, rawDetails) {
		t.Errorf("StatusDetails = %x, want %x", end.StatusDetails, rawDetails)
	}
	if len(end.Trailers) != 1 || end.Trailers[0].Name != "x-debug-id" {
		t.Errorf("Trailers = %v, want exactly one x-debug-id entry", end.Trailers)
	}
}

// ----------------------------------------------------------------------
// D7: metadata strip set.
// ----------------------------------------------------------------------

func TestChannel_StartMetadataStripSet(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	hdrs := &http2.H2HeadersEvent{
		Method:    "POST",
		Scheme:    "https",
		Authority: "api.example.com",
		Path:      "/svc.S/M",
		Headers: []envelope.KeyValue{
			{Name: ":pseudo-only", Value: "x"},
			{Name: "content-type", Value: "application/grpc+proto"},
			{Name: "grpc-encoding", Value: "gzip"},
			{Name: "grpc-accept-encoding", Value: "gzip, identity"},
			{Name: "grpc-timeout", Value: "30S"},
			{Name: "x-request-id", Value: "abc123"},
			{Name: "Authorization", Value: "Bearer xyz"}, // case preserved
			{Name: "x-tenant", Value: "acme"},
		},
	}
	stub.pushHeaders(envelope.Send, []byte("HPACK"), hdrs)

	ch := Wrap(stub, nil, RoleServer)
	defer ch.Close()

	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	sm := env.Message.(*envelope.GRPCStartMessage)
	if sm.ContentType != "application/grpc+proto" {
		t.Errorf("ContentType = %q", sm.ContentType)
	}
	if sm.Encoding != "gzip" {
		t.Errorf("Encoding = %q", sm.Encoding)
	}
	if len(sm.AcceptEncoding) != 2 || sm.AcceptEncoding[0] != "gzip" || sm.AcceptEncoding[1] != "identity" {
		t.Errorf("AcceptEncoding = %v", sm.AcceptEncoding)
	}
	if sm.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", sm.Timeout)
	}

	wantMeta := []envelope.KeyValue{
		{Name: "x-request-id", Value: "abc123"},
		{Name: "Authorization", Value: "Bearer xyz"},
		{Name: "x-tenant", Value: "acme"},
	}
	if len(sm.Metadata) != len(wantMeta) {
		t.Fatalf("Metadata = %v, want %v", sm.Metadata, wantMeta)
	}
	for i, kv := range wantMeta {
		if sm.Metadata[i] != kv {
			t.Errorf("Metadata[%d] = %v, want %v", i, sm.Metadata[i], kv)
		}
	}
}

func TestChannel_EndTrailersStripSet(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))
	stub.pushTrailers(envelope.Receive, []byte("HPACK-trailer"), []envelope.KeyValue{
		{Name: "GRPC-status", Value: "0"}, // case-insensitive strip
		{Name: "grpc-message", Value: ""},
		{Name: "grpc-status-details-bin", Value: ""},
		{Name: "x-trace", Value: "abc"},
		{Name: "x-Server", Value: "test"},
	})

	ch := Wrap(stub, nil, RoleServer)
	defer ch.Close()

	envs := drainNext(t, ch, 2)
	end := envs[1].Message.(*envelope.GRPCEndMessage)
	wantTrailers := []envelope.KeyValue{
		{Name: "x-trace", Value: "abc"},
		{Name: "x-Server", Value: "test"},
	}
	if len(end.Trailers) != len(wantTrailers) {
		t.Fatalf("Trailers = %v, want %v", end.Trailers, wantTrailers)
	}
	for i, kv := range wantTrailers {
		if end.Trailers[i] != kv {
			t.Errorf("Trailers[%d] = %v, want %v", i, end.Trailers[i], kv)
		}
	}
}

// ----------------------------------------------------------------------
// Channel.Close cascade and idempotency.
// ----------------------------------------------------------------------

func TestChannel_CloseCascadeIdempotent(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	ch := Wrap(stub, nil, RoleServer)

	for i := 0; i < 3; i++ {
		if err := ch.Close(); err != nil {
			t.Errorf("Close #%d: %v", i, err)
		}
	}
	if got := stub.closed.Load(); got != 1 {
		t.Errorf("inner.Close call count = %d, want 1", got)
	}
}

// ----------------------------------------------------------------------
// LPM cap exceeded → StreamError(InternalError).
// ----------------------------------------------------------------------

func TestChannel_LPMCapExceeded(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))
	// Forge a LPM whose declared length exceeds MaxGRPCMessageSize.
	prefix := make([]byte, lpmPrefixLen)
	binary.BigEndian.PutUint32(prefix[1:5], config.MaxGRPCMessageSize+1)
	stub.pushData(envelope.Send, prefix, false)

	ch := Wrap(stub, nil, RoleServer)
	defer ch.Close()

	// Drain Start.
	if _, err := ch.Next(context.Background()); err != nil {
		t.Fatalf("Next Start: %v", err)
	}
	_, err := ch.Next(context.Background())
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("Next: got %v, want *layer.StreamError", err)
	}
	if se.Code != layer.ErrorInternalError {
		t.Errorf("StreamError.Code = %v, want ErrorInternalError", se.Code)
	}
	if stub.rstErr == nil {
		t.Error("inner.MarkTerminatedWithRST was not called for cap-exceeded")
	}
}

// ----------------------------------------------------------------------
// Bad gzip on Receive → StreamError(Protocol).
// ----------------------------------------------------------------------

func TestChannel_BadGzipPayload(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	hdrs := requestStartHeaders("/svc.S/M",
		envelope.KeyValue{Name: "grpc-encoding", Value: "gzip"},
	)
	stub.pushHeaders(envelope.Send, []byte("HPACK"), hdrs)
	// Compressed=1 but payload is not valid gzip.
	stub.pushData(envelope.Send, makeLPM(true, []byte("not-gzip-data!")), true)

	ch := Wrap(stub, nil, RoleServer)
	defer ch.Close()

	if _, err := ch.Next(context.Background()); err != nil {
		t.Fatalf("Next Start: %v", err)
	}
	_, err := ch.Next(context.Background())
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("Next: got %v, want *layer.StreamError", err)
	}
	if se.Code != layer.ErrorProtocol {
		t.Errorf("StreamError.Code = %v, want ErrorProtocol", se.Code)
	}
}

// ----------------------------------------------------------------------
// WireLength=0 + Compressed=true (empty payload, no decompression issue).
// ----------------------------------------------------------------------

func TestChannel_EmptyCompressedLPM(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	hdrs := requestStartHeaders("/svc.S/M",
		envelope.KeyValue{Name: "grpc-encoding", Value: "gzip"},
	)
	stub.pushHeaders(envelope.Send, []byte("HPACK"), hdrs)
	// Compressed=1, length=0, no payload bytes after prefix.
	stub.pushData(envelope.Send, makeLPM(true, nil), true)

	ch := Wrap(stub, nil, RoleServer)
	defer ch.Close()

	envs := drainNext(t, ch, 2)
	dm := envs[1].Message.(*envelope.GRPCDataMessage)
	if !dm.Compressed || dm.WireLength != 0 || len(dm.Payload) != 0 {
		t.Errorf("Compressed=%v WireLength=%d len(Payload)=%d, want true/0/0",
			dm.Compressed, dm.WireLength, len(dm.Payload))
	}
}

// ----------------------------------------------------------------------
// Repeated mid-stream HEADERS → StreamError.
// ----------------------------------------------------------------------

func TestChannel_RepeatedMidStreamHeaders(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-1")
	stub.pushHeaders(envelope.Send, []byte("HPACK1"), requestStartHeaders("/svc.S/M"))
	// Second HEADERS on the same direction (without END_STREAM) — invalid.
	stub.pushHeaders(envelope.Send, []byte("HPACK2"), requestStartHeaders("/svc.S/M"))

	ch := Wrap(stub, nil, RoleServer)
	defer ch.Close()

	if _, err := ch.Next(context.Background()); err != nil {
		t.Fatalf("Next Start: %v", err)
	}
	_, err := ch.Next(context.Background())
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("Next: got %v, want *layer.StreamError", err)
	}
	if se.Code != layer.ErrorProtocol {
		t.Errorf("StreamError.Code = %v, want ErrorProtocol", se.Code)
	}
}

// ----------------------------------------------------------------------
// Helpers — direct unit tests.
// ----------------------------------------------------------------------

func TestParseGRPCTimeout(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"30S", 30 * time.Second},
		{"500m", 500 * time.Millisecond},
		{"1H", time.Hour},
		{"15M", 15 * time.Minute},
		{"100u", 100 * time.Microsecond},
		{"50n", 50 * time.Nanosecond},
		{"", 0},
		{"x", 0},
		{"5X", 0},
	}
	for _, tc := range cases {
		got := parseGRPCTimeout(tc.in)
		if got != tc.want {
			t.Errorf("parseGRPCTimeout(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestFormatGRPCTimeout(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   time.Duration
		want string
	}{
		{30 * time.Second, "30S"},
		{500 * time.Millisecond, "500m"},
		{time.Hour, "1H"},
		{15 * time.Minute, "15M"},
		{100 * time.Microsecond, "100u"},
		{50 * time.Nanosecond, "50n"},
		{0, ""},
		{-1 * time.Second, ""},
	}
	for _, tc := range cases {
		got := formatGRPCTimeout(tc.in)
		if got != tc.want {
			t.Errorf("formatGRPCTimeout(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPercentEncodeDecodeRoundTrip(t *testing.T) {
	t.Parallel()
	cases := []string{
		"plain ascii text",
		"with %20 escapes",
		"control \x01\x02 bytes",
		"unicode 日本語",
		"",
	}
	for _, s := range cases {
		enc := percentEncode(s)
		dec := percentDecode(enc)
		if dec != s {
			t.Errorf("round-trip %q → %q → %q", s, enc, dec)
		}
	}
}
