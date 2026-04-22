package pipeline

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// mockWriter is a test double for flow.Writer.
type mockWriter struct {
	streams []*flow.Stream
	flows   []*flow.Flow
	updates []streamUpdateRecord
	saveErr error
}

type streamUpdateRecord struct {
	streamID string
	update   flow.StreamUpdate
}

func (m *mockWriter) SaveStream(_ context.Context, s *flow.Stream) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.streams = append(m.streams, s)
	return nil
}

func (m *mockWriter) UpdateStream(_ context.Context, id string, u flow.StreamUpdate) error {
	m.updates = append(m.updates, streamUpdateRecord{streamID: id, update: u})
	return nil
}

func (m *mockWriter) SaveFlow(_ context.Context, f *flow.Flow) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.flows = append(m.flows, f)
	return nil
}

func TestRecordStep_NilStore(t *testing.T) {
	step := NewRecordStep(nil, nil)
	env := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  0,
		Protocol:  envelope.ProtocolRaw,
		Raw:       []byte("hello"),
		Message:   &envelope.RawMessage{Bytes: []byte("hello")},
	}
	r := step.Process(context.Background(), env)
	if r.Action != Continue {
		t.Errorf("nil store: got action %v, want Continue", r.Action)
	}
}

func TestRecordStep_CreateStreamOnFirstSend(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	env := &envelope.Envelope{
		StreamID:  "stream-1",
		FlowID:    "flow-1",
		Direction: envelope.Send,
		Sequence:  0,
		Protocol:  envelope.ProtocolRaw,
		Raw:       []byte("data"),
		Message:   &envelope.RawMessage{Bytes: []byte("data")},
		Context: envelope.EnvelopeContext{
			ConnID: "conn-1",
		},
	}
	step.Process(context.Background(), env)

	if len(w.streams) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(w.streams))
	}
	s := w.streams[0]
	if s.ID != "stream-1" {
		t.Errorf("stream ID = %q, want %q", s.ID, "stream-1")
	}
	if s.ConnID != "conn-1" {
		t.Errorf("stream ConnID = %q, want %q", s.ConnID, "conn-1")
	}
	if s.Protocol != "raw" {
		t.Errorf("stream Protocol = %q, want %q", s.Protocol, "raw")
	}
	if s.State != "active" {
		t.Errorf("stream State = %q, want %q", s.State, "active")
	}

	if len(w.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(w.flows))
	}
}

func TestRecordStep_NoStreamOnSubsequentSend(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	env := &envelope.Envelope{
		StreamID:  "stream-1",
		FlowID:    "flow-2",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolRaw,
		Raw:       []byte("more"),
		Message:   &envelope.RawMessage{Bytes: []byte("more")},
	}
	step.Process(context.Background(), env)

	if len(w.streams) != 0 {
		t.Errorf("expected 0 streams for Sequence>0, got %d", len(w.streams))
	}
	if len(w.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(w.flows))
	}
}

func TestRecordStep_NoStreamOnReceive(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	env := &envelope.Envelope{
		StreamID:  "stream-1",
		FlowID:    "flow-3",
		Direction: envelope.Receive,
		Sequence:  0,
		Protocol:  envelope.ProtocolRaw,
		Raw:       []byte("resp"),
		Message:   &envelope.RawMessage{Bytes: []byte("resp")},
	}
	step.Process(context.Background(), env)

	if len(w.streams) != 0 {
		t.Errorf("expected 0 streams for Receive, got %d", len(w.streams))
	}
	if len(w.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(w.flows))
	}
}

// TestRecordStep_ReceiveProjectsUpstreamTLSToConnInfo verifies that Receive
// envelopes with a non-nil Context.TLS trigger an UpdateStream call that
// projects upstream TLS reality into Stream.ConnInfo — the diagnostic
// invariant USK-619 is solving.
func TestRecordStep_ReceiveProjectsUpstreamTLSToConnInfo(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	upstreamCert := &x509.Certificate{
		Subject: pkix.Name{CommonName: "upstream-tls-marker"},
	}
	upstreamSnap := &envelope.TLSSnapshot{
		SNI:             "upstream.example.com",
		ALPN:            "h2",
		PeerCertificate: upstreamCert,
		Version:         tls.VersionTLS13,
		CipherSuite:     tls.TLS_AES_128_GCM_SHA256,
	}

	env := &envelope.Envelope{
		StreamID:  "stream-1",
		FlowID:    "flow-recv",
		Direction: envelope.Receive,
		Sequence:  0,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("HTTP/1.1 200 OK\r\n\r\n"),
		Message:   &envelope.HTTPMessage{Status: 200},
		Context: envelope.EnvelopeContext{
			ConnID: "conn-1",
			TLS:    upstreamSnap,
		},
	}
	step.Process(context.Background(), env)

	if len(w.updates) != 1 {
		t.Fatalf("expected 1 UpdateStream call, got %d", len(w.updates))
	}
	got := w.updates[0]
	if got.streamID != "stream-1" {
		t.Errorf("UpdateStream streamID = %q, want stream-1", got.streamID)
	}
	if got.update.TLSVersion != "TLS 1.3" {
		t.Errorf("TLSVersion = %q, want %q", got.update.TLSVersion, "TLS 1.3")
	}
	if got.update.TLSCipher != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("TLSCipher = %q, want TLS_AES_128_GCM_SHA256", got.update.TLSCipher)
	}
	if got.update.TLSALPN != "h2" {
		t.Errorf("TLSALPN = %q, want h2", got.update.TLSALPN)
	}
	if !strings.Contains(got.update.TLSServerCertSubject, "upstream-tls-marker") {
		t.Errorf("TLSServerCertSubject = %q, want to contain upstream-tls-marker",
			got.update.TLSServerCertSubject)
	}
}

// TestRecordStep_SendDoesNotProjectClientMITMToConnInfo guards against
// regressing to the Send-side projection model — the client Send envelope
// carries the synthetic MITM cert we presented, which would mislead
// analysts if recorded as Stream.ConnInfo.TLSServerCertSubject.
func TestRecordStep_SendDoesNotProjectClientMITMToConnInfo(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	clientSnap := &envelope.TLSSnapshot{
		Version: tls.VersionTLS13,
		PeerCertificate: &x509.Certificate{
			Subject: pkix.Name{CommonName: "synthetic-mitm-cert"},
		},
	}
	env := &envelope.Envelope{
		StreamID:  "stream-1",
		FlowID:    "flow-send",
		Direction: envelope.Send,
		Sequence:  0,
		Protocol:  envelope.ProtocolHTTP,
		Message:   &envelope.HTTPMessage{Method: "GET"},
		Context: envelope.EnvelopeContext{
			ConnID: "conn-1",
			TLS:    clientSnap,
		},
	}
	step.Process(context.Background(), env)

	if len(w.updates) != 0 {
		t.Errorf("expected 0 UpdateStream calls for Send, got %d (synthetic MITM "+
			"cert leaked into ConnInfo)", len(w.updates))
	}
}

// TestRecordStep_ReceiveWithoutTLSSkipsUpdate verifies that Receive envelopes
// without a TLS snapshot (e.g., cleartext h2c) do not fire a no-op
// UpdateStream.
func TestRecordStep_ReceiveWithoutTLSSkipsUpdate(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	env := &envelope.Envelope{
		StreamID:  "stream-1",
		FlowID:    "flow-recv",
		Direction: envelope.Receive,
		Sequence:  0,
		Protocol:  envelope.ProtocolHTTP,
		Message:   &envelope.HTTPMessage{Status: 200},
		Context: envelope.EnvelopeContext{
			ConnID: "conn-1",
			// TLS intentionally nil (cleartext)
		},
	}
	step.Process(context.Background(), env)

	if len(w.updates) != 0 {
		t.Errorf("expected 0 UpdateStream calls for cleartext Receive, got %d",
			len(w.updates))
	}
}

func TestRecordStep_FlowFieldsRaw(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	env := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  0,
		Protocol:  envelope.ProtocolRaw,
		Raw:       []byte("raw-bytes"),
		Message:   &envelope.RawMessage{Bytes: []byte("raw-bytes")},
	}
	step.Process(context.Background(), env)

	if len(w.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(w.flows))
	}
	fl := w.flows[0]
	if fl.ID != "f1" {
		t.Errorf("flow ID = %q, want %q", fl.ID, "f1")
	}
	if fl.StreamID != "s1" {
		t.Errorf("flow StreamID = %q, want %q", fl.StreamID, "s1")
	}
	if fl.Direction != "send" {
		t.Errorf("flow Direction = %q, want %q", fl.Direction, "send")
	}
	if string(fl.RawBytes) != "raw-bytes" {
		t.Errorf("flow RawBytes = %q, want %q", fl.RawBytes, "raw-bytes")
	}
	if string(fl.Body) != "raw-bytes" {
		t.Errorf("flow Body = %q, want %q", fl.Body, "raw-bytes")
	}
	if fl.Metadata["protocol"] != "raw" {
		t.Errorf("flow metadata[protocol] = %q, want %q", fl.Metadata["protocol"], "raw")
	}
}

func TestRecordStep_FlowFieldsHTTP(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	env := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  0,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("GET / HTTP/1.1\r\n\r\n"),
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Scheme:    "https",
			Authority: "example.com",
			Path:      "/api",
			RawQuery:  "key=val",
			Headers: []envelope.KeyValue{
				{Name: "Host", Value: "example.com"},
			},
			Body: []byte("body-data"),
		},
	}
	step.Process(context.Background(), env)

	if len(w.streams) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(w.streams))
	}
	if w.streams[0].Scheme != "https" {
		t.Errorf("stream Scheme = %q, want %q", w.streams[0].Scheme, "https")
	}

	if len(w.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(w.flows))
	}
	fl := w.flows[0]
	if fl.Method != "GET" {
		t.Errorf("flow Method = %q, want %q", fl.Method, "GET")
	}
	if fl.URL == nil {
		t.Fatal("flow URL is nil")
	}
	if fl.URL.Path != "/api" {
		t.Errorf("flow URL.Path = %q, want %q", fl.URL.Path, "/api")
	}
	if fl.URL.RawQuery != "key=val" {
		t.Errorf("flow URL.RawQuery = %q, want %q", fl.URL.RawQuery, "key=val")
	}
	if string(fl.Body) != "body-data" {
		t.Errorf("flow Body = %q, want %q", fl.Body, "body-data")
	}
	if fl.Headers["Host"] == nil || fl.Headers["Host"][0] != "example.com" {
		t.Errorf("flow Headers[Host] = %v, want [example.com]", fl.Headers["Host"])
	}
}

func TestRecordStep_HTTPTrailersProjectedToFlow(t *testing.T) {
	// Response with trailers (HTTP/2 trailer-HEADERS or HTTP/1.1 chunked
	// trailers). Projection must be symmetric to Headers and retain
	// duplicate-name values so analysts can observe grpc-status style
	// metadata.
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	env := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Receive,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("HTTP/2 200\r\n\r\nbody\r\n"),
		Message: &envelope.HTTPMessage{
			Status: 200,
			Headers: []envelope.KeyValue{
				{Name: "Trailer", Value: "X-Trailer-1"},
			},
			Trailers: []envelope.KeyValue{
				{Name: "X-Trailer-1", Value: "trailer-value"},
				{Name: "Grpc-Status", Value: "0"},
				{Name: "X-Trailer-1", Value: "second"},
			},
			Body: []byte("body"),
		},
	}
	// Use sequence > 0 to avoid stream creation noise.
	step.Process(context.Background(), env)

	if len(w.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(w.flows))
	}
	fl := w.flows[0]
	if fl.Trailers == nil {
		t.Fatal("flow Trailers is nil; want projected map")
	}
	if got := fl.Trailers["X-Trailer-1"]; len(got) != 2 || got[0] != "trailer-value" || got[1] != "second" {
		t.Errorf("flow Trailers[X-Trailer-1] = %v, want [trailer-value second]", got)
	}
	if got := fl.Trailers["Grpc-Status"]; len(got) != 1 || got[0] != "0" {
		t.Errorf("flow Trailers[Grpc-Status] = %v, want [0]", got)
	}
}

func TestRecordStep_HTTPTrailersEmptyStaysNil(t *testing.T) {
	// An HTTPMessage without trailers must not produce an empty map — the
	// nil-vs-empty distinction keeps round-tripping via SQLite idempotent.
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	env := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  0,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("GET / HTTP/1.1\r\n\r\n"),
		Message: &envelope.HTTPMessage{
			Method: "GET",
			Path:   "/",
		},
	}
	step.Process(context.Background(), env)

	if len(w.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(w.flows))
	}
	if w.flows[0].Trailers != nil {
		t.Errorf("flow Trailers = %v, want nil for message without trailers", w.flows[0].Trailers)
	}
}

func TestRecordStep_VariantRecording(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	// Create a snapshot and modified envelope — simulate Pipeline.Run behavior.
	original := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolRaw,
		Raw:       []byte("original-data"),
		Message:   &envelope.RawMessage{Bytes: []byte("original-data")},
	}

	modified := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolRaw,
		Raw:       []byte("modified-data"),
		Message:   &envelope.RawMessage{Bytes: []byte("modified-data")},
	}

	// Put the original as the snapshot in context.
	ctx := withSnapshot(context.Background(), original)
	step.Process(ctx, modified)

	if len(w.flows) != 2 {
		t.Fatalf("expected 2 flows (variant pair), got %d", len(w.flows))
	}

	origFlow := w.flows[0]
	modFlow := w.flows[1]

	if origFlow.ID != "f1-original" {
		t.Errorf("original flow ID = %q, want %q", origFlow.ID, "f1-original")
	}
	if origFlow.Metadata["variant"] != "original" {
		t.Errorf("original variant = %q, want %q", origFlow.Metadata["variant"], "original")
	}
	if string(origFlow.RawBytes) != "original-data" {
		t.Errorf("original RawBytes = %q, want %q", origFlow.RawBytes, "original-data")
	}

	if modFlow.ID != "f1" {
		t.Errorf("modified flow ID = %q, want %q", modFlow.ID, "f1")
	}
	if modFlow.Metadata["variant"] != "modified" {
		t.Errorf("modified variant = %q, want %q", modFlow.Metadata["variant"], "modified")
	}
	if string(modFlow.RawBytes) != "modified-data" {
		t.Errorf("modified RawBytes = %q, want %q", modFlow.RawBytes, "modified-data")
	}
}

func TestRecordStep_NoVariantWhenUnmodified(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	env := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolRaw,
		Raw:       []byte("same-data"),
		Message:   &envelope.RawMessage{Bytes: []byte("same-data")},
	}

	snap := env.Clone()
	ctx := withSnapshot(context.Background(), snap)
	step.Process(ctx, env)

	if len(w.flows) != 1 {
		t.Fatalf("expected 1 flow (no variant), got %d", len(w.flows))
	}
	if w.flows[0].Metadata["variant"] != "" {
		t.Errorf("unexpected variant metadata: %q", w.flows[0].Metadata["variant"])
	}
}

func TestEnvelopeModified_RawDiff(t *testing.T) {
	a := &envelope.Envelope{
		Raw:     []byte("aaa"),
		Message: &envelope.RawMessage{Bytes: []byte("aaa")},
	}
	b := &envelope.Envelope{
		Raw:     []byte("bbb"),
		Message: &envelope.RawMessage{Bytes: []byte("bbb")},
	}
	if !envelopeModified(a, b) {
		t.Error("expected modified when Raw differs")
	}
}

func TestEnvelopeModified_MessageDiff(t *testing.T) {
	a := &envelope.Envelope{
		Raw:     []byte("same"),
		Message: &envelope.RawMessage{Bytes: []byte("aaa")},
	}
	b := &envelope.Envelope{
		Raw:     []byte("same"),
		Message: &envelope.RawMessage{Bytes: []byte("bbb")},
	}
	if !envelopeModified(a, b) {
		t.Error("expected modified when Message.Bytes differs")
	}
}

func TestEnvelopeModified_Identical(t *testing.T) {
	a := &envelope.Envelope{
		Raw:     []byte("same"),
		Message: &envelope.RawMessage{Bytes: []byte("same")},
	}
	b := &envelope.Envelope{
		Raw:     []byte("same"),
		Message: &envelope.RawMessage{Bytes: []byte("same")},
	}
	if envelopeModified(a, b) {
		t.Error("expected not modified when identical")
	}
}

func TestEnvelopeModified_HTTPMessage(t *testing.T) {
	base := &envelope.HTTPMessage{
		Method:    "GET",
		Path:      "/test",
		Authority: "example.com",
		Headers:   []envelope.KeyValue{{Name: "Host", Value: "example.com"}},
		Body:      []byte("body"),
	}
	same := &envelope.HTTPMessage{
		Method:    "GET",
		Path:      "/test",
		Authority: "example.com",
		Headers:   []envelope.KeyValue{{Name: "Host", Value: "example.com"}},
		Body:      []byte("body"),
	}
	different := &envelope.HTTPMessage{
		Method:    "POST",
		Path:      "/test",
		Authority: "example.com",
		Headers:   []envelope.KeyValue{{Name: "Host", Value: "example.com"}},
		Body:      []byte("body"),
	}

	raw := []byte("raw")
	a := &envelope.Envelope{Raw: raw, Message: base}
	b := &envelope.Envelope{Raw: raw, Message: same}
	c := &envelope.Envelope{Raw: raw, Message: different}

	if envelopeModified(a, b) {
		t.Error("expected not modified for identical HTTPMessage")
	}
	if !envelopeModified(a, c) {
		t.Error("expected modified for different HTTPMessage")
	}
}

// TestRecordStep_VariantRecording_WireEncoder verifies that when a per-
// protocol WireEncoder is registered the modified variant's RawBytes is
// overwritten with the encoder's output while the original variant's
// RawBytes continues to reflect the snapshot (ingress) Raw.
func TestRecordStep_VariantRecording_WireEncoder(t *testing.T) {
	w := &mockWriter{}
	encoded := []byte("ENCODED-MODIFIED-WIRE-BYTES")
	step := NewRecordStep(w, nil,
		WithWireEncoder(envelope.ProtocolHTTP, func(*envelope.Envelope) ([]byte, error) {
			return encoded, nil
		}),
	)

	original := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("GET /orig HTTP/1.1\r\n\r\n"),
		Message:   &envelope.HTTPMessage{Method: "GET", Path: "/orig"},
	}
	modified := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		// Raw intentionally still reflects the ingress bytes — Pipeline
		// never rewrites Raw even when env.Message is mutated.
		Raw:     []byte("GET /orig HTTP/1.1\r\n\r\n"),
		Message: &envelope.HTTPMessage{Method: "GET", Path: "/modified"},
	}

	ctx := withSnapshot(context.Background(), original)
	step.Process(ctx, modified)

	if len(w.flows) != 2 {
		t.Fatalf("expected 2 flows, got %d", len(w.flows))
	}
	origFlow := w.flows[0]
	modFlow := w.flows[1]

	if string(origFlow.RawBytes) != "GET /orig HTTP/1.1\r\n\r\n" {
		t.Errorf("original RawBytes = %q, want ingress Raw", origFlow.RawBytes)
	}
	if origFlow.Metadata["wire_bytes"] != "" {
		t.Errorf("original wire_bytes metadata = %q, want empty",
			origFlow.Metadata["wire_bytes"])
	}
	if string(modFlow.RawBytes) != string(encoded) {
		t.Errorf("modified RawBytes = %q, want %q", modFlow.RawBytes, encoded)
	}
	if modFlow.Metadata["wire_bytes"] != "" {
		t.Errorf("modified wire_bytes metadata = %q, want empty (encoder succeeded fully)",
			modFlow.Metadata["wire_bytes"])
	}
}

// TestRecordStep_VariantRecording_NoEncoderLeavesRawAndTags verifies that
// when no WireEncoder is registered for the protocol but at least one
// encoder exists for other protocols, the modified variant's RawBytes
// remains env.Raw and Metadata["wire_bytes"] is "unavailable".
func TestRecordStep_VariantRecording_NoEncoderLeavesRawAndTags(t *testing.T) {
	w := &mockWriter{}
	// Register an encoder for ProtocolRaw so wireEncoders is non-empty,
	// but the test envelope is ProtocolHTTP — no encoder available for it.
	step := NewRecordStep(w, nil,
		WithWireEncoder(envelope.ProtocolRaw, func(*envelope.Envelope) ([]byte, error) {
			t.Fatal("raw encoder must not be called for http envelope")
			return nil, nil
		}),
	)

	original := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("ORIG"),
		Message:   &envelope.HTTPMessage{Method: "GET"},
	}
	modified := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("ORIG"),
		Message:   &envelope.HTTPMessage{Method: "POST"},
	}

	ctx := withSnapshot(context.Background(), original)
	step.Process(ctx, modified)

	if len(w.flows) != 2 {
		t.Fatalf("expected 2 flows, got %d", len(w.flows))
	}
	modFlow := w.flows[1]
	if string(modFlow.RawBytes) != "ORIG" {
		t.Errorf("modified RawBytes = %q, want env.Raw (%q)", modFlow.RawBytes, "ORIG")
	}
	if modFlow.Metadata["wire_bytes"] != "" {
		t.Errorf("modified wire_bytes metadata = %q, want empty "+
			"(no encoder registered for this protocol at all; tag should be silent)",
			modFlow.Metadata["wire_bytes"])
	}
}

// TestRecordStep_VariantRecording_EncoderErrorTagsUnavailable verifies that
// a WireEncoder error (other than ErrPartialWireBytes) leaves RawBytes as
// env.Raw and tags wire_bytes = "unavailable".
func TestRecordStep_VariantRecording_EncoderErrorTagsUnavailable(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil,
		WithWireEncoder(envelope.ProtocolHTTP, func(*envelope.Envelope) ([]byte, error) {
			return nil, errors.New("encoder broken")
		}),
	)

	original := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("ORIG"),
		Message:   &envelope.HTTPMessage{Method: "GET"},
	}
	modified := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("ORIG"),
		Message:   &envelope.HTTPMessage{Method: "POST"},
	}

	ctx := withSnapshot(context.Background(), original)
	step.Process(ctx, modified)

	if len(w.flows) != 2 {
		t.Fatalf("expected 2 flows, got %d", len(w.flows))
	}
	modFlow := w.flows[1]
	if string(modFlow.RawBytes) != "ORIG" {
		t.Errorf("modified RawBytes = %q, want env.Raw kept on encoder error",
			modFlow.RawBytes)
	}
	if modFlow.Metadata["wire_bytes"] != "unavailable" {
		t.Errorf("modified wire_bytes metadata = %q, want %q",
			modFlow.Metadata["wire_bytes"], "unavailable")
	}
}

// TestRecordStep_VariantRecording_EncoderPartialTagsPartial verifies that
// an encoder returning ErrPartialWireBytes together with a non-nil slice
// writes those bytes and tags wire_bytes = "partial".
func TestRecordStep_VariantRecording_EncoderPartialTagsPartial(t *testing.T) {
	w := &mockWriter{}
	partial := []byte("HEADERS-ONLY")
	step := NewRecordStep(w, nil,
		WithWireEncoder(envelope.ProtocolHTTP, func(*envelope.Envelope) ([]byte, error) {
			return partial, ErrPartialWireBytes
		}),
	)

	original := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("ORIG"),
		Message:   &envelope.HTTPMessage{Method: "GET"},
	}
	modified := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("ORIG"),
		Message:   &envelope.HTTPMessage{Method: "POST"},
	}

	ctx := withSnapshot(context.Background(), original)
	step.Process(ctx, modified)

	if len(w.flows) != 2 {
		t.Fatalf("expected 2 flows, got %d", len(w.flows))
	}
	modFlow := w.flows[1]
	if string(modFlow.RawBytes) != string(partial) {
		t.Errorf("modified RawBytes = %q, want %q (partial encoder output)",
			modFlow.RawBytes, partial)
	}
	if modFlow.Metadata["wire_bytes"] != "partial" {
		t.Errorf("modified wire_bytes metadata = %q, want %q",
			modFlow.Metadata["wire_bytes"], "partial")
	}
}

// TestRecordStep_VariantRecording_OriginalRawNeverRewrittenByEncoder verifies
// that the original variant's RawBytes is sourced from snap.Raw and that the
// WireEncoder (which operates on current) does not influence it.
func TestRecordStep_VariantRecording_OriginalRawNeverRewrittenByEncoder(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil,
		WithWireEncoder(envelope.ProtocolHTTP, func(*envelope.Envelope) ([]byte, error) {
			return []byte("MODIFIED-ONLY"), nil
		}),
	)

	original := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("WIRE-INGRESS"),
		Message:   &envelope.HTTPMessage{Method: "GET"},
	}
	modified := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("WIRE-INGRESS"),
		Message:   &envelope.HTTPMessage{Method: "POST"},
	}

	ctx := withSnapshot(context.Background(), original)
	step.Process(ctx, modified)

	if len(w.flows) != 2 {
		t.Fatalf("expected 2 flows, got %d", len(w.flows))
	}
	if string(w.flows[0].RawBytes) != "WIRE-INGRESS" {
		t.Errorf("original RawBytes = %q, want ingress Raw unmodified",
			w.flows[0].RawBytes)
	}
	if string(w.flows[1].RawBytes) != "MODIFIED-ONLY" {
		t.Errorf("modified RawBytes = %q, want encoder output", w.flows[1].RawBytes)
	}
}

func TestRecordStep_StoreError(t *testing.T) {
	w := &mockWriter{saveErr: errors.New("store unavailable")}
	step := NewRecordStep(w, nil)

	env := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  0,
		Protocol:  envelope.ProtocolRaw,
		Raw:       []byte("data"),
		Message:   &envelope.RawMessage{Bytes: []byte("data")},
	}

	// Should not panic; errors are logged but not returned.
	r := step.Process(context.Background(), env)
	if r.Action != Continue {
		t.Errorf("store error: got action %v, want Continue", r.Action)
	}
}
