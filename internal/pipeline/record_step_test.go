package pipeline

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
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

// TestRecordStep_VariantRecording_EncoderPartialNilBytesTagsUnavailable
// verifies that an encoder that returns ErrPartialWireBytes together with a
// nil byte slice is treated as a contract violation: RawBytes stays as
// env.Raw and wire_bytes is tagged "unavailable", NOT "partial". Tagging
// "partial" on a nil-bytes return would misrepresent the stored ingress Raw
// as a partial re-encode.
func TestRecordStep_VariantRecording_EncoderPartialNilBytesTagsUnavailable(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil,
		WithWireEncoder(envelope.ProtocolHTTP, func(*envelope.Envelope) ([]byte, error) {
			return nil, ErrPartialWireBytes
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
		t.Errorf("modified RawBytes = %q, want env.Raw kept when partial+nil",
			modFlow.RawBytes)
	}
	if modFlow.Metadata["wire_bytes"] != "unavailable" {
		t.Errorf("modified wire_bytes metadata = %q, want %q "+
			"(partial sentinel with nil bytes violates contract)",
			modFlow.Metadata["wire_bytes"], "unavailable")
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

// TestRecordStep_BodyBufferMaterializedToFlowBody verifies that when
// HTTPMessage.Body is nil and BodyBuffer is non-nil, RecordStep materializes
// the buffer via Bytes(ctx) into Flow.Body. Exercises both memory-mode and
// file-mode buffers.
func TestRecordStep_BodyBufferMaterializedToFlowBody(t *testing.T) {
	tests := []struct {
		name     string
		makeBuf  func(t *testing.T) *bodybuf.BodyBuffer
		wantBody []byte
	}{
		{
			name: "memory",
			makeBuf: func(t *testing.T) *bodybuf.BodyBuffer {
				return bodybuf.NewMemory([]byte("memory-body"))
			},
			wantBody: []byte("memory-body"),
		},
		{
			name: "file",
			makeBuf: func(t *testing.T) *bodybuf.BodyBuffer {
				bb, err := bodybuf.NewFile(t.TempDir(), "rec", 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := bb.Write([]byte("file-body")); err != nil {
					t.Fatal(err)
				}
				return bb
			},
			wantBody: []byte("file-body"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &mockWriter{}
			step := NewRecordStep(w, nil)
			bb := tt.makeBuf(t)
			t.Cleanup(func() { _ = bb.Release() })

			env := &envelope.Envelope{
				StreamID:  "s1",
				FlowID:    "f1",
				Direction: envelope.Send,
				Sequence:  0,
				Protocol:  envelope.ProtocolHTTP,
				Raw:       []byte("wire-bytes"),
				Message: &envelope.HTTPMessage{
					Method:     "POST",
					Scheme:     "https",
					Authority:  "example.com",
					Path:       "/api",
					BodyBuffer: bb,
				},
			}
			step.Process(context.Background(), env)

			if len(w.flows) != 1 {
				t.Fatalf("expected 1 flow, got %d", len(w.flows))
			}
			fl := w.flows[0]
			if !bytes.Equal(fl.Body, tt.wantBody) {
				t.Errorf("flow.Body = %q, want %q", fl.Body, tt.wantBody)
			}
			if fl.BodyTruncated {
				t.Error("flow.BodyTruncated = true, want false for sub-cap body")
			}
		})
	}
}

// TestRecordStep_BodyBufferExceedsMaxBodySize_Truncated verifies that a
// materialized body larger than maxBodySize is truncated and
// flow.Flow.BodyTruncated is set to true.
func TestRecordStep_BodyBufferExceedsMaxBodySize_Truncated(t *testing.T) {
	const cap = 10 << 20 // 10 MiB
	const payloadSize = 12 << 20
	payload := bytes.Repeat([]byte("X"), payloadSize)

	w := &mockWriter{}
	step := NewRecordStep(w, nil, WithMaxBodySize(cap))

	bb, err := bodybuf.NewFile(t.TempDir(), "rec", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bb.Release() })
	if _, err := bb.Write(payload); err != nil {
		t.Fatal(err)
	}

	env := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  0,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("wire"),
		Message: &envelope.HTTPMessage{
			Method:     "POST",
			BodyBuffer: bb,
		},
	}
	step.Process(context.Background(), env)

	if len(w.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(w.flows))
	}
	fl := w.flows[0]
	if int64(len(fl.Body)) != cap {
		t.Errorf("flow.Body length = %d, want %d", len(fl.Body), cap)
	}
	if !fl.BodyTruncated {
		t.Error("flow.BodyTruncated = false, want true for over-cap body")
	}
}

// TestRecordStep_MaterializeErrorLogsWarnAndSkipsBody verifies that an error
// from BodyBuffer.Bytes (simulated by Releasing the buffer to dead state)
// leaves Flow.Body nil and does not crash. The Warn log path is exercised;
// we assert the observable outcome (nil Body, no panic, flow still saved).
func TestRecordStep_MaterializeErrorLogsWarnAndSkipsBody(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	bb := bodybuf.NewMemory([]byte("doomed"))
	// Drive refcount to zero so subsequent Bytes(ctx) errors with
	// "bytes after release".
	if err := bb.Release(); err != nil {
		t.Fatal(err)
	}

	env := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  0,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("wire"),
		Message: &envelope.HTTPMessage{
			Method:     "POST",
			BodyBuffer: bb,
		},
	}
	step.Process(context.Background(), env)

	if len(w.flows) != 1 {
		t.Fatalf("expected 1 flow even when materialize fails, got %d", len(w.flows))
	}
	fl := w.flows[0]
	if fl.Body != nil {
		t.Errorf("flow.Body = %q, want nil after materialize error", fl.Body)
	}
	if fl.BodyTruncated {
		t.Error("flow.BodyTruncated = true, want false on materialize error")
	}
}

// TestRecordStep_VariantDetection_BodyBufferToBodyReplacement verifies that
// the variant detection path emits both original and modified flows when
// the snapshot has BodyBuffer!=nil and the current envelope has Body!=nil
// with BodyBuffer==nil — the state produced by Transform.commit.
func TestRecordStep_VariantDetection_BodyBufferToBodyReplacement(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	snapBuf := bodybuf.NewMemory([]byte("original-body-from-buffer"))
	t.Cleanup(func() { _ = snapBuf.Release() })

	snap := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("WIRE-INGRESS"),
		Message: &envelope.HTTPMessage{
			Method:     "POST",
			BodyBuffer: snapBuf,
		},
	}
	// Current: simulate Transform commit — Body set, BodyBuffer niled.
	current := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("WIRE-INGRESS"),
		Message: &envelope.HTTPMessage{
			Method: "POST",
			Body:   []byte("modified-body"),
		},
	}

	ctx := withSnapshot(context.Background(), snap)
	step.Process(ctx, current)

	if len(w.flows) != 2 {
		t.Fatalf("expected 2 flows (variant pair from BodyBuffer→Body), got %d", len(w.flows))
	}
	origFlow := w.flows[0]
	modFlow := w.flows[1]
	if origFlow.Metadata["variant"] != "original" {
		t.Errorf("orig variant = %q, want original", origFlow.Metadata["variant"])
	}
	if !bytes.Equal(origFlow.Body, []byte("original-body-from-buffer")) {
		t.Errorf("orig flow.Body = %q, want materialized snapshot buffer", origFlow.Body)
	}
	if modFlow.Metadata["variant"] != "modified" {
		t.Errorf("mod variant = %q, want modified", modFlow.Metadata["variant"])
	}
	if !bytes.Equal(modFlow.Body, []byte("modified-body")) {
		t.Errorf("mod flow.Body = %q, want modified-body", modFlow.Body)
	}
}

// TestRecordStep_VariantDetection_SameBodyBuffer_NoVariant verifies that
// when snapshot and current share the same BodyBuffer pointer and both
// Body slices are nil, httpMessageModified returns false and only one
// flow is emitted (no variant pair).
func TestRecordStep_VariantDetection_SameBodyBuffer_NoVariant(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	sharedBuf := bodybuf.NewMemory([]byte("shared-buffer-contents"))
	t.Cleanup(func() { _ = sharedBuf.Release() })

	snap := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("WIRE"),
		Message: &envelope.HTTPMessage{
			Method:     "POST",
			BodyBuffer: sharedBuf,
		},
	}
	current := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("WIRE"),
		Message: &envelope.HTTPMessage{
			Method:     "POST",
			BodyBuffer: sharedBuf,
		},
	}

	ctx := withSnapshot(context.Background(), snap)
	step.Process(ctx, current)

	if len(w.flows) != 1 {
		t.Fatalf("expected 1 flow when BodyBuffer pointers match, got %d", len(w.flows))
	}
	if w.flows[0].Metadata["variant"] != "" {
		t.Errorf("unexpected variant tag: %q", w.flows[0].Metadata["variant"])
	}
}

// --- USK-646: WS / gRPC / SSE projection tests ---------------------------

func TestRecordStep_FlowFieldsWSText(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	env := &envelope.Envelope{
		StreamID:  "ws-1",
		FlowID:    "ws-1-f1",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolWebSocket,
		Raw:       []byte{0x81, 0x05, 'h', 'e', 'l', 'l', 'o'},
		Message: &envelope.WSMessage{
			Opcode:     envelope.WSText,
			Fin:        true,
			Compressed: false,
			Payload:    []byte("hello"),
		},
	}
	step.Process(context.Background(), env)

	if len(w.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(w.flows))
	}
	fl := w.flows[0]
	if string(fl.Body) != "hello" {
		t.Errorf("flow Body = %q, want %q", fl.Body, "hello")
	}
	if !bytes.Equal(fl.RawBytes, env.Raw) {
		t.Errorf("flow RawBytes = %v, want %v", fl.RawBytes, env.Raw)
	}
	if got := fl.Metadata["protocol"]; got != "ws" {
		t.Errorf("metadata[protocol] = %q, want ws", got)
	}
	if got := fl.Metadata["ws_opcode"]; got != "1" {
		t.Errorf("metadata[ws_opcode] = %q, want %q", got, "1")
	}
	if got := fl.Metadata["ws_fin"]; got != "true" {
		t.Errorf("metadata[ws_fin] = %q, want true", got)
	}
	if got := fl.Metadata["ws_compressed"]; got != "false" {
		t.Errorf("metadata[ws_compressed] = %q, want false", got)
	}
	if _, has := fl.Metadata["ws_close_code"]; has {
		t.Errorf("non-Close frame must not emit ws_close_code (got %q)",
			fl.Metadata["ws_close_code"])
	}
	if _, has := fl.Metadata["ws_close_reason"]; has {
		t.Errorf("non-Close frame must not emit ws_close_reason")
	}
}

func TestRecordStep_FlowFieldsWSCloseFrame(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	env := &envelope.Envelope{
		StreamID:  "ws-1",
		FlowID:    "ws-1-close",
		Direction: envelope.Receive,
		Sequence:  5,
		Protocol:  envelope.ProtocolWebSocket,
		Raw:       []byte{0x88, 0x06, 0x03, 0xe8, 'b', 'y', 'e', '!'},
		Message: &envelope.WSMessage{
			Opcode:      envelope.WSClose,
			Fin:         true,
			Compressed:  false,
			CloseCode:   1000,
			CloseReason: "bye!",
			Payload:     []byte{0x03, 0xe8, 'b', 'y', 'e', '!'},
		},
	}
	step.Process(context.Background(), env)

	if len(w.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(w.flows))
	}
	fl := w.flows[0]
	if got := fl.Metadata["ws_opcode"]; got != "8" {
		t.Errorf("metadata[ws_opcode] = %q, want 8", got)
	}
	if got := fl.Metadata["ws_close_code"]; got != "1000" {
		t.Errorf("metadata[ws_close_code] = %q, want 1000", got)
	}
	if got := fl.Metadata["ws_close_reason"]; got != "bye!" {
		t.Errorf("metadata[ws_close_reason] = %q, want bye!", got)
	}
}

func TestRecordStep_FlowFieldsGRPCStart(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	env := &envelope.Envelope{
		StreamID:  "rpc-1",
		FlowID:    "rpc-1-start",
		Direction: envelope.Send,
		Sequence:  0,
		Protocol:  envelope.ProtocolGRPC,
		Raw:       []byte("hpack-encoded-start"),
		Message: &envelope.GRPCStartMessage{
			Service:     "helloworld.Greeter",
			Method:      "SayHello",
			ContentType: "application/grpc+proto",
			Encoding:    "gzip",
			Metadata: []envelope.KeyValue{
				{Name: "grpc-timeout", Value: "1S"},
				{Name: "user-agent", Value: "grpc-go/1.0"},
				{Name: "user-agent", Value: "second-ua"},
			},
		},
	}
	step.Process(context.Background(), env)

	if len(w.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(w.flows))
	}
	fl := w.flows[0]
	if got := fl.Metadata["grpc_event"]; got != "start" {
		t.Errorf("metadata[grpc_event] = %q, want start", got)
	}
	if got := fl.Metadata["grpc_service"]; got != "helloworld.Greeter" {
		t.Errorf("metadata[grpc_service] = %q", got)
	}
	if got := fl.Metadata["grpc_method"]; got != "SayHello" {
		t.Errorf("metadata[grpc_method] = %q", got)
	}
	if got := fl.Metadata["grpc_content_type"]; got != "application/grpc+proto" {
		t.Errorf("metadata[grpc_content_type] = %q", got)
	}
	if got := fl.Metadata["grpc_encoding"]; got != "gzip" {
		t.Errorf("metadata[grpc_encoding] = %q", got)
	}
	if fl.Headers == nil {
		t.Fatal("expected Headers populated from gRPC metadata")
	}
	if got := fl.Headers["grpc-timeout"]; len(got) != 1 || got[0] != "1S" {
		t.Errorf("Headers[grpc-timeout] = %v", got)
	}
	if got := fl.Headers["user-agent"]; len(got) != 2 || got[0] != "grpc-go/1.0" || got[1] != "second-ua" {
		t.Errorf("Headers[user-agent] = %v, want duplicate-name preserved order", got)
	}
	if !bytes.Equal(fl.RawBytes, env.Raw) {
		t.Errorf("flow RawBytes did not preserve env.Raw")
	}
}

func TestRecordStep_FlowFieldsGRPCStartOptionalsOmitted(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	env := &envelope.Envelope{
		StreamID:  "rpc-1",
		FlowID:    "rpc-1-start",
		Direction: envelope.Send,
		Sequence:  0,
		Protocol:  envelope.ProtocolGRPC,
		Message: &envelope.GRPCStartMessage{
			Service: "svc.S",
			Method:  "M",
		},
	}
	step.Process(context.Background(), env)

	if len(w.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(w.flows))
	}
	fl := w.flows[0]
	if _, has := fl.Metadata["grpc_content_type"]; has {
		t.Errorf("empty content_type must not be emitted")
	}
	if _, has := fl.Metadata["grpc_encoding"]; has {
		t.Errorf("empty encoding must not be emitted")
	}
	if fl.Headers != nil {
		t.Errorf("Headers must remain nil when Metadata is empty (got %v)", fl.Headers)
	}
}

func TestRecordStep_FlowFieldsGRPCData(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	wirePrefix := []byte{0x01, 0x00, 0x00, 0x00, 0x05}
	wireBody := append(wirePrefix, []byte("compr")...)
	env := &envelope.Envelope{
		StreamID:  "rpc-1",
		FlowID:    "rpc-1-data-0",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolGRPC,
		Raw:       wireBody,
		Message: &envelope.GRPCDataMessage{
			Service:    "svc.S",
			Method:     "M",
			Compressed: true,
			WireLength: 5,
			Payload:    []byte("plain"),
		},
	}
	step.Process(context.Background(), env)

	fl := w.flows[0]
	if got := fl.Metadata["grpc_event"]; got != "data" {
		t.Errorf("metadata[grpc_event] = %q, want data", got)
	}
	if got := fl.Metadata["grpc_service"]; got != "svc.S" {
		t.Errorf("metadata[grpc_service] = %q", got)
	}
	if got := fl.Metadata["grpc_method"]; got != "M" {
		t.Errorf("metadata[grpc_method] = %q", got)
	}
	if got := fl.Metadata["grpc_compressed"]; got != "true" {
		t.Errorf("metadata[grpc_compressed] = %q, want true", got)
	}
	if got := fl.Metadata["grpc_wire_length"]; got != "5" {
		t.Errorf("metadata[grpc_wire_length] = %q, want 5", got)
	}
	if string(fl.Body) != "plain" {
		t.Errorf("flow Body = %q, want decompressed payload", fl.Body)
	}
	if !bytes.Equal(fl.RawBytes, wireBody) {
		t.Errorf("flow RawBytes did not preserve LPM wire form")
	}
}

func TestRecordStep_FlowFieldsGRPCEnd(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	details := []byte{0x0a, 0x05, 'h', 'e', 'l', 'l', 'o'}
	env := &envelope.Envelope{
		StreamID:  "rpc-1",
		FlowID:    "rpc-1-end",
		Direction: envelope.Receive,
		Sequence:  9,
		Protocol:  envelope.ProtocolGRPC,
		Raw:       []byte("hpack-encoded-end"),
		Message: &envelope.GRPCEndMessage{
			Status:        13,
			Message:       "internal error",
			StatusDetails: details,
			Trailers: []envelope.KeyValue{
				{Name: "x-trailer", Value: "v1"},
				{Name: "x-trailer", Value: "v2"},
			},
		},
	}
	step.Process(context.Background(), env)

	fl := w.flows[0]
	if got := fl.Metadata["grpc_event"]; got != "end" {
		t.Errorf("metadata[grpc_event] = %q, want end", got)
	}
	if got := fl.Metadata["grpc_status"]; got != "13" {
		t.Errorf("metadata[grpc_status] = %q, want 13", got)
	}
	if got := fl.Metadata["grpc_message"]; got != "internal error" {
		t.Errorf("metadata[grpc_message] = %q", got)
	}
	wantB64 := base64.StdEncoding.EncodeToString(details)
	if got := fl.Metadata["grpc_status_details_bin"]; got != wantB64 {
		t.Errorf("metadata[grpc_status_details_bin] = %q, want %q", got, wantB64)
	}
	if fl.Trailers == nil {
		t.Fatal("expected Trailers populated")
	}
	if got := fl.Trailers["x-trailer"]; len(got) != 2 || got[0] != "v1" || got[1] != "v2" {
		t.Errorf("Trailers[x-trailer] = %v", got)
	}
	// gRPC End must not pollute service/method (RFC §3.2.3 — End only carries
	// trailers).
	if _, has := fl.Metadata["grpc_service"]; has {
		t.Errorf("End must not emit grpc_service (got %q)", fl.Metadata["grpc_service"])
	}
}

func TestRecordStep_FlowFieldsGRPCEndOptionalsOmitted(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	env := &envelope.Envelope{
		StreamID:  "rpc-ok",
		FlowID:    "rpc-ok-end",
		Direction: envelope.Receive,
		Sequence:  5,
		Protocol:  envelope.ProtocolGRPC,
		Message: &envelope.GRPCEndMessage{
			Status: 0,
		},
	}
	step.Process(context.Background(), env)

	fl := w.flows[0]
	if got := fl.Metadata["grpc_status"]; got != "0" {
		t.Errorf("metadata[grpc_status] = %q, want 0", got)
	}
	if _, has := fl.Metadata["grpc_message"]; has {
		t.Errorf("empty grpc-message must not be emitted")
	}
	if _, has := fl.Metadata["grpc_status_details_bin"]; has {
		t.Errorf("empty grpc-status-details-bin must not be emitted")
	}
	if fl.Trailers != nil {
		t.Errorf("Trailers must remain nil when no trailers (got %v)", fl.Trailers)
	}
}

func TestRecordStep_FlowFieldsSSEFull(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	env := &envelope.Envelope{
		StreamID:  "sse-1",
		FlowID:    "sse-1-evt",
		Direction: envelope.Receive,
		Sequence:  3,
		Protocol:  envelope.ProtocolSSE,
		Raw:       []byte("event: ping\ndata: hi\nid: 42\nretry: 1500\n\n"),
		Message: &envelope.SSEMessage{
			Event: "ping",
			Data:  "hi",
			ID:    "42",
			Retry: 1500 * time.Millisecond,
		},
	}
	step.Process(context.Background(), env)

	fl := w.flows[0]
	if string(fl.Body) != "hi" {
		t.Errorf("flow Body = %q, want hi", fl.Body)
	}
	if got := fl.Metadata["sse_event"]; got != "ping" {
		t.Errorf("metadata[sse_event] = %q, want ping", got)
	}
	if got := fl.Metadata["sse_id"]; got != "42" {
		t.Errorf("metadata[sse_id] = %q, want 42", got)
	}
	if got := fl.Metadata["sse_retry_ms"]; got != "1500" {
		t.Errorf("metadata[sse_retry_ms] = %q, want 1500", got)
	}
	if !bytes.Equal(fl.RawBytes, env.Raw) {
		t.Errorf("flow RawBytes did not preserve env.Raw")
	}
}

func TestRecordStep_FlowFieldsSSEOptionalsOmitted(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	env := &envelope.Envelope{
		StreamID:  "sse-1",
		FlowID:    "sse-1-evt",
		Direction: envelope.Receive,
		Sequence:  1,
		Protocol:  envelope.ProtocolSSE,
		Raw:       []byte("data: payload-only\n\n"),
		Message: &envelope.SSEMessage{
			Data: "payload-only",
		},
	}
	step.Process(context.Background(), env)

	fl := w.flows[0]
	if string(fl.Body) != "payload-only" {
		t.Errorf("flow Body = %q", fl.Body)
	}
	for _, k := range []string{"sse_event", "sse_id", "sse_retry_ms"} {
		if _, has := fl.Metadata[k]; has {
			t.Errorf("optional metadata %q emitted on empty/zero field (=%q)", k, fl.Metadata[k])
		}
	}
}

// --- USK-646: messageModified for new types ------------------------------

func TestEnvelopeModified_WSPayload(t *testing.T) {
	a := &envelope.Envelope{Message: &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Payload: []byte("aa")}}
	b := &envelope.Envelope{Message: &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Payload: []byte("bb")}}
	if !envelopeModified(a, b) {
		t.Error("expected modified when WS payload differs")
	}
}

func TestEnvelopeModified_WSOpcode(t *testing.T) {
	a := &envelope.Envelope{Message: &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Payload: []byte("x")}}
	b := &envelope.Envelope{Message: &envelope.WSMessage{Opcode: envelope.WSBinary, Fin: true, Payload: []byte("x")}}
	if !envelopeModified(a, b) {
		t.Error("expected modified when WS opcode differs")
	}
}

func TestEnvelopeModified_WSMaskIgnored(t *testing.T) {
	// Masked/Mask are wire-level masking artifacts; differences must NOT
	// trigger variant recording. Re-masking on Send would otherwise produce
	// false-positive variants for every client→server frame.
	a := &envelope.Envelope{Message: &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Masked: true, Mask: [4]byte{1, 2, 3, 4}, Payload: []byte("hi")}}
	b := &envelope.Envelope{Message: &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Masked: false, Mask: [4]byte{}, Payload: []byte("hi")}}
	if envelopeModified(a, b) {
		t.Error("Masked/Mask differences must not trigger variant detection")
	}
}

func TestEnvelopeModified_GRPCStartMetadata(t *testing.T) {
	a := &envelope.Envelope{Message: &envelope.GRPCStartMessage{
		Service:  "S",
		Method:   "M",
		Metadata: []envelope.KeyValue{{Name: "k", Value: "v1"}},
	}}
	b := &envelope.Envelope{Message: &envelope.GRPCStartMessage{
		Service:  "S",
		Method:   "M",
		Metadata: []envelope.KeyValue{{Name: "k", Value: "v2"}},
	}}
	if !envelopeModified(a, b) {
		t.Error("expected modified when GRPCStart metadata value differs")
	}
}

func TestEnvelopeModified_GRPCStartAcceptEncoding(t *testing.T) {
	a := &envelope.Envelope{Message: &envelope.GRPCStartMessage{Service: "S", Method: "M", AcceptEncoding: []string{"gzip"}}}
	b := &envelope.Envelope{Message: &envelope.GRPCStartMessage{Service: "S", Method: "M", AcceptEncoding: []string{"identity"}}}
	if !envelopeModified(a, b) {
		t.Error("expected modified when AcceptEncoding differs")
	}
}

func TestEnvelopeModified_GRPCDataPayload(t *testing.T) {
	a := &envelope.Envelope{Message: &envelope.GRPCDataMessage{Service: "S", Method: "M", Payload: []byte("a")}}
	b := &envelope.Envelope{Message: &envelope.GRPCDataMessage{Service: "S", Method: "M", Payload: []byte("b")}}
	if !envelopeModified(a, b) {
		t.Error("expected modified when GRPCData payload differs")
	}
}

func TestEnvelopeModified_GRPCDataServiceDefensive(t *testing.T) {
	// Service/Method are denormalized read-only on Data, but defensive compare
	// catches an errant Step that mutates them.
	a := &envelope.Envelope{Message: &envelope.GRPCDataMessage{Service: "S1", Method: "M", Payload: []byte("x")}}
	b := &envelope.Envelope{Message: &envelope.GRPCDataMessage{Service: "S2", Method: "M", Payload: []byte("x")}}
	if !envelopeModified(a, b) {
		t.Error("expected modified when GRPCData service is mutated")
	}
}

func TestEnvelopeModified_GRPCEndStatus(t *testing.T) {
	a := &envelope.Envelope{Message: &envelope.GRPCEndMessage{Status: 0}}
	b := &envelope.Envelope{Message: &envelope.GRPCEndMessage{Status: 13}}
	if !envelopeModified(a, b) {
		t.Error("expected modified when GRPCEnd status differs")
	}
}

func TestEnvelopeModified_GRPCEndTrailers(t *testing.T) {
	a := &envelope.Envelope{Message: &envelope.GRPCEndMessage{Trailers: []envelope.KeyValue{{Name: "k", Value: "v1"}}}}
	b := &envelope.Envelope{Message: &envelope.GRPCEndMessage{Trailers: []envelope.KeyValue{{Name: "k", Value: "v2"}}}}
	if !envelopeModified(a, b) {
		t.Error("expected modified when GRPCEnd trailers differ")
	}
}

func TestEnvelopeModified_SSEData(t *testing.T) {
	a := &envelope.Envelope{Message: &envelope.SSEMessage{Event: "e", Data: "old"}}
	b := &envelope.Envelope{Message: &envelope.SSEMessage{Event: "e", Data: "new"}}
	if !envelopeModified(a, b) {
		t.Error("expected modified when SSE data differs")
	}
}

func TestEnvelopeModified_SSEUnchanged(t *testing.T) {
	a := &envelope.Envelope{Message: &envelope.SSEMessage{Event: "e", Data: "x", ID: "1", Retry: 100 * time.Millisecond}}
	b := &envelope.Envelope{Message: &envelope.SSEMessage{Event: "e", Data: "x", ID: "1", Retry: 100 * time.Millisecond}}
	if envelopeModified(a, b) {
		t.Error("expected unchanged when all SSE fields equal")
	}
}

func TestRecordStep_VariantRecordingGRPCData(t *testing.T) {
	// Full variant pair test for GRPCDataMessage — exercises envelopeModified
	// + recordVariantFlows + envelopeToFlow's gRPC branch end-to-end.
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	original := &envelope.Envelope{
		StreamID:  "rpc-1",
		FlowID:    "rpc-1-data-0",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolGRPC,
		Raw:       []byte{0x00, 0x00, 0x00, 0x00, 0x03, 'a', 'b', 'c'},
		Message: &envelope.GRPCDataMessage{
			Service:    "S",
			Method:     "M",
			Compressed: false,
			WireLength: 3,
			Payload:    []byte("abc"),
		},
	}
	modified := &envelope.Envelope{
		StreamID:  "rpc-1",
		FlowID:    "rpc-1-data-0",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolGRPC,
		Raw:       []byte{0x00, 0x00, 0x00, 0x00, 0x03, 'x', 'y', 'z'},
		Message: &envelope.GRPCDataMessage{
			Service:    "S",
			Method:     "M",
			Compressed: false,
			WireLength: 3,
			Payload:    []byte("xyz"),
		},
	}

	ctx := withSnapshot(context.Background(), original)
	step.Process(ctx, modified)

	if len(w.flows) != 2 {
		t.Fatalf("expected 2 flows (variant pair), got %d", len(w.flows))
	}
	if w.flows[0].ID != "rpc-1-data-0-original" || w.flows[0].Metadata["variant"] != "original" {
		t.Errorf("flow[0] = %+v, want original variant", w.flows[0])
	}
	if w.flows[1].ID != "rpc-1-data-0" || w.flows[1].Metadata["variant"] != "modified" {
		t.Errorf("flow[1] = %+v, want modified variant", w.flows[1])
	}
	if string(w.flows[0].Body) != "abc" || string(w.flows[1].Body) != "xyz" {
		t.Errorf("variant Body mismatch: original=%q modified=%q",
			w.flows[0].Body, w.flows[1].Body)
	}
}
