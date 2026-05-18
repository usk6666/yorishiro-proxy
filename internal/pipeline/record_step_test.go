package pipeline

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

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

// uniqueConstraintWriter is a flow.Writer test double that mimics the SQLite
// schema's V11 UNIQUE(stream_id, sequence, direction, variant) constraint on
// the flows table. It is used by USK-735 regression tests to assert that the
// modified-variant record can coexist with the original under that constraint.
type uniqueConstraintWriter struct {
	streams    []*flow.Stream
	flows      []*flow.Flow
	seen       map[string]struct{}
	collisions int
}

func (m *uniqueConstraintWriter) SaveStream(_ context.Context, s *flow.Stream) error {
	m.streams = append(m.streams, s)
	return nil
}

func (m *uniqueConstraintWriter) UpdateStream(_ context.Context, _ string, _ flow.StreamUpdate) error {
	return nil
}

func (m *uniqueConstraintWriter) SaveFlow(_ context.Context, f *flow.Flow) error {
	variant := ""
	if f.Metadata != nil {
		variant = f.Metadata["variant"]
	}
	key := f.StreamID + "\x00" + f.Direction + "\x00" + strconv.Itoa(f.Sequence) + "\x00" + variant
	if _, dup := m.seen[key]; dup {
		m.collisions++
		return errors.New("UNIQUE constraint failed: flows.stream_id, flows.sequence, flows.direction, flows.variant")
	}
	m.seen[key] = struct{}{}
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

// TestRecordStep_HTTPVersionProjectedToFlow pins that HTTPMessage.HTTPVersion
// (USK-788) is copied onto the persisted Flow. Each canonical wire-version
// value is exercised so any future projection refactor cannot silently
// regress to leaving the field empty.
func TestRecordStep_HTTPVersionProjectedToFlow(t *testing.T) {
	cases := []struct {
		name        string
		httpVersion string
	}{
		{name: "http/1.0", httpVersion: envelope.HTTPVersion10},
		{name: "http/1.1", httpVersion: envelope.HTTPVersion11},
		{name: "h2", httpVersion: envelope.HTTPVersionH2},
		{name: "h2c", httpVersion: envelope.HTTPVersionH2C},
		{name: "empty (non-HTTP / legacy)", httpVersion: ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
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
					Method:      "GET",
					Path:        "/",
					HTTPVersion: tc.httpVersion,
				},
			}
			step.Process(context.Background(), env)

			if len(w.flows) != 1 {
				t.Fatalf("expected 1 flow, got %d", len(w.flows))
			}
			if got := w.flows[0].HTTPVersion; got != tc.httpVersion {
				t.Errorf("flow HTTPVersion = %q, want %q", got, tc.httpVersion)
			}
		})
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

	// USK-878: variant identity is recorded in Metadata, not in the FlowID
	// string. The original-variant row carries the wire-observed FlowID
	// verbatim; the modified-variant row gets a fresh UUID so the import
	// path's strict UUID validation accepts the round-trip. The pair stays
	// linkable via Metadata["base_flow_id"] on the modified row.
	if origFlow.ID != "f1" {
		t.Errorf("original flow ID = %q, want %q", origFlow.ID, "f1")
	}
	if origFlow.Metadata["variant"] != "original" {
		t.Errorf("original variant = %q, want %q", origFlow.Metadata["variant"], "original")
	}
	if string(origFlow.RawBytes) != "original-data" {
		t.Errorf("original RawBytes = %q, want %q", origFlow.RawBytes, "original-data")
	}

	if modFlow.ID == "" {
		t.Error("modified flow ID is empty; expected a fresh UUID")
	}
	if _, err := uuid.Parse(modFlow.ID); err != nil {
		t.Errorf("modified flow ID = %q, want a valid UUID (parse err: %v)", modFlow.ID, err)
	}
	if modFlow.Metadata["variant"] != "modified" {
		t.Errorf("modified variant = %q, want %q", modFlow.Metadata["variant"], "modified")
	}
	if modFlow.Metadata["base_flow_id"] != "f1" {
		t.Errorf("modified base_flow_id = %q, want %q", modFlow.Metadata["base_flow_id"], "f1")
	}
	if string(modFlow.RawBytes) != "modified-data" {
		t.Errorf("modified RawBytes = %q, want %q", modFlow.RawBytes, "modified-data")
	}
	// USK-735 / USK-878: the original and modified variant FlowIDs must
	// differ so the SQLite PRIMARY KEY accepts both rows. StreamID,
	// Sequence, Direction are identical across the variant pair by design
	// — the schemaV11 `variant` column disambiguates them on the SQL UNIQUE
	// constraint, and the FlowID stays distinct only to satisfy the PK.
	if origFlow.ID == modFlow.ID {
		t.Errorf("variant FlowIDs collide: orig=%q mod=%q", origFlow.ID, modFlow.ID)
	}
}

// TestRecordStep_VariantRecording_NoSaveError pins USK-735: a real flow.Writer
// (the SQLite-style UNIQUE(stream_id, sequence, direction) constraint) must
// not produce a save error when both variants of an intercept rewrite are
// recorded. Before USK-735 the modified variant inherited the same FlowID as
// the snapshot and only the FlowID column on flow.Flow distinguishes the two,
// so SaveFlow silently failed on every modify_and_forward.
func TestRecordStep_VariantRecording_NoSaveError(t *testing.T) {
	w := &uniqueConstraintWriter{
		seen: make(map[string]struct{}),
	}
	step := NewRecordStep(w, nil)

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

	ctx := withSnapshot(context.Background(), original)
	step.Process(ctx, modified)

	if w.collisions != 0 {
		t.Errorf("UNIQUE collision occurred %d time(s); modified variant FlowID must differ from original",
			w.collisions)
	}
	if len(w.flows) != 2 {
		t.Fatalf("expected 2 flows persisted, got %d", len(w.flows))
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

// TestRecordStep_ModifiedVariant_RawOnly_RawWins covers USK-686 / RFC §9.3 D4:
// when a preceding Step (PluginStepPost on MutationRawOnly) marks the
// context's RawAuthoritative flag, RecordStep must skip applyWireEncode
// and record env.Raw verbatim into the modified-variant flow's RawBytes.
// Calling the encoder would overwrite the user's smuggling-test bytes
// with a "cleaned-up" re-encoded form, destroying the diagnostic signal
// that motivated D4.
func TestRecordStep_ModifiedVariant_RawOnly_RawWins(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil,
		WithWireEncoder(envelope.ProtocolHTTP, func(*envelope.Envelope) ([]byte, error) {
			t.Fatal("encoder must NOT be called when RawAuthoritative is set (RFC §9.3 D4)")
			return nil, nil
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
	// MutationRawOnly: Message stays the same as snapshot; Raw is the
	// user's verbatim bytes (smuggling payload, intentionally malformed).
	userVerbatim := []byte("GET /orig HTTP/1.1\r\nX-Smuggle: a\r\n\r\nbody")
	modified := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       userVerbatim,
		Message:   &envelope.HTTPMessage{Method: "GET", Path: "/orig"},
	}

	ctx := withWireEncodedState(context.Background())
	markRawAuthoritative(ctx)
	ctx = withSnapshot(ctx, original)
	step.Process(ctx, modified)

	if len(w.flows) != 2 {
		t.Fatalf("expected 2 flows (original + modified variants), got %d", len(w.flows))
	}
	origFlow := w.flows[0]
	modFlow := w.flows[1]

	if string(origFlow.RawBytes) != "GET /orig HTTP/1.1\r\n\r\n" {
		t.Errorf("original RawBytes = %q, want snapshot ingress Raw", origFlow.RawBytes)
	}
	if !bytes.Equal(modFlow.RawBytes, userVerbatim) {
		t.Errorf("modified RawBytes = %q, want user-verbatim bytes (D4 raw-wins)",
			modFlow.RawBytes)
	}
	if got := modFlow.Metadata["wire_bytes"]; got != "" {
		t.Errorf("modified wire_bytes metadata = %q, want empty (encoder skipped, not unavailable)",
			got)
	}
	if modFlow.Metadata["variant"] != "modified" {
		t.Errorf("modified variant tag = %q, want %q",
			modFlow.Metadata["variant"], "modified")
	}
}

// TestRecordStep_ModifiedVariant_Both_RawWins covers USK-686 / RFC §9.3 D4:
// when a plugin produces MutationBoth (modifies BOTH msg["raw"] AND a
// Message field), Raw still wins. RecordStep must record env.Raw verbatim
// in the modified-variant flow even though the Message field divergence
// would normally be the encoder's input. The Message-side mutation is
// preserved in modFlow.Method/Headers/etc. for typed inspection but does
// NOT drive RawBytes.
func TestRecordStep_ModifiedVariant_Both_RawWins(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil,
		WithWireEncoder(envelope.ProtocolHTTP, func(*envelope.Envelope) ([]byte, error) {
			t.Fatal("encoder must NOT be called when RawAuthoritative is set (RFC §9.3 D4)")
			return nil, nil
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
	userVerbatim := []byte("POST /modified HTTP/1.1\r\nContent-Length: 4\r\n\r\nDATA")
	modified := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       userVerbatim,
		// Both Raw AND Message changed — MutationBoth.
		Message: &envelope.HTTPMessage{Method: "POST", Path: "/modified"},
	}

	ctx := withWireEncodedState(context.Background())
	markRawAuthoritative(ctx)
	ctx = withSnapshot(ctx, original)
	step.Process(ctx, modified)

	if len(w.flows) != 2 {
		t.Fatalf("expected 2 flows, got %d", len(w.flows))
	}
	modFlow := w.flows[1]

	if !bytes.Equal(modFlow.RawBytes, userVerbatim) {
		t.Errorf("modified RawBytes = %q, want user-verbatim bytes (D4 raw-wins despite Message change)",
			modFlow.RawBytes)
	}
	// Message-side projection still reflects the Message divergence.
	if modFlow.Method != "POST" {
		t.Errorf("modified Method = %q, want %q (Message projection independent of D4)",
			modFlow.Method, "POST")
	}
	if got := modFlow.Metadata["wire_bytes"]; got != "" {
		t.Errorf("modified wire_bytes metadata = %q, want empty", got)
	}
}

// TestRecordStep_FlowRawBytes_FullWireBytes is a USK-773 regression guard:
// when an HTTP/1.x channel hands a chunked envelope with Envelope.Raw
// containing the complete wire bytes (header section + chunk-framed body),
// the RecordStep must project those full bytes into Flow.RawBytes verbatim
// without any normalization, dechunking, or truncation.
func TestRecordStep_FlowRawBytes_FullWireBytes(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	// Hand-crafted chunked wire: header + multi-chunk body + trailer.
	wire := []byte("HTTP/1.1 200 OK\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"5\r\nhello\r\n" +
		"6;ext=v\r\n world\r\n" +
		"A\r\n0123456789\r\n" +
		"0\r\nX-Trailer: yes\r\n\r\n")
	env := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Receive,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       wire,
		Message: &envelope.HTTPMessage{
			Status:       200,
			StatusReason: "OK",
			Body:         []byte("hello world0123456789"),
		},
	}

	step.Process(context.Background(), env)

	if len(w.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(w.flows))
	}
	fl := w.flows[0]
	if !bytes.Equal(fl.RawBytes, wire) {
		t.Errorf("Flow.RawBytes does not preserve full wire snapshot:\n got=%q\nwant=%q",
			fl.RawBytes, wire)
	}
	// Sanity: chunk framing markers survived projection.
	for _, marker := range []string{
		"Transfer-Encoding: chunked",
		"5\r\nhello\r\n",
		"6;ext=v\r\n",
		"0\r\nX-Trailer: yes\r\n\r\n",
	} {
		if !bytes.Contains(fl.RawBytes, []byte(marker)) {
			t.Errorf("Flow.RawBytes missing chunk marker %q", marker)
		}
	}
}

// TestRecordStep_FlowRawBytes_VariantPreservesFullWire is a USK-773 + USK-686
// regression guard: when both original and modified envelopes carry full
// wire bytes (USK-773 promotes Envelope.Raw to header+body), the variant
// recording path must preserve the full wire bytes for the original variant
// (snap.Raw is verbatim) and use the WireEncoder output (which is also full
// wire bytes) for the modified variant.
func TestRecordStep_FlowRawBytes_VariantPreservesFullWire(t *testing.T) {
	origWire := []byte("HTTP/1.1 200 OK\r\n" +
		"Content-Length: 5\r\n" +
		"\r\n" +
		"hello")
	modWire := []byte("HTTP/1.1 200 OK\r\n" +
		"Content-Length: 7\r\n" +
		"X-Injected: yes\r\n" +
		"\r\n" +
		"goodbye")

	w := &mockWriter{}
	step := NewRecordStep(w, nil,
		WithWireEncoder(envelope.ProtocolHTTP, func(e *envelope.Envelope) ([]byte, error) {
			// Stand-in for the http1 layer's EncodeWireBytes — returns the
			// full wire snapshot for the modified variant.
			return modWire, nil
		}),
	)

	original := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Receive,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       origWire,
		Message: &envelope.HTTPMessage{
			Status:  200,
			Headers: []envelope.KeyValue{{Name: "Content-Length", Value: "5"}},
			Body:    []byte("hello"),
		},
	}
	modified := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Receive,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       origWire, // ingress Raw still snap.Raw — encoder produces post-mutation bytes
		Message: &envelope.HTTPMessage{
			Status: 200,
			Headers: []envelope.KeyValue{
				{Name: "Content-Length", Value: "7"},
				{Name: "X-Injected", Value: "yes"},
			},
			Body: []byte("goodbye"),
		},
	}

	ctx := withSnapshot(context.Background(), original)
	step.Process(ctx, modified)

	if len(w.flows) != 2 {
		t.Fatalf("expected 2 flows (original + modified), got %d", len(w.flows))
	}
	origFlow, modFlow := w.flows[0], w.flows[1]

	if !bytes.Equal(origFlow.RawBytes, origWire) {
		t.Errorf("original Flow.RawBytes lost full wire snapshot:\n got=%q\nwant=%q",
			origFlow.RawBytes, origWire)
	}
	if !bytes.Equal(modFlow.RawBytes, modWire) {
		t.Errorf("modified Flow.RawBytes did not match encoder output:\n got=%q\nwant=%q",
			modFlow.RawBytes, modWire)
	}

	// Variant tags.
	if origFlow.Metadata["variant"] != "original" {
		t.Errorf("original variant tag = %q, want %q", origFlow.Metadata["variant"], "original")
	}
	if modFlow.Metadata["variant"] != "modified" {
		t.Errorf("modified variant tag = %q, want %q", modFlow.Metadata["variant"], "modified")
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
	// USK-878: original-variant keeps the wire-observed FlowID verbatim;
	// modified-variant gets a fresh UUID. Pairing is via Metadata.
	if w.flows[0].ID != "rpc-1-data-0" || w.flows[0].Metadata["variant"] != "original" {
		t.Errorf("flow[0] = %+v, want original variant with ID=%q", w.flows[0], "rpc-1-data-0")
	}
	if _, err := uuid.Parse(w.flows[1].ID); err != nil {
		t.Errorf("modified flow ID = %q, want a valid UUID (parse err: %v)", w.flows[1].ID, err)
	}
	if w.flows[1].Metadata["variant"] != "modified" {
		t.Errorf("flow[1] variant = %q, want %q", w.flows[1].Metadata["variant"], "modified")
	}
	if w.flows[1].Metadata["base_flow_id"] != "rpc-1-data-0" {
		t.Errorf("flow[1] base_flow_id = %q, want %q", w.flows[1].Metadata["base_flow_id"], "rpc-1-data-0")
	}
	if w.flows[0].ID == w.flows[1].ID {
		t.Errorf("variant FlowIDs collide: orig=%q mod=%q", w.flows[0].ID, w.flows[1].ID)
	}
	if string(w.flows[0].Body) != "abc" || string(w.flows[1].Body) != "xyz" {
		t.Errorf("variant Body mismatch: original=%q modified=%q",
			w.flows[0].Body, w.flows[1].Body)
	}
}

// TestRecordStep_FlowRawBytes_SpillPath_FullCapture verifies that when an
// envelope arrives with a disk-spilled RawBuffer (USK-772) and the total
// wire bytes fit within the BLOB cap, the projection materializes the full
// header + body via Envelope.WireBytes(ctx).
func TestRecordStep_FlowRawBytes_SpillPath_FullCapture(t *testing.T) {
	w := &mockWriter{}
	// Generous cap so the spilled body fits.
	step := NewRecordStep(w, nil, WithMaxBodySize(64<<10))

	header := []byte("HTTP/1.1 200 OK\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n")
	body := []byte("5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
	bb := bodybuf.NewMemory(body)
	defer bb.Release()

	env := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Receive,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       header,
		RawBuffer: bb,
		Message: &envelope.HTTPMessage{
			Status:       200,
			StatusReason: "OK",
			Body:         []byte("hello world"),
		},
	}

	step.Process(context.Background(), env)

	if len(w.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(w.flows))
	}
	want := append(append([]byte{}, header...), body...)
	if !bytes.Equal(w.flows[0].RawBytes, want) {
		t.Errorf("Flow.RawBytes mismatch:\n got=%q\nwant=%q", w.flows[0].RawBytes, want)
	}
}

// TestRecordStep_FlowRawBytes_SpillPath_BlobTruncated verifies that the
// BLOB-projection cap (RecordStep.maxBodySize, defaulting to
// config.MaxBodySize) kicks in when the total wire bytes exceed it. The
// network passthrough path is independent (the Channel write streams from
// RawBuffer without applying this cap), so the test only validates the BLOB
// truncation. No Anomaly is emitted by RecordStep because the wire bytes
// were complete on the wire.
func TestRecordStep_FlowRawBytes_SpillPath_BlobTruncated(t *testing.T) {
	w := &mockWriter{}
	const cap = 32
	step := NewRecordStep(w, nil, WithMaxBodySize(cap))

	header := []byte("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n")
	body := bytes.Repeat([]byte("X"), 100)
	bb := bodybuf.NewMemory(body)
	defer bb.Release()

	env := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Receive,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       header,
		RawBuffer: bb,
		Message: &envelope.HTTPMessage{
			Status: 200,
			Body:   body,
		},
	}

	step.Process(context.Background(), env)

	if len(w.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(w.flows))
	}
	full := append(append([]byte{}, header...), body...)
	got := w.flows[0].RawBytes
	if int64(len(got)) != cap {
		t.Errorf("Flow.RawBytes len = %d, want cap %d", len(got), cap)
	}
	if !bytes.Equal(got, full[:cap]) {
		t.Errorf("Flow.RawBytes prefix mismatch (truncation must keep leading bytes):\n got=%q\nwant=%q",
			got, full[:cap])
	}
}

// --- USK-776: capture_scope (recording-only filter) ---

func newRecordScopeForTest(includes, excludes []flow.ScopeRule) *flow.RecordScope {
	rs := flow.NewRecordScope()
	rs.SetRules(includes, excludes)
	return rs
}

func httpSendEnv(streamID, host, path string) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    streamID + "-0",
		Direction: envelope.Send,
		Sequence:  0,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Authority: host,
			Path:      path,
		},
	}
}

func httpReceiveEnv(streamID, host, path string) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    streamID + "-resp",
		Direction: envelope.Receive,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Authority: host,
			Path:      path,
			Status:    200,
		},
	}
}

func TestRecordStep_CaptureScope_NilScope_RecordsAll(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil, WithRecordScope(nil))
	step.Process(context.Background(), httpSendEnv("s1", "static.cdn.com", "/asset.js"))
	if len(w.flows) != 1 || len(w.streams) != 1 {
		t.Fatalf("nil scope should record everything; got %d streams, %d flows", len(w.streams), len(w.flows))
	}
}

func TestRecordStep_CaptureScope_EmptyScope_RecordsAll(t *testing.T) {
	w := &mockWriter{}
	rs := flow.NewRecordScope()
	step := NewRecordStep(w, nil, WithRecordScope(rs))
	step.Process(context.Background(), httpSendEnv("s1", "any.example.com", "/"))
	if len(w.flows) != 1 || len(w.streams) != 1 {
		t.Fatalf("empty RecordScope should record everything; got %d streams, %d flows", len(w.streams), len(w.flows))
	}
}

func TestRecordStep_CaptureScope_FilterOutDoesNotCreateStream(t *testing.T) {
	w := &mockWriter{}
	rs := newRecordScopeForTest(
		[]flow.ScopeRule{{Hostname: "api.target.com"}},
		nil,
	)
	step := NewRecordStep(w, nil, WithRecordScope(rs))

	step.Process(context.Background(), httpSendEnv("filtered-1", "static.cdn.com", "/asset.js"))

	if len(w.streams) != 0 {
		t.Errorf("filtered stream must not be created (FK invariant); got %d streams", len(w.streams))
	}
	if len(w.flows) != 0 {
		t.Errorf("filtered flow must not be saved; got %d flows", len(w.flows))
	}
}

func TestRecordStep_CaptureScope_InScopeRecorded(t *testing.T) {
	w := &mockWriter{}
	rs := newRecordScopeForTest(
		[]flow.ScopeRule{{Hostname: "api.target.com"}},
		nil,
	)
	step := NewRecordStep(w, nil, WithRecordScope(rs))

	step.Process(context.Background(), httpSendEnv("s1", "api.target.com", "/v1/widgets"))

	if len(w.streams) != 1 {
		t.Fatalf("in-scope stream must be created; got %d streams", len(w.streams))
	}
	if len(w.flows) != 1 {
		t.Fatalf("in-scope flow must be saved; got %d flows", len(w.flows))
	}
}

func TestRecordStep_CaptureScope_PerStreamConsistency(t *testing.T) {
	// First Send is in-scope → Stream + Flow saved. Receive on the same
	// stream must also be saved (it inherits the cached "record" decision)
	// regardless of any field that's missing on the response envelope.
	w := &mockWriter{}
	rs := newRecordScopeForTest(
		[]flow.ScopeRule{{Hostname: "api.target.com"}},
		nil,
	)
	step := NewRecordStep(w, nil, WithRecordScope(rs))

	step.Process(context.Background(), httpSendEnv("s1", "api.target.com", "/x"))
	step.Process(context.Background(), httpReceiveEnv("s1", "api.target.com", "/x"))

	if len(w.streams) != 1 {
		t.Fatalf("expected exactly 1 stream, got %d", len(w.streams))
	}
	if len(w.flows) != 2 {
		t.Fatalf("expected 2 flows (send + receive), got %d", len(w.flows))
	}
}

func TestRecordStep_CaptureScope_FilteredStream_SubsequentEnvelopesAlsoFiltered(t *testing.T) {
	// First Send is filtered → Stream NOT created. The cache marks the
	// stream as "do not record"; subsequent Receive on the same stream must
	// also be filtered (otherwise SaveFlow would FK-violate against the
	// missing parent Stream row).
	w := &mockWriter{}
	rs := newRecordScopeForTest(
		[]flow.ScopeRule{{Hostname: "api.target.com"}},
		nil,
	)
	step := NewRecordStep(w, nil, WithRecordScope(rs))

	step.Process(context.Background(), httpSendEnv("filtered-1", "static.cdn.com", "/asset.js"))
	step.Process(context.Background(), httpReceiveEnv("filtered-1", "static.cdn.com", "/asset.js"))

	if len(w.streams) != 0 || len(w.flows) != 0 {
		t.Fatalf("filtered stream must filter every envelope; got %d streams, %d flows",
			len(w.streams), len(w.flows))
	}
}

func TestRecordStep_CaptureScope_NonFirstSendCacheMissDefaultsToFilter(t *testing.T) {
	// Receive without a prior cached decision (e.g. cache eviction) must
	// default to filter so the FK invariant is not violated. We simulate
	// this by sending a Receive on a never-seen stream when the scope is
	// non-empty.
	w := &mockWriter{}
	rs := newRecordScopeForTest(
		[]flow.ScopeRule{{Hostname: "api.target.com"}},
		nil,
	)
	step := NewRecordStep(w, nil, WithRecordScope(rs))

	step.Process(context.Background(), httpReceiveEnv("orphan", "api.target.com", "/x"))
	if len(w.flows) != 0 {
		t.Fatalf("orphan Receive must not be recorded; got %d flows", len(w.flows))
	}
}

func TestRecordStep_CaptureScope_DecisionCacheLRUEviction(t *testing.T) {
	w := &mockWriter{}
	rs := newRecordScopeForTest(
		[]flow.ScopeRule{{Hostname: "api.target.com"}},
		nil,
	)
	step := NewRecordStep(w, nil, WithRecordScope(rs))
	step.decisionCache = newRecordDecisionCache(2)

	step.Process(context.Background(), httpSendEnv("a", "api.target.com", "/"))
	step.Process(context.Background(), httpSendEnv("b", "api.target.com", "/"))
	step.Process(context.Background(), httpSendEnv("c", "api.target.com", "/"))

	if got := step.decisionCache.len(); got != 2 {
		t.Errorf("LRU cache size should be capped at 2, got %d", got)
	}
}

func TestRecordStep_CaptureScope_ExcludesWin(t *testing.T) {
	w := &mockWriter{}
	rs := newRecordScopeForTest(
		[]flow.ScopeRule{{Hostname: "*.target.com"}},
		[]flow.ScopeRule{{Hostname: "static.target.com"}},
	)
	step := NewRecordStep(w, nil, WithRecordScope(rs))

	step.Process(context.Background(), httpSendEnv("s1", "api.target.com", "/x"))
	step.Process(context.Background(), httpSendEnv("s2", "static.target.com", "/x"))

	if len(w.streams) != 1 || w.streams[0].ID != "s1" {
		t.Fatalf("expected only s1 stream, got %+v", w.streams)
	}
	if len(w.flows) != 1 || w.flows[0].StreamID != "s1" {
		t.Fatalf("expected only s1 flow, got %+v", w.flows)
	}
}

func TestRecordStep_CaptureScope_RuntimeUpdate(t *testing.T) {
	// The same RecordScope pointer flows from configure_tool to RecordStep,
	// so a runtime SetRules call must take effect on the next envelope.
	w := &mockWriter{}
	rs := flow.NewRecordScope()
	step := NewRecordStep(w, nil, WithRecordScope(rs))

	// Initially empty scope → record.
	step.Process(context.Background(), httpSendEnv("s1", "noisy.cdn.com", "/x"))
	if len(w.flows) != 1 {
		t.Fatalf("empty scope should have recorded; got %d flows", len(w.flows))
	}

	// Tighten scope via the shared pointer.
	rs.SetRules([]flow.ScopeRule{{Hostname: "api.target.com"}}, nil)

	// New stream against out-of-scope host → filtered.
	step.Process(context.Background(), httpSendEnv("s2", "noisy.cdn.com", "/y"))
	if len(w.flows) != 1 {
		t.Errorf("scope tightening should have filtered s2; got %d flows", len(w.flows))
	}

	// New stream against in-scope host → recorded.
	step.Process(context.Background(), httpSendEnv("s3", "api.target.com", "/z"))
	if len(w.flows) != 2 {
		t.Errorf("in-scope stream after retightening should record; got %d flows", len(w.flows))
	}
}

// TestRecordStep_DefaultOrigin_Proxy pins the USK-785 contract: a
// RecordStep constructed without WithOrigin stamps Stream.Origin =
// OriginProxy on the Stream it creates at first-Send. This is the
// behaviour the live proxy data path relies on.
func TestRecordStep_DefaultOrigin_Proxy(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	env := &envelope.Envelope{
		StreamID:  "stream-proxy",
		FlowID:    "flow-1",
		Direction: envelope.Send,
		Sequence:  0,
		Protocol:  envelope.ProtocolRaw,
		Raw:       []byte("data"),
		Message:   &envelope.RawMessage{Bytes: []byte("data")},
		Context:   envelope.EnvelopeContext{ConnID: "conn-1"},
	}
	step.Process(context.Background(), env)

	if len(w.streams) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(w.streams))
	}
	if got, want := w.streams[0].Origin, flow.OriginProxy; got != want {
		t.Errorf("default Stream.Origin = %q, want %q", got, want)
	}
}

// TestRecordStep_WithOriginResend pins the USK-785 contract for the
// resend code path: the 4 resend MCP tools construct a RecordStep with
// WithOrigin(OriginResend) so resend-originated streams can be filtered
// from live captures by the query tool (USK-786).
func TestRecordStep_WithOriginResend(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil, WithOrigin(flow.OriginResend))

	env := &envelope.Envelope{
		StreamID:  "stream-resend",
		FlowID:    "flow-1",
		Direction: envelope.Send,
		Sequence:  0,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("GET / HTTP/1.1\r\n\r\n"),
		Message:   &envelope.HTTPMessage{Method: "GET", Path: "/"},
		Context:   envelope.EnvelopeContext{ConnID: "conn-resend"},
	}
	step.Process(context.Background(), env)

	if len(w.streams) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(w.streams))
	}
	if got, want := w.streams[0].Origin, flow.OriginResend; got != want {
		t.Errorf("WithOrigin(Resend) → Stream.Origin = %q, want %q", got, want)
	}
}

// TestRecordStep_WithOrigin_EmptyFallsBackToProxy pins the
// "no-explicit-nil" contract on WithOrigin: an empty Origin argument is
// treated as "use default", which is OriginProxy. Callers can therefore
// thread a config-provided value through WithOrigin without explicit
// guards on the call site.
func TestRecordStep_WithOrigin_EmptyFallsBackToProxy(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil, WithOrigin(""))

	env := &envelope.Envelope{
		StreamID:  "stream-empty-origin",
		FlowID:    "flow-1",
		Direction: envelope.Send,
		Sequence:  0,
		Protocol:  envelope.ProtocolRaw,
		Raw:       []byte("data"),
		Message:   &envelope.RawMessage{Bytes: []byte("data")},
		Context:   envelope.EnvelopeContext{ConnID: "conn-empty"},
	}
	step.Process(context.Background(), env)

	if len(w.streams) != 1 {
		t.Fatalf("expected 1 stream, got %d", len(w.streams))
	}
	if got, want := w.streams[0].Origin, flow.OriginProxy; got != want {
		t.Errorf("WithOrigin('') → Stream.Origin = %q, want %q", got, want)
	}
}

// TestRecordStep_FlowFieldsTLSHandshake exercises the USK-790 projection
// of TLSHandshakeMessage onto a flow.Flow. The single-shot meta envelope
// contributes only Metadata entries (no headers / body / URL); every
// non-empty field on the message must surface in the recorded Metadata.
func TestRecordStep_FlowFieldsTLSHandshake(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	env := &envelope.Envelope{
		StreamID:  "s-tls",
		FlowID:    "f-tls",
		Direction: envelope.Send,
		Sequence:  0,
		Protocol:  envelope.ProtocolTLSHandshake,
		Message: &envelope.TLSHandshakeMessage{
			SNI:                   "example.com",
			LocalAddr:             "127.0.0.1:8080",
			RemoteAddr:            "192.0.2.1:55555",
			UpstreamAddr:          "93.184.216.34:443",
			BytesClientToUpstream: 4096,
			BytesUpstreamToClient: 8192,
			Outcome:               envelope.TLSHandshakeOutcomeTunneled,
		},
	}
	step.Process(context.Background(), env)

	if len(w.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(w.flows))
	}
	fl := w.flows[0]
	if fl.Metadata["protocol"] != string(envelope.ProtocolTLSHandshake) {
		t.Errorf("protocol = %q, want %q", fl.Metadata["protocol"], envelope.ProtocolTLSHandshake)
	}
	if fl.Metadata["sni"] != "example.com" {
		t.Errorf("sni = %q", fl.Metadata["sni"])
	}
	if fl.Metadata["local_addr"] != "127.0.0.1:8080" {
		t.Errorf("local_addr = %q", fl.Metadata["local_addr"])
	}
	if fl.Metadata["remote_addr"] != "192.0.2.1:55555" {
		t.Errorf("remote_addr = %q", fl.Metadata["remote_addr"])
	}
	if fl.Metadata["upstream_addr"] != "93.184.216.34:443" {
		t.Errorf("upstream_addr = %q", fl.Metadata["upstream_addr"])
	}
	if fl.Metadata["bytes_client_to_upstream"] != "4096" {
		t.Errorf("bytes_client_to_upstream = %q", fl.Metadata["bytes_client_to_upstream"])
	}
	if fl.Metadata["bytes_upstream_to_client"] != "8192" {
		t.Errorf("bytes_upstream_to_client = %q", fl.Metadata["bytes_upstream_to_client"])
	}
	if fl.Metadata["outcome"] != envelope.TLSHandshakeOutcomeTunneled {
		t.Errorf("outcome = %q", fl.Metadata["outcome"])
	}
	if _, ok := fl.Metadata["error"]; ok {
		t.Errorf("error metadata should be absent for tunneled outcome, got %q", fl.Metadata["error"])
	}
}

// ---------------------------------------------------------------------------
// USK-802 — per-Stream record caps for streaming protocols (gRPC / SSE).
// The cap is enforced inside RecordStep against persistence only; wire
// forwarding is unaffected because the Pipeline is invoked downstream of
// the Channel send path (gRPC) / TeeReader (SSE).
// ---------------------------------------------------------------------------

// grpcDataEnvelope returns a synthetic *envelope.Envelope carrying a
// GRPCDataMessage suitable for gating tests. seq drives both Sequence
// and FlowID so every envelope is uniquely identifiable in mockWriter.flows.
func grpcDataEnvelope(streamID string, seq int) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    streamID + "-d-" + strconv.Itoa(seq),
		Direction: envelope.Receive,
		Sequence:  seq,
		Protocol:  envelope.ProtocolGRPC,
		Raw:       []byte{0x00, 0x00, 0x00, 0x00, 0x01, 0xaa},
		Message: &envelope.GRPCDataMessage{
			Service:    "svc",
			Method:     "Echo",
			Payload:    []byte{0xaa},
			WireLength: 1,
		},
	}
}

// sseEventEnvelope returns a synthetic SSE per-event Envelope for gating
// tests. The Direction is Receive (SSE is server-push only).
func sseEventEnvelope(streamID string, seq int) *envelope.Envelope {
	data := "evt-" + strconv.Itoa(seq)
	return &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    streamID + "-e-" + strconv.Itoa(seq),
		Direction: envelope.Receive,
		Sequence:  seq,
		Protocol:  envelope.ProtocolSSE,
		Raw:       []byte("data: " + data + "\n\n"),
		Message:   &envelope.SSEMessage{Data: data},
	}
}

// TestRecordStep_GRPCPerStreamCap verifies that a positive
// WithGRPCMaxMessagesPerStream gates SaveFlow on GRPCDataMessage envelopes
// once the cap is reached. The first over-cap envelope must trigger an
// UpdateStream(AppendTags["records_truncated"]) and subsequent over-cap
// envelopes must drop silently without further UpdateStream calls.
func TestRecordStep_GRPCPerStreamCap(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil, WithGRPCMaxMessagesPerStream(3))
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		step.Process(ctx, grpcDataEnvelope("s1", i))
	}
	if len(w.flows) != 3 {
		t.Errorf("flows recorded = %d, want 3 (cap)", len(w.flows))
	}
	// Truncated tag must be stamped exactly once (on the 4th envelope —
	// the first over-cap). The 5th envelope drops silently.
	tagUpdates := 0
	for _, u := range w.updates {
		if u.streamID == "s1" && u.update.AppendTags["records_truncated"] == "per_stream_cap_reached" {
			tagUpdates++
		}
	}
	if tagUpdates != 1 {
		t.Errorf("AppendTags[records_truncated] updates = %d, want 1", tagUpdates)
	}
}

// TestRecordStep_SSEPerStreamCap mirrors the gRPC cap test for SSE.
// SSEMessage envelopes are gated; the per-event cap must drop excess
// events while leaving the wire-side TeeReader untouched (the test only
// observes the Pipeline-level persistence side effect).
func TestRecordStep_SSEPerStreamCap(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil, WithSSEMaxEventsPerStream(2))
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		step.Process(ctx, sseEventEnvelope("s1", i))
	}
	if len(w.flows) != 2 {
		t.Errorf("flows recorded = %d, want 2 (cap)", len(w.flows))
	}
	tagUpdates := 0
	for _, u := range w.updates {
		if u.streamID == "s1" && u.update.AppendTags["records_truncated"] == "per_stream_cap_reached" {
			tagUpdates++
		}
	}
	if tagUpdates != 1 {
		t.Errorf("AppendTags[records_truncated] updates = %d, want 1", tagUpdates)
	}
}

// TestRecordStep_GRPCStartEndNotCounted verifies the design decision that
// only GRPCDataMessage envelopes count toward the cap. GRPCStartMessage
// and GRPCEndMessage are bounded ≤2 per Stream and must always record.
//
// Layout: cap=2, send Start + 3 Data + End. Expected SaveFlow calls = 4
// (Start + Data×2 + End). The 3rd Data is dropped; Start and End survive.
func TestRecordStep_GRPCStartEndNotCounted(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil, WithGRPCMaxMessagesPerStream(2))
	ctx := context.Background()

	startEnv := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "s1-start",
		Direction: envelope.Send,
		Sequence:  0,
		Protocol:  envelope.ProtocolGRPC,
		Message:   &envelope.GRPCStartMessage{Service: "svc", Method: "Echo"},
	}
	endEnv := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "s1-end",
		Direction: envelope.Receive,
		Sequence:  4,
		Protocol:  envelope.ProtocolGRPC,
		Message:   &envelope.GRPCEndMessage{Status: 0},
	}
	step.Process(ctx, startEnv)
	for i := 0; i < 3; i++ {
		step.Process(ctx, grpcDataEnvelope("s1", i+1))
	}
	step.Process(ctx, endEnv)

	if len(w.flows) != 4 {
		t.Errorf("flows recorded = %d, want 4 (Start + 2 Data + End)", len(w.flows))
	}
	// Verify Start and End survived the gate.
	var sawStart, sawEnd bool
	for _, fl := range w.flows {
		if fl.ID == "s1-start" {
			sawStart = true
		}
		if fl.ID == "s1-end" {
			sawEnd = true
		}
	}
	if !sawStart {
		t.Error("Start envelope was not recorded; the gate must not affect it")
	}
	if !sawEnd {
		t.Error("End envelope was not recorded; the gate must not affect it")
	}
}

// TestRecordStep_OtherProtocolsUnaffected verifies that envelopes outside
// the gated protocols (HTTP, Raw, WS, ...) are recorded unconditionally
// regardless of the configured caps.
func TestRecordStep_OtherProtocolsUnaffected(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil,
		WithGRPCMaxMessagesPerStream(1),
		WithSSEMaxEventsPerStream(1),
	)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		env := &envelope.Envelope{
			StreamID:  "s-http",
			FlowID:    "f" + strconv.Itoa(i),
			Direction: envelope.Send,
			Sequence:  i,
			Protocol:  envelope.ProtocolHTTP,
			Raw:       []byte("GET / HTTP/1.1\r\n\r\n"),
			Message: &envelope.HTTPMessage{
				Method: "GET",
				Path:   "/",
			},
		}
		step.Process(ctx, env)
	}
	if len(w.flows) != 5 {
		t.Errorf("HTTP envelopes recorded = %d, want 5 (gating must not apply)", len(w.flows))
	}
}

// TestRecordStep_EmptyStreamID verifies that an envelope with an empty
// StreamID falls through the gate (no cache key is derivable). Synthetic
// test stacks routinely omit StreamID; the gate must not break them.
func TestRecordStep_EmptyStreamID(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil, WithGRPCMaxMessagesPerStream(1))
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		env := &envelope.Envelope{
			FlowID:    "f" + strconv.Itoa(i),
			Direction: envelope.Receive,
			Sequence:  i,
			Protocol:  envelope.ProtocolGRPC,
			Message:   &envelope.GRPCDataMessage{Payload: []byte{0xaa}},
		}
		step.Process(ctx, env)
	}
	if len(w.flows) != 3 {
		t.Errorf("envelopes recorded = %d, want 3 (empty StreamID bypasses gate)", len(w.flows))
	}
}

// TestRecordStep_CountCacheLRU verifies that the per-Stream count cache
// is bounded by an LRU and that an evicted Stream restarts its counter
// on next observation. Capacity is too small to expose internally, so
// the test exercises the documented trade-off via direct cache access.
func TestRecordStep_CountCacheLRU(t *testing.T) {
	cache := newRecordCountCache(2)
	// stream A and stream B fill the cache.
	if c, _ := cache.bumpAndCheck("A", 100); c != 1 {
		t.Errorf("A first bump count = %d, want 1", c)
	}
	if c, _ := cache.bumpAndCheck("B", 100); c != 1 {
		t.Errorf("B first bump count = %d, want 1", c)
	}
	if got := cache.len(); got != 2 {
		t.Fatalf("cache len = %d, want 2", got)
	}
	// Stream C exceeds capacity; A is the LRU and should be evicted.
	if c, _ := cache.bumpAndCheck("C", 100); c != 1 {
		t.Errorf("C first bump count = %d, want 1", c)
	}
	if got := cache.len(); got != 2 {
		t.Errorf("cache len = %d, want 2 after eviction", got)
	}
	// A reappears with a reset counter (acknowledged trade-off).
	if c, _ := cache.bumpAndCheck("A", 100); c != 1 {
		t.Errorf("A re-discover count = %d, want 1 (counter reset on eviction)", c)
	}
}

// TestRecordStep_TruncatedMetadataOnce verifies the one-shot latch: even
// after many subsequent overflowing envelopes the AppendTags update fires
// exactly once per Stream.
func TestRecordStep_TruncatedMetadataOnce(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil, WithGRPCMaxMessagesPerStream(1))
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		step.Process(ctx, grpcDataEnvelope("s1", i))
	}
	tagUpdates := 0
	for _, u := range w.updates {
		if u.update.AppendTags["records_truncated"] == "per_stream_cap_reached" {
			tagUpdates++
		}
	}
	if tagUpdates != 1 {
		t.Errorf("AppendTags[records_truncated] updates = %d after 10 envelopes, want 1 (one-shot latch)", tagUpdates)
	}
}

// TestRecordStep_NoCapsNoCache verifies the lazy-allocation contract: when
// neither cap Option is supplied, the count cache is never allocated and
// the gate is a no-op. This protects the unit-test stack zero-allocation
// invariant — non-streaming-protocol tests must not pay any cost for the
// new gating machinery.
func TestRecordStep_NoCapsNoCache(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)
	if step.countCache != nil {
		t.Error("countCache allocated without any per-Stream cap Option")
	}
	// Sanity: gating yields true unconditionally without a cache.
	env := grpcDataEnvelope("s1", 0)
	if !step.allowFlowRecord(context.Background(), env) {
		t.Error("allowFlowRecord = false with no caps; want true (degrades to no-op)")
	}
}

// TestRecordStep_HTTPAnomaliesProjectedToMetadata pins that every
// envelope.AnomalyType defined on HTTPMessage (HTTP/1.x parser anomalies +
// HTTP/2 receive-side anomalies + HTTP/2 send-side strip from USK-840)
// projects onto Flow.Metadata via a stable per-type key under the
// `http_anomaly_` prefix. Mirrors the gRPC/SSE precedent (USK-659 /
// USK-656). Critical for MITM Principle #5 — typed anomalies that the
// parsers/encoders surface must reach the analyst-facing MCP path
// (USK-849).
func TestRecordStep_HTTPAnomaliesProjectedToMetadata(t *testing.T) {
	cases := []struct {
		name    string
		typ     envelope.AnomalyType
		detail  string
		wantKey string
	}{
		// HTTP/1.x parser anomalies.
		{name: "CLTE", typ: envelope.AnomalyCLTE, detail: "TE wins; CL=10 TE=chunked", wantKey: "http_anomaly_cl_te"},
		{name: "DuplicateCL", typ: envelope.AnomalyDuplicateCL, detail: "CL: 10, 10", wantKey: "http_anomaly_duplicate_cl"},
		{name: "InvalidTE", typ: envelope.AnomalyInvalidTE, detail: "te=identity", wantKey: "http_anomaly_invalid_te"},
		{name: "HeaderInjection", typ: envelope.AnomalyHeaderInjection, detail: "X-Foo: \\r\\nbar", wantKey: "http_anomaly_header_injection"},
		{name: "AmbiguousTE", typ: envelope.AnomalyAmbiguousTE, detail: "te=chunked; chunked", wantKey: "http_anomaly_ambiguous_te"},
		{name: "ObsFold", typ: envelope.AnomalyObsFold, detail: "folded header", wantKey: "http_anomaly_obs_fold"},
		{name: "TrailerPseudoHeader", typ: envelope.AnomalyTrailerPseudoHeader, detail: ":status", wantKey: "http_anomaly_trailer_pseudo_header"},
		{name: "TrailerForbidden", typ: envelope.AnomalyTrailerForbidden, detail: "Content-Length", wantKey: "http_anomaly_trailer_forbidden"},
		{name: "TrailersInPassthrough", typ: envelope.AnomalyTrailersInPassthrough, detail: "", wantKey: "http_anomaly_trailers_in_passthrough"},
		{name: "RawBodyTruncated", typ: envelope.AnomalyRawBodyTruncated, detail: "1048576", wantKey: "http_anomaly_raw_body_truncated"},
		// HTTP/2 receive-side anomalies.
		{name: "H2DuplicatePseudoHeader", typ: envelope.H2DuplicatePseudoHeader, detail: ":authority", wantKey: "http_anomaly_h2_duplicate_pseudo_header"},
		{name: "H2PseudoHeaderAfterRegular", typ: envelope.H2PseudoHeaderAfterRegular, detail: ":method", wantKey: "http_anomaly_h2_pseudo_header_after_regular"},
		{name: "H2InvalidPseudoHeader", typ: envelope.H2InvalidPseudoHeader, detail: ":foo", wantKey: "http_anomaly_h2_invalid_pseudo_header"},
		{name: "H2UppercaseHeaderName", typ: envelope.H2UppercaseHeaderName, detail: "X-Foo", wantKey: "http_anomaly_h2_uppercase_header_name"},
		{name: "H2ConnectionSpecificHeader", typ: envelope.H2ConnectionSpecificHeader, detail: "connection, transfer-encoding", wantKey: "http_anomaly_h2_connection_specific_header"},
		// HTTP/2 send-side strip mirror (USK-840).
		{name: "H2ConnectionSpecificHeaderStrippedOnSend", typ: envelope.H2ConnectionSpecificHeaderStrippedOnSend, detail: "connection", wantKey: "http_anomaly_h2_connection_specific_header_stripped_on_send"},
		{name: "H2TrailersAfterPassthrough", typ: envelope.H2TrailersAfterPassthrough, detail: "", wantKey: "http_anomaly_h2_trailers_after_passthrough"},
		{name: "H2PushPromise", typ: envelope.H2PushPromise, detail: "promised stream 4", wantKey: "http_anomaly_h2_push_promise"},
		{name: "H2UnsupportedConnectProtocol", typ: envelope.H2UnsupportedConnectProtocol, detail: "webtransport", wantKey: "http_anomaly_h2_unsupported_connect_protocol"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
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
					Anomalies: []envelope.Anomaly{
						{Type: tc.typ, Detail: tc.detail},
					},
				},
			}
			step.Process(context.Background(), env)

			if len(w.flows) != 1 {
				t.Fatalf("expected 1 flow, got %d", len(w.flows))
			}
			fl := w.flows[0]
			detail, ok := fl.Metadata[tc.wantKey]
			if !ok {
				t.Fatalf("Metadata[%q] missing; keys=%v", tc.wantKey, metadataKeysSorted(fl.Metadata))
			}
			if detail != tc.detail {
				t.Errorf("Metadata[%q] = %q, want %q (Detail must round-trip verbatim — Principle #3)", tc.wantKey, detail, tc.detail)
			}
		})
	}
}

// TestRecordStep_HTTPAnomalyUnknownTypeUsesFallbackKey verifies the
// `http_anomaly_unknown_<lowercase-type>` fallback path. A future producer
// that adds a new AnomalyType without patching httpAnomalyMetadataKey
// must still surface in MCP rollup (Principle #5 — surface, don't drop).
func TestRecordStep_HTTPAnomalyUnknownTypeUsesFallbackKey(t *testing.T) {
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
			Anomalies: []envelope.Anomaly{
				{Type: envelope.AnomalyType("FutureProducerAnomaly"), Detail: "hypothetical"},
			},
		},
	}
	step.Process(context.Background(), env)
	if len(w.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(w.flows))
	}
	fl := w.flows[0]
	detail, ok := fl.Metadata["http_anomaly_unknown_futureproduceranomaly"]
	if !ok {
		t.Fatalf("fallback metadata key missing; keys=%v", metadataKeysSorted(fl.Metadata))
	}
	if detail != "hypothetical" {
		t.Errorf("fallback Detail = %q, want %q", detail, "hypothetical")
	}
}

// TestRecordStep_HTTPAnomaliesEmptySliceProducesNoKeys verifies the
// happy-path baseline — when a HTTPMessage carries no Anomalies, no
// `http_anomaly_*` metadata keys are emitted.
func TestRecordStep_HTTPAnomaliesEmptySliceProducesNoKeys(t *testing.T) {
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
			Path:      "/",
			Anomalies: nil,
		},
	}
	step.Process(context.Background(), env)
	if len(w.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(w.flows))
	}
	fl := w.flows[0]
	for key := range fl.Metadata {
		if strings.HasPrefix(key, "http_anomaly_") {
			t.Errorf("unexpected http_anomaly_* key %q on flow with no anomalies", key)
		}
	}
}

// TestRecordStep_HTTPAnomaliesMultipleProjectIndependently verifies that
// multiple distinct AnomalyTypes on one HTTPMessage produce multiple
// per-type Metadata keys (no clobbering). Mirrors the gRPC/SSE pattern
// where each AnomalyType gets its own column.
func TestRecordStep_HTTPAnomaliesMultipleProjectIndependently(t *testing.T) {
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
			Anomalies: []envelope.Anomaly{
				{Type: envelope.AnomalyCLTE, Detail: "TE wins"},
				{Type: envelope.AnomalyObsFold, Detail: "fold-1"},
				{Type: envelope.H2ConnectionSpecificHeaderStrippedOnSend, Detail: "connection"},
			},
		},
	}
	step.Process(context.Background(), env)
	if len(w.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(w.flows))
	}
	fl := w.flows[0]
	wants := map[string]string{
		"http_anomaly_cl_te":    "TE wins",
		"http_anomaly_obs_fold": "fold-1",
		"http_anomaly_h2_connection_specific_header_stripped_on_send": "connection",
	}
	for key, want := range wants {
		got, ok := fl.Metadata[key]
		if !ok {
			t.Errorf("Metadata[%q] missing; keys=%v", key, metadataKeysSorted(fl.Metadata))
			continue
		}
		if got != want {
			t.Errorf("Metadata[%q] = %q, want %q", key, got, want)
		}
	}
}

// TestRecordStep_HTTPAnomalyVariantLifecycle locks the variant lifecycle
// invariant for HTTP/2 send-side strip anomalies (USK-840 / USK-849):
// the aggregator attaches H2ConnectionSpecificHeaderStrippedOnSend to the
// modified-variant envelope only (the strip happens on the wire-encode
// path, which runs AFTER Intercept/Transform). Therefore the modified
// flow row must carry the http_anomaly_h2_connection_specific_header_stripped_on_send
// metadata key, while the original-variant row (the pre-modification
// snapshot, captured before the strip) carries no anomaly metadata.
//
// This nails Q6 from the design review and matches the existing variant
// recording pattern in TestRecordStep_VariantRecording.
func TestRecordStep_HTTPAnomalyVariantLifecycle(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)

	// Snapshot: pre-aggregator HTTPMessage — the strip hasn't happened
	// yet, so no anomaly is attached.
	original := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("[h2 hpack bytes orig]"),
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Scheme:    "https",
			Authority: "example.com",
			Path:      "/",
			Headers: []envelope.KeyValue{
				{Name: "Connection", Value: "keep-alive"},
			},
		},
	}
	// Modified envelope: simulates the post-aggregator state where the
	// wire encoder stripped the connection-specific header and the
	// aggregator attached the diagnostic anomaly to the modified
	// HTTPMessage. We also tweak Raw so envelopeModified() returns true.
	modified := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("[h2 hpack bytes mod]"),
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Scheme:    "https",
			Authority: "example.com",
			Path:      "/",
			Headers: []envelope.KeyValue{
				{Name: "Connection", Value: "keep-alive"},
			},
			Anomalies: []envelope.Anomaly{
				{Type: envelope.H2ConnectionSpecificHeaderStrippedOnSend, Detail: "connection"},
			},
		},
	}

	ctx := withSnapshot(context.Background(), original)
	step.Process(ctx, modified)

	if len(w.flows) != 2 {
		t.Fatalf("expected 2 flows (variant pair), got %d", len(w.flows))
	}
	origFlow := w.flows[0]
	modFlow := w.flows[1]
	if origFlow.Metadata["variant"] != "original" || modFlow.Metadata["variant"] != "modified" {
		t.Fatalf("variant order wrong: orig=%q mod=%q", origFlow.Metadata["variant"], modFlow.Metadata["variant"])
	}

	// The original variant must carry NO http_anomaly_* metadata —
	// the strip hadn't happened on the snapshot envelope.
	for key := range origFlow.Metadata {
		if strings.HasPrefix(key, "http_anomaly_") {
			t.Errorf("original variant should carry no http_anomaly_* metadata; got %q", key)
		}
	}

	// The modified variant must carry the strip anomaly verbatim.
	const wantKey = "http_anomaly_h2_connection_specific_header_stripped_on_send"
	detail, ok := modFlow.Metadata[wantKey]
	if !ok {
		t.Fatalf("modified variant missing Metadata[%q]; keys=%v", wantKey, metadataKeysSorted(modFlow.Metadata))
	}
	if detail != "connection" {
		t.Errorf("Metadata[%q] = %q, want %q (verbatim wire header name)", wantKey, detail, "connection")
	}
}

// metadataKeysSorted returns a stable-ordered key list for failure messages.
func metadataKeysSorted(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// strings.Sort lives behind sort.Strings; record_step_test.go does not
	// import sort, so use a simple insertion-sort proxy via map iteration —
	// tests only use this in failure messages so determinism beats speed.
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	return keys
}

// TestRecordStep_GRPCStartProjectsURLAndScheme pins the USK-920 projection
// contract: a Send-direction GRPCStartMessage carrying request-side
// pseudo-headers (:authority / :scheme / :path) must produce a Flow with a
// well-formed URL and a Stream whose Scheme matches :scheme. This is the
// recovery path that lets resend_grpc replay listener-captured flows from
// {flow_id} alone (extractResendGRPCStartFields reads Flow.URL first).
//
// The table covers every observable shape produced by gRPC channel.go's
// buildStartMessage:
//   - Full triple — happy path (https, h2c, response-side empty).
//   - Path missing but Service+Method present — defensive reconstruction.
//   - Response-side (Authority+Scheme empty) — no URL projection.
//
// Each branch directly mirrors a `if dir == envelope.Send` outcome in
// internal/layer/grpc/channel.go, so a refactor that drops one field cannot
// silently regress to the pre-USK-920 behavior.
func TestRecordStep_GRPCStartProjectsURLAndScheme(t *testing.T) {
	cases := []struct {
		name       string
		msg        *envelope.GRPCStartMessage
		wantURL    bool
		wantHost   string
		wantScheme string
		wantPath   string
		wantStream string
	}{
		{
			name: "full_https",
			msg: &envelope.GRPCStartMessage{
				Service:   "hello.HelloService",
				Method:    "SayHello",
				Authority: "api.example.com:443",
				Scheme:    "https",
				Path:      "/hello.HelloService/SayHello",
			},
			wantURL:    true,
			wantHost:   "api.example.com:443",
			wantScheme: "https",
			wantPath:   "/hello.HelloService/SayHello",
			wantStream: "https",
		},
		{
			name: "full_h2c_http",
			msg: &envelope.GRPCStartMessage{
				Service:   "hello.HelloService",
				Method:    "SayHello",
				Authority: "127.0.0.1:9000",
				Scheme:    "http",
				Path:      "/hello.HelloService/SayHello",
			},
			wantURL:    true,
			wantHost:   "127.0.0.1:9000",
			wantScheme: "http",
			wantPath:   "/hello.HelloService/SayHello",
			wantStream: "http",
		},
		{
			name: "path_missing_reconstructed_from_service_method",
			msg: &envelope.GRPCStartMessage{
				Service:   "hello.HelloService",
				Method:    "SayHello",
				Authority: "api.example.com",
				Scheme:    "https",
				// Path intentionally empty — projectGRPCStart must reconstruct.
			},
			wantURL:    true,
			wantHost:   "api.example.com",
			wantScheme: "https",
			wantPath:   "/hello.HelloService/SayHello",
			wantStream: "https",
		},
		{
			name: "response_side_no_url_projection",
			msg: &envelope.GRPCStartMessage{
				// Authority / Scheme / Path empty on the response side per
				// channel.go's `if dir == envelope.Send` gate.
				Service: "hello.HelloService",
				Method:  "SayHello",
			},
			wantURL:    false,
			wantStream: "",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			w := &mockWriter{}
			step := NewRecordStep(w, nil)
			env := &envelope.Envelope{
				StreamID:  "stream-" + tc.name,
				FlowID:    "flow-" + tc.name,
				Direction: envelope.Send,
				Sequence:  0,
				Protocol:  envelope.ProtocolGRPC,
				Raw:       []byte("hpack-bytes"),
				Message:   tc.msg,
			}
			step.Process(context.Background(), env)

			if len(w.streams) != 1 {
				t.Fatalf("expected 1 stream, got %d", len(w.streams))
			}
			if got := w.streams[0].Scheme; got != tc.wantStream {
				t.Errorf("stream Scheme = %q, want %q", got, tc.wantStream)
			}

			if len(w.flows) != 1 {
				t.Fatalf("expected 1 flow, got %d", len(w.flows))
			}
			fl := w.flows[0]
			if tc.wantURL {
				if fl.URL == nil {
					t.Fatal("flow URL is nil; want populated")
				}
				if fl.URL.Host != tc.wantHost {
					t.Errorf("flow URL.Host = %q, want %q", fl.URL.Host, tc.wantHost)
				}
				if fl.URL.Scheme != tc.wantScheme {
					t.Errorf("flow URL.Scheme = %q, want %q", fl.URL.Scheme, tc.wantScheme)
				}
				if fl.URL.Path != tc.wantPath {
					t.Errorf("flow URL.Path = %q, want %q", fl.URL.Path, tc.wantPath)
				}
			} else if fl.URL != nil {
				t.Errorf("flow URL = %+v, want nil for response-side Start", fl.URL)
			}
			// grpc_service / grpc_method must always project regardless of
			// pseudo-header presence — the Metadata fallback in
			// extractResendGRPCStartFields depends on it for legacy flows.
			if got := fl.Metadata["grpc_service"]; got != tc.msg.Service {
				t.Errorf("flow Metadata[grpc_service] = %q, want %q", got, tc.msg.Service)
			}
			if got := fl.Metadata["grpc_method"]; got != tc.msg.Method {
				t.Errorf("flow Metadata[grpc_method] = %q, want %q", got, tc.msg.Method)
			}
		})
	}
}
