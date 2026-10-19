package grpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// USK-1254: an LPM the reassembler cannot complete — declared length over
// the per-Channel cap (case 2) or cut short by END_STREAM (case 3) — must
// be recorded through the LPM record callback as an overlay envelope
// carrying a typed anomaly, while the stream still terminates exactly as
// before (same *layer.StreamError, same RST_STREAM code, no semantic
// envelope).

// lpmPrefix builds a 5-byte LPM prefix with an arbitrary flag byte.
func lpmPrefix(flag byte, declared uint32) []byte {
	p := make([]byte, lpmPrefixLen)
	p[0] = flag
	binary.BigEndian.PutUint32(p[1:5], declared)
	return p
}

// concat returns a fresh slice holding parts in order.
func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// lpmRecorder collects envelopes handed to the LPM record callback.
type lpmRecorder struct {
	mu  sync.Mutex
	got []*envelope.Envelope
}

func (r *lpmRecorder) cb(env *envelope.Envelope) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, env)
}

func (r *lpmRecorder) snapshot() []*envelope.Envelope {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*envelope.Envelope(nil), r.got...)
}

// nextUntilErr drains ch until Next returns an error and returns the
// envelopes observed before it plus the error.
func nextUntilErr(t *testing.T, ch layer.Channel, maxEnvs int) ([]*envelope.Envelope, error) {
	t.Helper()
	var envs []*envelope.Envelope
	for i := 0; i <= maxEnvs; i++ {
		env, err := ch.Next(context.Background())
		if err != nil {
			return envs, err
		}
		envs = append(envs, env)
	}
	t.Fatalf("Next did not return an error within %d envelopes", maxEnvs)
	return nil, nil
}

// requireStreamError asserts err is a *layer.StreamError with the given
// code and reason (the pre-USK-1254 termination, unchanged).
func requireStreamError(t *testing.T, err error, code layer.ErrorCode, reason string) {
	t.Helper()
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("Next err = %v, want *layer.StreamError", err)
	}
	if se.Code != code {
		t.Errorf("StreamError.Code = %v, want %v", se.Code, code)
	}
	if se.Reason != reason {
		t.Errorf("StreamError.Reason = %q, want %q", se.Reason, reason)
	}
}

// requireNoDataEnvelopes asserts the consumer saw no GRPCDataMessage
// envelope — the partial LPM must never reach the semantic (forwarding)
// path.
func requireNoDataEnvelopes(t *testing.T, envs []*envelope.Envelope) {
	t.Helper()
	for i, env := range envs {
		if _, ok := env.Message.(*envelope.GRPCDataMessage); ok {
			t.Errorf("semantic envs[%d] is a GRPCDataMessage; the partial LPM must not reach the semantic path", i)
		}
	}
}

type wantAnomalyEnv struct {
	dir     envelope.Direction
	raw     []byte
	typ     envelope.AnomalyType
	detail  string
	service string
	method  string
}

// requireAnomalyEnv asserts env is a partial-LPM overlay envelope matching
// want and returns its message for further checks.
func requireAnomalyEnv(t *testing.T, env *envelope.Envelope, want wantAnomalyEnv) *envelope.GRPCDataMessage {
	t.Helper()
	if env.Protocol != envelope.ProtocolGRPC {
		t.Errorf("anomaly env Protocol = %q, want grpc", env.Protocol)
	}
	if env.Direction != want.dir {
		t.Errorf("anomaly env Direction = %v, want %v", env.Direction, want.dir)
	}
	if !bytes.Equal(env.Raw, want.raw) {
		t.Errorf("anomaly env Raw = %x, want %x (observed bytes, verbatim)", env.Raw, want.raw)
	}
	m, ok := env.Message.(*envelope.GRPCDataMessage)
	if !ok {
		t.Fatalf("anomaly env Message = %T, want *envelope.GRPCDataMessage", env.Message)
	}
	if m.Payload != nil {
		t.Errorf("anomaly env Payload = %x, want nil", m.Payload)
	}
	if len(m.Anomalies) != 1 {
		t.Fatalf("anomaly env Anomalies = %+v, want exactly 1", m.Anomalies)
	}
	if m.Anomalies[0].Type != want.typ {
		t.Errorf("Anomalies[0].Type = %q, want %q", m.Anomalies[0].Type, want.typ)
	}
	if m.Anomalies[0].Detail != want.detail {
		t.Errorf("Anomalies[0].Detail = %q, want %q", m.Anomalies[0].Detail, want.detail)
	}
	if m.Service != want.service || m.Method != want.method {
		t.Errorf("anomaly env Service/Method = %q/%q, want %q/%q", m.Service, m.Method, want.service, want.method)
	}
	return m
}

// T1: case 2 — the declared length exceeds the cap. Raw carries the
// verbatim prefix (including a non-RFC flag byte) plus the payload bytes
// the same DATA frame carried.
func TestChannel_LPMPartialAnomaly_TooLarge(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-too-large")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))
	prefix := lpmPrefix(0x07, 200)
	tail := []byte("12345678")
	stub.pushData(envelope.Send, concat(prefix, tail), false)

	rec := &lpmRecorder{}
	ch := Wrap(stub, nil, RoleServer,
		WithLPMFrameRecordCallback(rec.cb),
		WithMaxMessageSize(100),
	)
	defer ch.Close()

	envs, err := nextUntilErr(t, ch, 4)
	requireStreamError(t, err, layer.ErrorInternalError, "grpc: message too large")
	requireNoDataEnvelopes(t, envs)
	if stub.rstCode != http2.ErrCodeInternal {
		t.Errorf("MarkTerminatedWithRST code = %d, want INTERNAL_ERROR (%d)", stub.rstCode, http2.ErrCodeInternal)
	}

	got := rec.snapshot()
	if len(got) != 1 {
		t.Fatalf("LPM record callback fired %d times, want 1 (the oversized-LPM anomaly row)", len(got))
	}
	m := requireAnomalyEnv(t, got[0], wantAnomalyEnv{
		dir:     envelope.Send,
		raw:     concat(prefix, tail),
		typ:     envelope.AnomalyGRPCLPMTooLarge,
		detail:  "declared=200 cap=100 captured=8",
		service: "svc.S",
		method:  "M",
	})
	if m.WireLength != 200 {
		t.Errorf("WireLength = %d, want 200 (declared)", m.WireLength)
	}
	if !m.Compressed {
		t.Errorf("Compressed = false, want true (flag byte 0x07 != 0)")
	}
	if got[0].StreamID != "stream-too-large" {
		t.Errorf("StreamID = %q, want stream-too-large", got[0].StreamID)
	}
}

// T1b: case 2 where the DATA frame carries more bytes than the declared
// length — only the declared length is captured; nothing beyond it is
// attributed to the oversized LPM.
func TestChannel_LPMPartialAnomaly_TooLarge_CapturesAtMostDeclared(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-too-large-cap")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))
	prefix := lpmPrefix(0, 6)
	stub.pushData(envelope.Send, concat(prefix, []byte("abcdefXYZ")), false)

	rec := &lpmRecorder{}
	ch := Wrap(stub, nil, RoleServer,
		WithLPMFrameRecordCallback(rec.cb),
		WithMaxMessageSize(5),
	)
	defer ch.Close()

	_, err := nextUntilErr(t, ch, 4)
	requireStreamError(t, err, layer.ErrorInternalError, "grpc: message too large")

	got := rec.snapshot()
	if len(got) != 1 {
		t.Fatalf("LPM record callback fired %d times, want 1", len(got))
	}
	requireAnomalyEnv(t, got[0], wantAnomalyEnv{
		dir:     envelope.Send,
		raw:     concat(prefix, []byte("abcdef")),
		typ:     envelope.AnomalyGRPCLPMTooLarge,
		detail:  "declared=6 cap=5 captured=6",
		service: "svc.S",
		method:  "M",
	})
}

// T2: case 2 with the prefix split across two DATA events (Receive side) —
// the anomaly Raw carries all 5 prefix bytes, including the ones from the
// earlier frame.
func TestChannel_LPMPartialAnomaly_TooLarge_PrefixSplitAcrossFrames(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-split")
	stub.pushHeaders(envelope.Receive, []byte("HPACK"), &http2.H2HeadersEvent{
		Status:  200,
		Headers: []envelope.KeyValue{{Name: "content-type", Value: "application/grpc"}},
	})
	prefix := lpmPrefix(0, 500)
	stub.pushData(envelope.Receive, prefix[:2], false)
	stub.pushData(envelope.Receive, concat(prefix[2:], []byte("xy")), false)

	rec := &lpmRecorder{}
	ch := Wrap(stub, nil, RoleClient,
		WithLPMFrameRecordCallback(rec.cb),
		WithMaxMessageSize(100),
	)
	defer ch.Close()

	_, err := nextUntilErr(t, ch, 4)
	requireStreamError(t, err, layer.ErrorInternalError, "grpc: message too large")

	got := rec.snapshot()
	if len(got) != 1 {
		t.Fatalf("LPM record callback fired %d times, want 1", len(got))
	}
	requireAnomalyEnv(t, got[0], wantAnomalyEnv{
		dir:    envelope.Receive,
		raw:    concat(prefix, []byte("xy")),
		typ:    envelope.AnomalyGRPCLPMTooLarge,
		detail: "declared=500 cap=100 captured=2",
	})
}

// T3: case 3, payload phase — END_STREAM arrives after 4 of 10 declared
// payload bytes.
func TestChannel_LPMPartialAnomaly_TruncatedPayload(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-trunc-payload")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))
	prefix := lpmPrefix(0, 10)
	stub.pushData(envelope.Send, concat(prefix, []byte("abcd")), true)

	rec := &lpmRecorder{}
	ch := Wrap(stub, nil, RoleServer, WithLPMFrameRecordCallback(rec.cb))
	defer ch.Close()

	envs, err := nextUntilErr(t, ch, 4)
	requireStreamError(t, err, layer.ErrorProtocol, "grpc: stream ended mid-LPM")
	requireNoDataEnvelopes(t, envs)
	if stub.rstCode != http2.ErrCodeInternal {
		t.Errorf("MarkTerminatedWithRST code = %d, want INTERNAL_ERROR (%d)", stub.rstCode, http2.ErrCodeInternal)
	}

	got := rec.snapshot()
	if len(got) != 1 {
		t.Fatalf("LPM record callback fired %d times, want 1 (the truncated-LPM anomaly row)", len(got))
	}
	m := requireAnomalyEnv(t, got[0], wantAnomalyEnv{
		dir:     envelope.Send,
		raw:     concat(prefix, []byte("abcd")),
		typ:     envelope.AnomalyGRPCLPMTruncated,
		detail:  "declared=10 observed=4",
		service: "svc.S",
		method:  "M",
	})
	if m.WireLength != 10 {
		t.Errorf("WireLength = %d, want 10 (declared)", m.WireLength)
	}
	if !m.EndStream {
		t.Errorf("EndStream = false, want true (the truncating frame carried END_STREAM)")
	}
}

// T4: case 3, prefix phase — 3 prefix bytes then an empty END_STREAM DATA
// frame.
func TestChannel_LPMPartialAnomaly_TruncatedPrefix(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-trunc-prefix")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))
	stub.pushData(envelope.Send, []byte{0x01, 0x00, 0x00}, false)
	stub.pushData(envelope.Send, nil, true)

	rec := &lpmRecorder{}
	ch := Wrap(stub, nil, RoleServer, WithLPMFrameRecordCallback(rec.cb))
	defer ch.Close()

	envs, err := nextUntilErr(t, ch, 4)
	requireStreamError(t, err, layer.ErrorProtocol, "grpc: stream ended mid-LPM")
	requireNoDataEnvelopes(t, envs)

	got := rec.snapshot()
	if len(got) != 1 {
		t.Fatalf("LPM record callback fired %d times, want 1 (the truncated-prefix anomaly row)", len(got))
	}
	m := requireAnomalyEnv(t, got[0], wantAnomalyEnv{
		dir:     envelope.Send,
		raw:     []byte{0x01, 0x00, 0x00},
		typ:     envelope.AnomalyGRPCLPMTruncated,
		detail:  "prefix_bytes=3",
		service: "svc.S",
		method:  "M",
	})
	if m.WireLength != 0 || m.Compressed {
		t.Errorf("WireLength/Compressed = %d/%v, want 0/false (prefix incomplete: nothing fabricated)", m.WireLength, m.Compressed)
	}
}

// T5: a complete LPM precedes the failing one in the same DATA event. The
// complete LPM's wire row (no anomaly) fires first, then the anomaly row.
func TestChannel_LPMPartialAnomaly_PrecedingCompleteLPMRecorded(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		tail       []byte
		endStream  bool
		maxMsg     uint32
		wantCode   layer.ErrorCode
		wantReason string
		wantType   envelope.AnomalyType
		wantDetail string
	}{
		{
			name:       "too large",
			tail:       concat(lpmPrefix(0, 300), []byte("zz")),
			maxMsg:     100,
			wantCode:   layer.ErrorInternalError,
			wantReason: "grpc: message too large",
			wantType:   envelope.AnomalyGRPCLPMTooLarge,
			wantDetail: "declared=300 cap=100 captured=2",
		},
		{
			name:       "end stream mid-LPM",
			tail:       concat(lpmPrefix(0, 9), []byte("zz")),
			endStream:  true,
			wantCode:   layer.ErrorProtocol,
			wantReason: "grpc: stream ended mid-LPM",
			wantType:   envelope.AnomalyGRPCLPMTruncated,
			wantDetail: "declared=9 observed=2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			stub := newStubInner("stream-preceding")
			stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))
			complete := makeLPM(false, []byte("good"))
			stub.pushData(envelope.Send, concat(complete, tt.tail), tt.endStream)

			rec := &lpmRecorder{}
			opts := []Option{WithLPMFrameRecordCallback(rec.cb)}
			if tt.maxMsg > 0 {
				opts = append(opts, WithMaxMessageSize(tt.maxMsg))
			}
			ch := Wrap(stub, nil, RoleServer, opts...)
			defer ch.Close()

			envs, err := nextUntilErr(t, ch, 4)
			requireStreamError(t, err, tt.wantCode, tt.wantReason)
			requireNoDataEnvelopes(t, envs)

			got := rec.snapshot()
			if len(got) != 2 {
				t.Fatalf("LPM record callback fired %d times, want 2 (complete LPM, then anomaly row)", len(got))
			}
			if !bytes.Equal(got[0].Raw, complete) {
				t.Errorf("got[0].Raw = %x, want %x (the complete LPM)", got[0].Raw, complete)
			}
			if got[0].Message != nil {
				t.Errorf("got[0].Message = %T, want nil (complete LPM rows carry no anomaly)", got[0].Message)
			}
			requireAnomalyEnv(t, got[1], wantAnomalyEnv{
				dir:     envelope.Send,
				raw:     tt.tail,
				typ:     tt.wantType,
				detail:  tt.wantDetail,
				service: "svc.S",
				method:  "M",
			})
		})
	}
}

// Guard: without a record callback installed the error paths behave
// exactly as before (no panic on the nil callback).
func TestChannel_LPMPartialAnomaly_NilCallback(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-nil-cb")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M"))
	stub.pushData(envelope.Send, concat(lpmPrefix(0, 10), []byte("ab")), true)

	ch := Wrap(stub, nil, RoleServer)
	defer ch.Close()

	_, err := nextUntilErr(t, ch, 4)
	requireStreamError(t, err, layer.ErrorProtocol, "grpc: stream ended mid-LPM")
}

// T6: a complete LPM precedes one whose payload fails gzip decode
// (buildDataEnvelopeLocked error path) in the same DATA event. The complete
// LPM was observed on the wire and must be recorded before the (unchanged)
// RST + StreamError; the failing LPM itself gets no row here.
func TestChannel_LPMPartialAnomaly_DecodeFailureRecordsPrecedingLPM(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-decode-fail")
	stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M",
		envelope.KeyValue{Name: "grpc-encoding", Value: "gzip"},
	))
	complete := makeLPM(false, []byte("good"))
	bad := makeLPM(true, []byte("not-gzip"))
	stub.pushData(envelope.Send, concat(complete, bad), false)

	rec := &lpmRecorder{}
	ch := Wrap(stub, nil, RoleServer, WithLPMFrameRecordCallback(rec.cb))
	defer ch.Close()

	envs, err := nextUntilErr(t, ch, 4)
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("Next err = %v, want *layer.StreamError", err)
	}
	if se.Code != layer.ErrorProtocol {
		t.Errorf("StreamError.Code = %v, want %v", se.Code, layer.ErrorProtocol)
	}
	if !strings.HasPrefix(se.Reason, "grpc: gzip decode: ") {
		t.Errorf("StreamError.Reason = %q, want prefix %q", se.Reason, "grpc: gzip decode: ")
	}
	requireNoDataEnvelopes(t, envs)
	if stub.rstCode != http2.ErrCodeInternal {
		t.Errorf("MarkTerminatedWithRST code = %d, want INTERNAL_ERROR (%d)", stub.rstCode, http2.ErrCodeInternal)
	}

	got := rec.snapshot()
	if len(got) != 1 {
		t.Fatalf("LPM record callback fired %d times, want 1 (the complete LPM preceding the decode failure)", len(got))
	}
	if !bytes.Equal(got[0].Raw, complete) {
		t.Errorf("got[0].Raw = %x, want %x (the complete LPM)", got[0].Raw, complete)
	}
	if got[0].Message != nil {
		t.Errorf("got[0].Message = %T, want nil (complete LPM rows carry no anomaly)", got[0].Message)
	}
}
