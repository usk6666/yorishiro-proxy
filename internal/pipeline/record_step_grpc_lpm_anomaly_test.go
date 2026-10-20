package pipeline

import (
	"bytes"
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// partialLPMAnomalyEnvelope builds an envelope shaped like the partial-LPM
// overlay envelope the gRPC Layer hands to the LPM record callback
// (USK-1254): WireLevel=grpc-lpm-frame, Raw = the observed bytes of the
// incomplete LPM, Message = GRPCDataMessage{Payload: nil, Anomalies}.
func partialLPMAnomalyEnvelope(raw []byte, m *envelope.GRPCDataMessage) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  "s-partial",
		FlowID:    "lpm-partial",
		Direction: envelope.Send,
		Sequence:  1,
		Protocol:  envelope.ProtocolGRPC,
		Raw:       raw,
		Message:   m,
		Context:   envelope.EnvelopeContext{WireLevel: flow.WireLevelGRPCLPMFrame},
	}
}

// T6: RecordStep projects GRPCDataMessage.Anomalies on a partial-LPM
// overlay envelope into stable grpc_anomaly_* Metadata keys, keeps the
// overlay WireLevel, stores RawBytes verbatim, leaves Body empty, and
// never fabricates grpc_wire_length / grpc_compressed for a truncated
// prefix.
func TestRecordStep_GRPCLPMPartialAnomalyProjected(t *testing.T) {
	tests := []struct {
		name          string
		raw           []byte
		msg           *envelope.GRPCDataMessage
		wantKey       string
		wantDetail    string
		wantWireLen   string // "" = key must be absent
		wantCompress  string // "" = key must be absent
		wantEndStream string
	}{
		{
			name: "too large",
			raw:  []byte{0x07, 0x00, 0x00, 0x00, 0xc8, '1', '2', '3', '4', '5', '6', '7', '8'},
			msg: &envelope.GRPCDataMessage{
				Service: "svc.S", Method: "M",
				Compressed: true, WireLength: 200,
				Anomalies: []envelope.Anomaly{{
					Type:   envelope.AnomalyGRPCLPMTooLarge,
					Detail: "declared=200 cap=100 captured=8",
				}},
			},
			wantKey:       "grpc_anomaly_lpm_too_large",
			wantDetail:    "declared=200 cap=100 captured=8",
			wantWireLen:   "200",
			wantCompress:  "true",
			wantEndStream: "false",
		},
		{
			name: "truncated payload",
			raw:  []byte{0x00, 0x00, 0x00, 0x00, 0x0a, 'a', 'b', 'c', 'd'},
			msg: &envelope.GRPCDataMessage{
				Service: "svc.S", Method: "M",
				WireLength: 10, EndStream: true,
				Anomalies: []envelope.Anomaly{{
					Type:   envelope.AnomalyGRPCLPMTruncated,
					Detail: "declared=10 observed=4",
				}},
			},
			wantKey:       "grpc_anomaly_lpm_truncated",
			wantDetail:    "declared=10 observed=4",
			wantWireLen:   "10",
			wantCompress:  "false",
			wantEndStream: "true",
		},
		{
			name: "truncated prefix",
			raw:  []byte{0x01, 0x00, 0x00},
			msg: &envelope.GRPCDataMessage{
				Service: "svc.S", Method: "M",
				EndStream: true,
				Anomalies: []envelope.Anomaly{{
					Type:   envelope.AnomalyGRPCLPMTruncated,
					Detail: "prefix_bytes=3",
				}},
			},
			wantKey:       "grpc_anomaly_lpm_truncated",
			wantDetail:    "prefix_bytes=3",
			wantEndStream: "true",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &mockWriter{}
			step := NewRecordStep(w, nil)
			step.Process(context.Background(), partialLPMAnomalyEnvelope(tt.raw, tt.msg))
			if len(w.flows) != 1 {
				t.Fatalf("flows recorded = %d, want 1", len(w.flows))
			}
			fl := w.flows[0]
			if fl.WireLevel != flow.WireLevelGRPCLPMFrame {
				t.Errorf("Flow.WireLevel = %q, want %q", fl.WireLevel, flow.WireLevelGRPCLPMFrame)
			}
			if !bytes.Equal(fl.RawBytes, tt.raw) {
				t.Errorf("Flow.RawBytes = %x, want %x (verbatim)", fl.RawBytes, tt.raw)
			}
			if len(fl.Body) != 0 {
				t.Errorf("Flow.Body = %x, want empty (no payload is fabricated)", fl.Body)
			}
			if got, ok := fl.Metadata[tt.wantKey]; !ok || got != tt.wantDetail {
				t.Errorf("Metadata[%q] = %q (present=%v), want %q; metadata=%v", tt.wantKey, got, ok, tt.wantDetail, fl.Metadata)
			}
			if got := fl.Metadata["grpc_event"]; got != "data" {
				t.Errorf("Metadata[grpc_event] = %q, want data", got)
			}
			assertOptionalKey(t, fl.Metadata, "grpc_wire_length", tt.wantWireLen)
			assertOptionalKey(t, fl.Metadata, "grpc_compressed", tt.wantCompress)
			if got := fl.Metadata["grpc_end_stream"]; got != tt.wantEndStream {
				t.Errorf("Metadata[grpc_end_stream] = %q, want %q", got, tt.wantEndStream)
			}
			if _, ok := fl.Metadata["grpc_anomaly_malformed_lpm"]; ok {
				t.Errorf("Metadata carries the gRPC-Web key grpc_anomaly_malformed_lpm; native gRPC anomalies must use their own keys")
			}
		})
	}
}

// assertOptionalKey asserts m[key] == want, or that key is absent when
// want is "".
func assertOptionalKey(t *testing.T, m map[string]string, key, want string) {
	t.Helper()
	got, ok := m[key]
	if want == "" {
		if ok {
			t.Errorf("Metadata[%q] = %q, want key absent (prefix truncated: value unknown, must not be fabricated)", key, got)
		}
		return
	}
	if got != want {
		t.Errorf("Metadata[%q] = %q (present=%v), want %q", key, got, ok, want)
	}
}

// Guard: an anomaly-carrying GRPCDataMessage is parser-derived; a
// snapshot/current pair differing only in Anomalies must not be treated
// as a user modification (no variant rows).
func TestGRPCDataModified_IgnoresAnomalies(t *testing.T) {
	a := &envelope.GRPCDataMessage{Service: "s", Method: "m", WireLength: 3}
	b := &envelope.GRPCDataMessage{Service: "s", Method: "m", WireLength: 3,
		Anomalies: []envelope.Anomaly{{Type: envelope.AnomalyGRPCLPMTruncated, Detail: "x"}}}
	if grpcDataModified(a, b) {
		t.Errorf("grpcDataModified reported a modification for an Anomalies-only difference")
	}
}
