package pipeline

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-1321: a WS message truncated at the Layer's decompression cap
// records the anomaly and Flow.BodyTruncated; a whole message does not.
func TestRecordStep_WSDecompressedTooLargeAnomaly(t *testing.T) {
	const detail = "decompressed payload exceeds 16777216 bytes; recorded payload is the first 16777216 bytes"
	for _, tc := range []struct {
		name      string
		anomalies []envelope.Anomaly
		want      bool
	}{
		{"truncated", []envelope.Anomaly{{Type: envelope.AnomalyWSDecompressedTooLarge, Detail: detail}}, true},
		{"whole", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &mockWriter{}
			step := NewRecordStep(w, nil)
			env := &envelope.Envelope{
				StreamID:  "ws-1",
				FlowID:    "ws-1-f1",
				Direction: envelope.Receive,
				Protocol:  envelope.ProtocolWebSocket,
				Raw:       []byte{0xC1, 0x01, 0x00},
				Message: &envelope.WSMessage{
					Opcode: envelope.WSText, Fin: true, Compressed: true,
					Payload: []byte("prefix"), Anomalies: tc.anomalies,
				},
			}
			step.Process(context.Background(), env)
			if len(w.flows) != 1 {
				t.Fatalf("expected 1 flow, got %d", len(w.flows))
			}
			fl := w.flows[0]
			got, has := fl.Metadata["ws_anomaly_decompressed_too_large"]
			if has != tc.want || (tc.want && got != detail) {
				t.Errorf("metadata[ws_anomaly_decompressed_too_large] = %q (present=%v), want present=%v", got, has, tc.want)
			}
			if fl.BodyTruncated != tc.want {
				t.Errorf("BodyTruncated = %v, want %v", fl.BodyTruncated, tc.want)
			}
		})
	}
}

// USK-1321: the anomaly is Layer-detected, not a content change, so it
// must not by itself produce a modified variant.
func TestWSMessageModified_IgnoresAnomalies(t *testing.T) {
	a := &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Payload: []byte("p")}
	b := &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Payload: []byte("p"),
		Anomalies: []envelope.Anomaly{{Type: envelope.AnomalyWSDecompressedTooLarge}}}
	if wsMessageModified(a, b) {
		t.Error("wsMessageModified = true for messages differing only in Anomalies")
	}
}
