package grpcweb

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// TestRawWinsSupported: a gRPC-Web Start's Raw is a header snapshot the
// Layer never writes (refused) — except the malformed-body passthrough
// Start, whose Raw is the forwarded body; Data and End frames are written
// verbatim (honoured).
func TestRawWinsSupported(t *testing.T) {
	cases := []struct {
		name string
		msg  envelope.Message
		want bool
	}{
		{"plain start", &envelope.GRPCStartMessage{Service: "s", Method: "m"}, false},
		{"malformed-body passthrough start", &envelope.GRPCStartMessage{
			Anomalies: []envelope.Anomaly{{Type: envelope.AnomalyMalformedGRPCWebLPM}},
		}, true},
		{"start with unrelated anomaly", &envelope.GRPCStartMessage{
			Anomalies: []envelope.Anomaly{{Type: envelope.AnomalyUnexpectedGRPCWebRequestTrailer}},
		}, false},
		{"data", &envelope.GRPCDataMessage{Payload: []byte("p")}, true},
		{"end", &envelope.GRPCEndMessage{Status: 0}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := &envelope.Envelope{Protocol: envelope.ProtocolGRPCWeb, Raw: []byte("x"), RawAuthoritative: true, Message: tc.msg}
			if got := RawWinsSupported(env); got != tc.want {
				t.Errorf("RawWinsSupported(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}
