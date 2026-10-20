package proxybuild

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// TestDefaultWireEncoderRegistries_RawWinsPolicy pins the RFC-001 §9.3 D4
// h2 policy wiring on the live route registries: the h2 route refuses a
// plugin msg["raw"] on an HTTPMessage (unframed HPACK), the h1 route does
// not; both routes refuse gRPC Start/End and gRPC-Web Start (header
// blocks) and honour Data.
func TestDefaultWireEncoderRegistries_RawWinsPolicy(t *testing.T) {
	h1 := defaultHTTP1WireEncoderRegistry()
	h2 := defaultHTTP2WireEncoderRegistry()
	httpEnv := &envelope.Envelope{Direction: envelope.Send, Protocol: envelope.ProtocolHTTP, Raw: []byte("x"), Message: &envelope.HTTPMessage{Method: "GET", Path: "/"}}
	if h2.RawWinsSupported(httpEnv) {
		t.Error("h2 route registry honours msg[\"raw\"] on HTTPMessage; want refused")
	}
	if !h1.RawWinsSupported(httpEnv) {
		t.Error("h1 route registry refuses msg[\"raw\"] on HTTPMessage; want honoured")
	}
	for name, r := range map[string]interface {
		RawWinsSupported(*envelope.Envelope) bool
	}{"h1": h1, "h2": h2} {
		cases := []struct {
			label string
			env   *envelope.Envelope
			want  bool
		}{
			{"grpc start", &envelope.Envelope{Protocol: envelope.ProtocolGRPC, Message: &envelope.GRPCStartMessage{}}, false},
			{"grpc end", &envelope.Envelope{Protocol: envelope.ProtocolGRPC, Message: &envelope.GRPCEndMessage{}}, false},
			{"grpc data", &envelope.Envelope{Protocol: envelope.ProtocolGRPC, Message: &envelope.GRPCDataMessage{}}, true},
			{"grpc-web start", &envelope.Envelope{Protocol: envelope.ProtocolGRPCWeb, Message: &envelope.GRPCStartMessage{}}, false},
			{"grpc-web data", &envelope.Envelope{Protocol: envelope.ProtocolGRPCWeb, Message: &envelope.GRPCDataMessage{}}, true},
			{"ws", &envelope.Envelope{Protocol: envelope.ProtocolWebSocket, Message: &envelope.WSMessage{}}, true},
		}
		for _, tc := range cases {
			if got := r.RawWinsSupported(tc.env); got != tc.want {
				t.Errorf("%s %s: RawWinsSupported = %v, want %v", name, tc.label, got, tc.want)
			}
		}
	}
}
