package mcp

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// TestResendEncoderRegistries_RawWinsPolicy pins the RFC-001 §9.3 D4 h2
// policy on the resend / fuzz registries: a plugin msg["raw"] on an h2
// HTTPMessage or a gRPC Start/End cannot be written verbatim, so the
// registry the resend PluginStepPost consults must refuse it; HTTP/1.x
// and gRPC Data keep honouring it.
func TestResendEncoderRegistries_RawWinsPolicy(t *testing.T) {
	httpEnv := &envelope.Envelope{Direction: envelope.Send, Protocol: envelope.ProtocolHTTP, Raw: []byte("x"), Message: &envelope.HTTPMessage{Method: "GET", Path: "/"}}
	cases := []struct {
		name string
		got  bool
		want bool
	}{
		{"resend http h2", resendHTTPEncoderRegistry(envelope.HTTPVersionH2).RawWinsSupported(httpEnv), false},
		{"resend http h2c", resendHTTPEncoderRegistry(envelope.HTTPVersionH2C).RawWinsSupported(httpEnv), false},
		{"resend http/1.1", resendHTTPEncoderRegistry(envelope.HTTPVersion11).RawWinsSupported(httpEnv), true},
		{"resend grpc start", buildResendGRPCEncoderRegistry().RawWinsSupported(&envelope.Envelope{Protocol: envelope.ProtocolGRPC, Message: &envelope.GRPCStartMessage{}}), false},
		{"resend grpc end", buildResendGRPCEncoderRegistry().RawWinsSupported(&envelope.Envelope{Protocol: envelope.ProtocolGRPC, Message: &envelope.GRPCEndMessage{}}), false},
		{"resend grpc data", buildResendGRPCEncoderRegistry().RawWinsSupported(&envelope.Envelope{Protocol: envelope.ProtocolGRPC, Message: &envelope.GRPCDataMessage{}}), true},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s: RawWinsSupported = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
}
