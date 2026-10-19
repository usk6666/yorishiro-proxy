package mcp

import (
	"bytes"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// TestApplyGRPCStartModify_KeepsGRPCWebPassthroughRaw — USK-1203 review F-1:
// for a gRPC-Web Start emitted for a malformed body, Envelope.Raw is the
// whole observed body that the upstream-side grpcweb Layer forwards
// verbatim — not an HPACK snapshot. A metadata override on the held Start
// must not destroy it (which would forward an empty, well-formed request).
// A native gRPC Start still has Raw cleared.
func TestApplyGRPCStartModify_KeepsGRPCWebPassthroughRaw(t *testing.T) {
	body := []byte{0x00, 0x00, 0x00, 0x03, 0xe8, 'a', 'b', 'c', 'd'}
	newStart := func(proto envelope.Protocol) *envelope.Envelope {
		return &envelope.Envelope{
			Direction: envelope.Send,
			Protocol:  proto,
			Raw:       append([]byte(nil), body...),
			Message: &envelope.GRPCStartMessage{
				Service:     "pkg.Echo",
				Method:      "Say",
				ContentType: "application/grpc-web+proto",
				Anomalies:   []envelope.Anomaly{{Type: envelope.AnomalyMalformedGRPCWebLPM, Detail: "x"}},
			},
		}
	}
	params := &grpcStartMessageModify{Metadata: []headerKV{{Name: "x-added", Value: "1"}}}

	env := newStart(envelope.ProtocolGRPCWeb)
	out, err := applyGRPCStartModify(env, env.Message.(*envelope.GRPCStartMessage), params)
	if err != nil {
		t.Fatalf("applyGRPCStartModify: %v", err)
	}
	if !bytes.Equal(out.Raw, body) {
		t.Errorf("gRPC-Web passthrough Raw = %q, want %q preserved", out.Raw, body)
	}
	if md := out.Message.(*envelope.GRPCStartMessage).Metadata; len(md) != 1 || md[0].Name != "x-added" {
		t.Errorf("metadata override not applied: %v", md)
	}

	native := newStart(envelope.ProtocolGRPC)
	out, err = applyGRPCStartModify(native, native.Message.(*envelope.GRPCStartMessage), params)
	if err != nil {
		t.Fatalf("applyGRPCStartModify (native): %v", err)
	}
	if out.Raw != nil {
		t.Errorf("native gRPC Start Raw = %q, want nil", out.Raw)
	}
}
