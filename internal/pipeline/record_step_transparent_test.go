package pipeline

import (
	"context"
	"net/netip"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-1318: a Stream created on a transparent connection carries the
// original destination (the pre-REDIRECT IP:port) as tags.original_dst,
// next to the client's SNI on TLS MITM. A context without a
// TransparentScope (explicit proxy, tcp_forward, resend / fuzz) leaves the
// tag absent.
func TestRecordStep_CreateStream_TransparentOriginalDstTag(t *testing.T) {
	transparent := func(dst string) context.Context {
		return connector.ContextWithTransparentScope(context.Background(), &connector.TransparentScope{
			Dst: netip.MustParseAddrPort(dst),
		})
	}
	tests := []struct {
		name            string
		ctx             context.Context
		tls             *envelope.TLSSnapshot
		wantOriginalDst string
		wantSNI         string
	}{
		{name: "transparent plain", ctx: transparent("192.0.2.10:80"), wantOriginalDst: "192.0.2.10:80"},
		{name: "transparent IPv6", ctx: transparent("[2001:db8::1]:8080"), wantOriginalDst: "[2001:db8::1]:8080"},
		{name: "transparent TLS keeps sni", ctx: transparent("192.0.2.10:443"),
			tls: &envelope.TLSSnapshot{SNI: "named.example"}, wantOriginalDst: "192.0.2.10:443", wantSNI: "named.example"},
		{name: "no transparent scope", ctx: context.Background(),
			tls: &envelope.TLSSnapshot{SNI: "named.example"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &mockWriter{}
			step := NewRecordStep(w, nil)
			env := &envelope.Envelope{
				StreamID:  "stream-1",
				FlowID:    "flow-1",
				Direction: envelope.Send,
				Protocol:  envelope.ProtocolRaw,
				Raw:       []byte("data"),
				Message:   &envelope.RawMessage{Bytes: []byte("data")},
				Context:   envelope.EnvelopeContext{ConnID: "conn-1", TLS: tt.tls},
			}
			step.Process(tt.ctx, env)
			if len(w.streams) != 1 {
				t.Fatalf("expected 1 stream, got %d", len(w.streams))
			}
			tags := w.streams[0].Tags
			got, ok := tags["original_dst"]
			if tt.wantOriginalDst == "" {
				if ok {
					t.Errorf("Tags[original_dst] = %q on a non-transparent Stream, want absent", got)
				}
			} else if got != tt.wantOriginalDst {
				t.Errorf("Tags[original_dst] = %q, want %q (tags %v)", got, tt.wantOriginalDst, tags)
			}
			if tags["sni"] != tt.wantSNI {
				t.Errorf("Tags[sni] = %q, want %q", tags["sni"], tt.wantSNI)
			}
		})
	}
}
