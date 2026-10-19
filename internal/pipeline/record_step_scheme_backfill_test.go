package pipeline

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// semanticHTTPSendEnvelope builds the aggregator's semantic request
// envelope (Send, Seq 0) carrying the client-declared :scheme.
func semanticHTTPSendEnvelope(streamID, scheme string) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    "semantic-" + streamID,
		Direction: envelope.Send,
		Sequence:  0,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "POST", Scheme: scheme, Authority: "example.test", Path: "/",
		},
		Context: envelope.EnvelopeContext{ConnID: "c1"},
	}
}

func schemeUpdates(w *mockWriter) []streamUpdateRecord {
	var out []streamUpdateRecord
	for _, u := range w.updates {
		if u.update.Scheme != "" {
			out = append(out, u)
		}
	}
	return out
}

// TestRecordStep_SchemeBackfill_OverlayFirst verifies that when a
// wire-level overlay creates the Stream (Scheme empty), the following
// semantic envelope backfills Scheme exactly once (USK-1197).
func TestRecordStep_SchemeBackfill_OverlayFirst(t *testing.T) {
	cases := []struct {
		name     string
		overlay  *envelope.Envelope
		semantic *envelope.Envelope
		want     string
	}{
		{
			name:     "h2-frame_then_HTTPMessage",
			overlay:  h2FrameSendEnvelope("s1"),
			semantic: semanticHTTPSendEnvelope("s1", "https"),
			want:     "https",
		},
		{
			name:     "h2-frame_then_HTTPMessage_h2c",
			overlay:  h2FrameSendEnvelope("s1"),
			semantic: semanticHTTPSendEnvelope("s1", "http"),
			want:     "http",
		},
		{
			name: "grpcweb-base64_then_GRPCStart",
			overlay: &envelope.Envelope{
				StreamID: "s1", Direction: envelope.Send, Sequence: 0,
				Protocol: envelope.ProtocolGRPCWeb, Raw: []byte("AAAA"),
				Context: envelope.EnvelopeContext{ConnID: "c1", WireLevel: flow.WireLevelGRPCWebBase64},
			},
			semantic: &envelope.Envelope{
				StreamID: "s1", Direction: envelope.Send, Sequence: 0,
				Protocol: envelope.ProtocolGRPCWeb,
				Message:  &envelope.GRPCStartMessage{Service: "svc", Method: "M", Scheme: "https"},
				Context:  envelope.EnvelopeContext{ConnID: "c1"},
			},
			want: "https",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &mockWriter{}
			step := NewRecordStep(w, nil)
			ctx := context.Background()

			step.Process(ctx, tc.overlay)
			step.Process(ctx, tc.semantic)
			// A second semantic Send/Seq0 on the same stream must not
			// issue another write.
			step.Process(ctx, tc.semantic)

			if len(w.streams) != 1 {
				t.Fatalf("SaveStream calls = %d, want 1", len(w.streams))
			}
			if w.streams[0].Scheme != "" {
				t.Fatalf("precondition: overlay-created Stream.Scheme = %q, want empty", w.streams[0].Scheme)
			}
			got := schemeUpdates(w)
			if len(got) != 1 {
				t.Fatalf("UpdateStream{Scheme} calls = %d, want 1 (updates=%+v)", len(got), w.updates)
			}
			if got[0].streamID != "s1" || got[0].update.Scheme != tc.want {
				t.Errorf("scheme update = %+v, want stream s1 scheme %q", got[0], tc.want)
			}
		})
	}
}

// TestRecordStep_SchemeBackfill_SemanticFirstNoExtraWrite guards the
// semantic-first paths (native gRPC order; body-less HTTPMessage): the
// Stream is created with the right scheme and no UpdateStream is
// issued for scheme (USK-1197).
func TestRecordStep_SchemeBackfill_SemanticFirstNoExtraWrite(t *testing.T) {
	cases := []struct {
		name string
		envs []*envelope.Envelope
		want string
	}{
		{
			name: "native_gRPC_order",
			envs: func() []*envelope.Envelope {
				start := semanticGRPCStartSendEnvelope("s1")
				start.Message.(*envelope.GRPCStartMessage).Scheme = "https"
				return []*envelope.Envelope{start, h2FrameSendEnvelope("s1"), grpcLPMFrameSendEnvelope("s1")}
			}(),
			want: "https",
		},
		{
			// A repeated semantic Send/Seq0 after an overlay must not
			// write either: the gate is armed only when an overlay
			// created the Stream.
			name: "HTTPMessage_then_overlay_then_HTTPMessage",
			envs: []*envelope.Envelope{
				semanticHTTPSendEnvelope("s1", "https"),
				h2FrameSendEnvelope("s1"),
				semanticHTTPSendEnvelope("s1", "https"),
			},
			want: "https",
		},
		{
			name: "bodyless_HTTPMessage",
			envs: []*envelope.Envelope{semanticHTTPSendEnvelope("s1", "https")},
			want: "https",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &mockWriter{}
			step := NewRecordStep(w, nil)
			ctx := context.Background()
			for _, env := range tc.envs {
				step.Process(ctx, env)
			}
			if len(w.streams) != 1 || w.streams[0].Scheme != tc.want {
				t.Fatalf("streams = %+v, want one with Scheme %q", w.streams, tc.want)
			}
			if got := schemeUpdates(w); len(got) != 0 {
				t.Errorf("UpdateStream{Scheme} calls = %d, want 0 on semantic-first path", len(got))
			}
		})
	}
}

// TestRecordStep_SchemeBackfill_OverlayOnlyNoWrite verifies that a stream
// that never sees a semantic envelope issues no scheme update.
func TestRecordStep_SchemeBackfill_OverlayOnlyNoWrite(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)
	step.Process(context.Background(), h2FrameSendEnvelope("s1"))
	if got := schemeUpdates(w); len(got) != 0 {
		t.Errorf("UpdateStream{Scheme} calls = %d, want 0", len(got))
	}
}
