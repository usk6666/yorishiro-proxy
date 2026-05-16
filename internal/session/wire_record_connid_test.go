// USK-910 regression test: the wire-record closures used by the
// detach / aggregator / native-gRPC paths must preserve the inner
// envelope's ConnID (and the rest of EnvelopeContext other than
// WireLevel) when stamping the wire_level discriminator.
//
// Before USK-910 the closures in h2_frame_record.go, grpc_lpm_record.go,
// and grpcweb_base64_record.go assigned a builder-derived ctxTmpl onto
// env.Context, clobbering the ConnID populated by the producing Layer's
// WithEnvelopeContext template. Combined with USK-908's first-write-
// wins streamCreated guard, aggregator-path / native-gRPC h2 streams
// produced streams rows with empty conn_id when the wire-level envelope
// raced ahead of the semantic envelope.
//
// This file exercises the two closure constructors whose return type is
// a plain `func(*envelope.Envelope)` directly accessible from the
// session package: h2FrameRecordCallback (USK-889 + USK-895 shared
// helper via wireLevelRecordCallback) and buildH2FrameRecordClosure
// (USK-897 + USK-899 shared producer for the aggregator-path /
// native-gRPC h2-frame Options).
//
// The GRPCLPMRecordOption and GRPCWebBase64RecordOption variants wrap
// the same closure shape in opaque package-private Option types and
// share their per-envelope assignment line-for-line with
// buildH2FrameRecordClosure — the pipeline-level cross-arrival test
// `TestRecordStep_CreateStream_PreservesInnerEnvelopeConnID_USK910` in
// internal/pipeline/record_step_h2frame_test.go covers the property
// for those Options via fixture envelopes shaped like what the closures
// emit.

package session

import (
	"context"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// captureContextStep is a pipeline.Step that records env.Context for
// every envelope that reaches it. The wire-record closures end with
// `_, _, _ = recPipeline.Run(ctx, env)`, so installing this Step as
// the only Step of the record-only Pipeline captures what the closure
// left on env.Context.
type captureContextStep struct {
	mu     sync.Mutex
	caught []envelope.EnvelopeContext
}

func (s *captureContextStep) Process(_ context.Context, env *envelope.Envelope) pipeline.Result {
	if env == nil {
		return pipeline.Result{Action: pipeline.Continue}
	}
	s.mu.Lock()
	s.caught = append(s.caught, env.Context)
	s.mu.Unlock()
	return pipeline.Result{Action: pipeline.Continue}
}

func (s *captureContextStep) snapshot() []envelope.EnvelopeContext {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]envelope.EnvelopeContext, len(s.caught))
	copy(out, s.caught)
	return out
}

func TestWireRecordCallbacks_PreserveInnerEnvelopeConnID_USK910(t *testing.T) {
	const innerConnID = "conn-from-producer-layer"
	const innerTargetHost = "inner.target:443"

	// flowCtx mirrors the sparse builder-side template that used to
	// clobber the inner envelope. ConnID is intentionally empty here —
	// that is exactly the production shape (proxybuild builder.go
	// constructed `envelope.EnvelopeContext{TargetHost: target}` with
	// ConnID unset). If the closure ever revives the
	// `env.Context = ctxTmpl` assignment, the captured ConnID would
	// become "" and the test would fail.
	flowCtx := envelope.EnvelopeContext{TargetHost: "upstream.example:443"}

	type subcase struct {
		name           string
		innerDirection envelope.Direction
		wantWireLevel  string
		fire           func(t *testing.T, p *pipeline.Pipeline, flowCtx envelope.EnvelopeContext, env *envelope.Envelope)
	}

	cases := []subcase{
		{
			name:           "h2FrameRecordCallback_receive",
			innerDirection: envelope.Receive,
			wantWireLevel:  flow.WireLevelH2Frame,
			fire: func(t *testing.T, p *pipeline.Pipeline, flowCtx envelope.EnvelopeContext, env *envelope.Envelope) {
				t.Helper()
				cb := h2FrameRecordCallback(context.Background(), p, "session-stream", envelope.Receive, flowCtx)
				if cb == nil {
					t.Fatal("h2FrameRecordCallback returned nil")
				}
				cb(env)
			},
		},
		{
			name:           "buildH2FrameRecordClosure_send",
			innerDirection: envelope.Send,
			wantWireLevel:  flow.WireLevelH2Frame,
			fire: func(t *testing.T, p *pipeline.Pipeline, flowCtx envelope.EnvelopeContext, env *envelope.Envelope) {
				t.Helper()
				cb := buildH2FrameRecordClosure(context.Background(), p, "session-stream", flowCtx)
				if cb == nil {
					t.Fatal("buildH2FrameRecordClosure returned nil")
				}
				cb(env)
			},
		},
		{
			name:           "buildH2FrameRecordClosure_receive",
			innerDirection: envelope.Receive,
			wantWireLevel:  flow.WireLevelH2Frame,
			fire: func(t *testing.T, p *pipeline.Pipeline, flowCtx envelope.EnvelopeContext, env *envelope.Envelope) {
				t.Helper()
				cb := buildH2FrameRecordClosure(context.Background(), p, "session-stream", flowCtx)
				if cb == nil {
					t.Fatal("buildH2FrameRecordClosure returned nil")
				}
				cb(env)
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cap := &captureContextStep{}
			// Build a minimal Pipeline whose only Step is the capture
			// Step. The closures call recPipeline.Run(ctx, env), so a
			// single-Step Pipeline observes exactly what the closure
			// left on env.Context.
			p := pipeline.New(cap)

			env := &envelope.Envelope{
				StreamID:  "inner-stream",
				FlowID:    "inner-flow",
				Direction: tc.innerDirection,
				Sequence:  0,
				Protocol:  envelope.ProtocolHTTP,
				Raw:       []byte("payload"),
				Context: envelope.EnvelopeContext{
					ConnID:     innerConnID,
					TargetHost: innerTargetHost,
				},
			}
			tc.fire(t, p, flowCtx, env)

			got := cap.snapshot()
			if len(got) != 1 {
				t.Fatalf("captured envelopes = %d, want 1", len(got))
			}
			if got[0].ConnID != innerConnID {
				t.Errorf("captured Context.ConnID = %q, want %q (USK-910: closure must not clobber producer-stamped ConnID)", got[0].ConnID, innerConnID)
			}
			if got[0].WireLevel != tc.wantWireLevel {
				t.Errorf("captured Context.WireLevel = %q, want %q", got[0].WireLevel, tc.wantWireLevel)
			}
			// TargetHost from the inner envelope must also be preserved
			// (locks in the related correctness gain documented in the
			// USK-910 design review, Resolved #11).
			if got[0].TargetHost != innerTargetHost {
				t.Errorf("captured Context.TargetHost = %q, want %q (USK-910: closure must not normalize inner Context fields)", got[0].TargetHost, innerTargetHost)
			}
		})
	}
}
