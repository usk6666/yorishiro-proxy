// USK-1197 regression tests: a wire-level overlay envelope (h2-frame /
// grpcweb-base64) that reaches RecordStep before the semantic envelope
// wins the USK-908 first-write-wins createStream race. The overlay
// carries no Message, so createStream used to persist Stream.Scheme="".
// The semantic envelope that follows carries the real scheme and must
// backfill it.
//
// These tests drive the REAL producers (httpaggregator / grpcweb wraps)
// with the REAL session record closures and a REAL SQLite store, so the
// overlay-first ordering is the one the production Layer creates, not a
// hand-ordered Process sequence.

package session

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/httpaggregator"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

func newSchemeTestStore(t *testing.T) *flow.SQLiteStore {
	t.Helper()
	store, err := flow.NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "flows.db"), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// runAllThroughPipeline drains ch, running every semantic envelope it
// yields through p — the same order the session loop uses (the overlay
// callbacks fire synchronously inside ch.Next).
func runAllThroughPipeline(t *testing.T, ctx context.Context, ch layer.Channel, p *pipeline.Pipeline) []*envelope.Envelope {
	t.Helper()
	var out []*envelope.Envelope
	for i := 0; i < 16; i++ {
		env, err := ch.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return out
			}
			t.Fatalf("Next: %v", err)
		}
		if _, _, err := p.Run(ctx, env); err != nil {
			t.Fatalf("pipeline Run: %v", err)
		}
		out = append(out, env)
	}
	t.Fatal("channel did not reach EOF")
	return out
}

func TestAggregatorOverlayFirst_StreamSchemeRecorded_USK1197(t *testing.T) {
	cases := []struct {
		name   string
		scheme string
	}{
		{name: "tls_h2_https", scheme: "https"},
		{name: "h2c_http", scheme: "http"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			store := newSchemeTestStore(t)
			p := pipeline.New(pipeline.NewRecordStep(store, nil))
			const streamID = "agg-stream-1"

			// Fixture shape follows the H2 event Channel output consumed by
			// httpaggregator (see aggregator_test.go
			// TestAggregator_HeadersBodyEndStream): HEADERS without
			// END_STREAM, then DATA carrying END_STREAM.
			inner := &mockChannel{
				streamID: streamID,
				nextEnvelopes: []*envelope.Envelope{
					{
						StreamID:  streamID,
						FlowID:    "f-headers",
						Direction: envelope.Send,
						Protocol:  envelope.ProtocolHTTP,
						Context:   envelope.EnvelopeContext{ConnID: "conn-1"},
						Message: &http2.H2HeadersEvent{
							Method: "POST", Scheme: tc.scheme, Authority: "example.com", Path: "/?case=post",
						},
					},
					{
						StreamID:  streamID,
						FlowID:    "f-data",
						Direction: envelope.Send,
						Protocol:  envelope.ProtocolHTTP,
						Context:   envelope.EnvelopeContext{ConnID: "conn-1"},
						Raw:       []byte("a=1"),
						Message:   &http2.H2DataEvent{Payload: []byte("a=1"), EndStream: true},
					},
				},
			}
			aggCh := httpaggregator.Wrap(inner, httpaggregator.RoleServer, nil, httpaggregator.WrapOptions{},
				AggregatorH2FrameRecordOption(ctx, p, streamID, envelope.EnvelopeContext{}))

			envs := runAllThroughPipeline(t, ctx, aggCh, p)
			if len(envs) != 1 {
				t.Fatalf("semantic envelopes = %d, want 1", len(envs))
			}
			if m, ok := envs[0].Message.(*envelope.HTTPMessage); !ok || m.Scheme != tc.scheme {
				t.Fatalf("semantic envelope message = %#v, want HTTPMessage with Scheme %q", envs[0].Message, tc.scheme)
			}

			st, err := store.GetStream(ctx, streamID)
			if err != nil {
				t.Fatalf("GetStream: %v", err)
			}
			if st.Scheme != tc.scheme {
				t.Errorf("Stream.Scheme = %q, want %q (overlay-first createStream must be backfilled from the semantic HTTPMessage)", st.Scheme, tc.scheme)
			}

			// MITM Principle 3: the h2-frame overlay row is still recorded.
			frames, err := store.GetFlows(ctx, streamID, flow.FlowListOptions{WireLevel: flow.WireLevelH2Frame})
			if err != nil {
				t.Fatalf("GetFlows(h2-frame): %v", err)
			}
			if len(frames) == 0 {
				t.Errorf("h2-frame overlay flows = 0, want >= 1")
			}
		})
	}
}

func TestGRPCWebTextOverlayFirst_StreamSchemeRecorded_USK1197(t *testing.T) {
	ctx := context.Background()
	store := newSchemeTestStore(t)
	p := pipeline.New(pipeline.NewRecordStep(store, nil))
	const streamID = "gw-stream-1"

	// Fixture shape follows grpcweb encoded_form_callback_test.go
	// (mustHTTPRequestEnv): an HTTP/1.x request HTTPMessage with a
	// grpc-web-text body, as produced by the http1 Layer.
	body := grpcweb.EncodeBase64Body(grpcweb.EncodeFrame(false, false, []byte("hello-grpcweb")))
	inner := &mockChannel{
		streamID: streamID,
		nextEnvelopes: []*envelope.Envelope{{
			StreamID:  streamID,
			FlowID:    "f-req",
			Direction: envelope.Send,
			Protocol:  envelope.ProtocolHTTP,
			Context:   envelope.EnvelopeContext{ConnID: "conn-1"},
			Raw:       body,
			Message: &envelope.HTTPMessage{
				Method:    "POST",
				Scheme:    "https",
				Authority: "example.com",
				Path:      "/pkg.Svc/Method",
				Headers: []envelope.KeyValue{
					{Name: "Content-Type", Value: "application/grpc-web-text+proto"},
				},
				Body: body,
			},
		}},
	}
	gwCh := grpcweb.Wrap(inner, grpcweb.RoleServer,
		GRPCWebBase64RecordOption(ctx, p, streamID, envelope.EnvelopeContext{}))

	_ = runAllThroughPipeline(t, ctx, gwCh, p)

	st, err := store.GetStream(ctx, streamID)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if st.Scheme != "https" {
		t.Errorf("Stream.Scheme = %q, want %q (grpcweb-base64 overlay-first createStream must be backfilled)", st.Scheme, "https")
	}
	if st.Protocol != string(envelope.ProtocolGRPCWeb) {
		t.Errorf("Stream.Protocol = %q, want %q", st.Protocol, envelope.ProtocolGRPCWeb)
	}
}
