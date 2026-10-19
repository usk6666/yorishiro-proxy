package proxybuild

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// USK-1193: an intercept hold that ends because its ctx ended is recorded
// through OnPipelineDrop with that same, already-cancelled ctx. The audit
// write must still land (first-request SaveStream and mid-stream
// UpdateStream branches) and the session's OnComplete afterwards must not
// overwrite it.
func TestSessionOptions_PipelineDrop_CancelledCtx_RecordsInterceptCancelled(t *testing.T) {
	tests := []struct {
		name       string
		seedActive bool
		protocol   envelope.Protocol
		msg        envelope.Message
	}{
		{"first request (SaveStream)", false, envelope.ProtocolHTTP, &envelope.HTTPMessage{Method: "GET", Scheme: "http", Path: "/held"}},
		{"mid-stream (UpdateStream)", true, envelope.ProtocolWebSocket, &envelope.WSMessage{Opcode: envelope.WSText, Payload: []byte("x")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := newSQLiteStoreForTest(t)
			const streamID = "stream-1193"
			if tc.seedActive {
				seedActiveStreamWithTags(t, store, streamID, nil)
			}
			deps := Deps{ListenerName: "live", FlowStore: store}
			opts := buildSessionOptions(deps, deps.ListenerName)
			if opts.OnPipelineDrop == nil || opts.OnComplete == nil {
				t.Fatal("buildSessionOptions did not install OnPipelineDrop / OnComplete")
			}

			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			env := &envelope.Envelope{StreamID: streamID, Direction: envelope.Receive, Protocol: tc.protocol, Message: tc.msg}
			opts.OnPipelineDrop(ctx, env, pipeline.BlockedByInterceptCancelled)
			// A nil err would finalise state=complete unless the blocked set guards it.
			opts.OnComplete(ctx, streamID, nil)

			st, err := store.GetStream(context.Background(), streamID)
			if err != nil {
				t.Fatalf("GetStream: %v (audit Stream not written)", err)
			}
			if st.State != "error" {
				t.Errorf("State = %q, want error", st.State)
			}
			if st.BlockedBy != pipeline.BlockedByInterceptCancelled {
				t.Errorf("BlockedBy = %q, want %q", st.BlockedBy, pipeline.BlockedByInterceptCancelled)
			}
		})
	}
}
