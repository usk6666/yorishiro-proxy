package session

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// grpcWebEndRespondStep is the gRPC-Web counterpart of grpcEndRespondStep:
// it answers the Send envelope at blockSeq with a Receive GRPCEndMessage on
// ProtocolGRPCWeb, the shape pipeline.grpcPolicyDropResult produces for a
// gRPC-Web block (USK-1220).
type grpcWebEndRespondStep struct {
	blockSeq int
}

func (s grpcWebEndRespondStep) Process(_ context.Context, env *envelope.Envelope) pipeline.Result {
	if env.Direction != envelope.Send || env.Sequence != s.blockSeq {
		return pipeline.Result{Action: pipeline.Continue}
	}
	return pipeline.Result{
		Action: pipeline.Respond,
		Response: &envelope.Envelope{
			StreamID:  env.StreamID,
			FlowID:    env.FlowID,
			Sequence:  env.Sequence + 1,
			Direction: envelope.Receive,
			Protocol:  envelope.ProtocolGRPCWeb,
			Message:   &envelope.GRPCEndMessage{Status: 7, Message: "blocked by safety_filter"},
		},
		BlockedBy: "safety_filter",
	}
}

func grpcWebSendEnv(seq int, msg envelope.Message) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  "grpcweb-stream",
		Sequence:  seq,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPCWeb,
		Message:   msg,
	}
}

// TestRunSession_GRPCWebEndRespond_TerminatesRPC pins USK-1220 (U3): a
// gRPC-Web request reaches the session as Start, Data*, then the grpcweb
// Layer's synthetic Send End sentinel, and the upstream grpcweb Channel only
// writes the request when that sentinel is sent. Once the proxy answered a
// Start or Data block with its gRPC-Web End terminator, the sentinel must
// never be forwarded (it would send the payload-stripped request upstream),
// the upstream — if dialed — must be closed so its buffer is discarded, and
// the session must end cleanly.
func TestRunSession_GRPCWebEndRespond_TerminatesRPC(t *testing.T) {
	for _, tc := range []struct {
		name     string
		blockSeq int
		wantDial bool
		wantSent int
	}{
		{name: "start block", blockSeq: 0, wantDial: false, wantSent: 0},
		{name: "data block", blockSeq: 1, wantDial: true, wantSent: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientCh := &mockChannel{
				streamID: "grpcweb-stream",
				nextEnvelopes: []*envelope.Envelope{
					grpcWebSendEnv(0, &envelope.GRPCStartMessage{Service: "svc", Method: "M"}),
					grpcWebSendEnv(1, &envelope.GRPCDataMessage{Payload: []byte("blocked")}),
					grpcWebSendEnv(2, &envelope.GRPCEndMessage{}),
				},
			}
			upstreamCh := &mockChannel{streamID: "up", blockNext: make(chan struct{})}
			var dialMu sync.Mutex
			dialed := 0
			dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
				dialMu.Lock()
				dialed++
				dialMu.Unlock()
				return upstreamCh, nil
			}
			p := pipeline.New(grpcWebEndRespondStep{blockSeq: tc.blockSeq})

			var mu sync.Mutex
			var completeErr error
			completed := false
			opts := SessionOptions{
				OnComplete: func(_ context.Context, _ string, err error) {
					mu.Lock()
					completed = true
					completeErr = err
					mu.Unlock()
				},
			}

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			start := time.Now()
			err := RunSession(ctx, clientCh, dial, p, opts)
			elapsed := time.Since(start)

			if err != nil {
				t.Fatalf("RunSession err = %v after %v, want nil (RPC terminated by proxy)", err, elapsed)
			}
			if elapsed > 2*time.Second {
				t.Errorf("RunSession took %v, want prompt return", elapsed)
			}
			mu.Lock()
			if !completed || completeErr != nil {
				t.Errorf("OnComplete called=%v err=%v, want called with nil", completed, completeErr)
			}
			mu.Unlock()

			dialMu.Lock()
			gotDial := dialed > 0
			dialMu.Unlock()
			if gotDial != tc.wantDial {
				t.Errorf("upstream dialed = %v, want %v", gotDial, tc.wantDial)
			}
			got := upstreamCh.getSent()
			for _, e := range got {
				if _, ok := e.Message.(*envelope.GRPCEndMessage); ok {
					t.Errorf("upstream received the Send End sentinel; the payload-stripped request would be written upstream")
				}
			}
			if len(got) != tc.wantSent {
				t.Errorf("upstream received %d envelopes, want %d", len(got), tc.wantSent)
			}
			if tc.wantDial && upstreamCh.getCloseCalls() == 0 {
				t.Errorf("upstream Close not called; the buffered request is not discarded")
			}
			sent := clientCh.getSent()
			if len(sent) != 1 {
				t.Fatalf("client received %d envelopes, want 1 (the gRPC-Web End terminator)", len(sent))
			}
			if _, ok := sent[0].Message.(*envelope.GRPCEndMessage); !ok {
				t.Errorf("client received %T, want *GRPCEndMessage", sent[0].Message)
			}
		})
	}
}
