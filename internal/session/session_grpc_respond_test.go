package session

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// grpcEndRespondStep emits Respond with a Receive-direction GRPCEndMessage
// for the Send envelope at blockSeq, modelling a native-gRPC SafetyFilter /
// intercept-drop block (blockedBy set) or a plugin RESPOND_GRPC (blockedBy
// empty).
type grpcEndRespondStep struct {
	blockSeq  int
	blockedBy string
}

func (s grpcEndRespondStep) Process(_ context.Context, env *envelope.Envelope) pipeline.Result {
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
			Protocol:  envelope.ProtocolGRPC,
			Message:   &envelope.GRPCEndMessage{Status: 7, Message: "blocked"},
		},
		BlockedBy: s.blockedBy,
	}
}

func grpcSendEnv(seq int, msg envelope.Message) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  "grpc-stream",
		Sequence:  seq,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message:   msg,
	}
}

// TestRunSession_GRPCEndRespond_TerminatesRPC pins USK-1202 R5: once a
// Respond carrying a native-gRPC End was delivered to the client, the RPC is
// over. The session must stop reading the client, close the upstream (so a
// half-open upstream stream does not leak a MAX_CONCURRENT_STREAMS slot and
// upstreamToClient unblocks), and report a clean (nil) result.
func TestRunSession_GRPCEndRespond_TerminatesRPC(t *testing.T) {
	for _, tc := range []struct {
		name      string
		blockedBy string
	}{
		{name: "policy block", blockedBy: "safety_filter"},
		{name: "plugin respond", blockedBy: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientCh := &mockChannel{
				streamID: "grpc-stream",
				nextEnvelopes: []*envelope.Envelope{
					grpcSendEnv(0, &envelope.GRPCStartMessage{Service: "svc", Method: "M"}),
					grpcSendEnv(1, &envelope.GRPCDataMessage{Payload: []byte("blocked")}),
					grpcSendEnv(2, &envelope.GRPCDataMessage{Payload: []byte("after"), EndStream: true}),
				},
			}
			// The upstream never answers: its Next blocks until Close.
			upstreamCh := &mockChannel{streamID: "up", blockNext: make(chan struct{})}
			dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
				return upstreamCh, nil
			}
			p := pipeline.New(grpcEndRespondStep{blockSeq: 1, blockedBy: tc.blockedBy})

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

			if got := upstreamCh.getSent(); len(got) != 1 {
				t.Errorf("upstream received %d envelopes, want 1 (Start only; nothing after the block)", len(got))
			}
			if upstreamCh.getCloseCalls() == 0 {
				t.Errorf("upstream Close not called; half-open upstream stream leaks")
			}
			sent := clientCh.getSent()
			if len(sent) != 1 {
				t.Fatalf("client received %d envelopes, want 1 (the GRPCEnd terminator)", len(sent))
			}
			if _, ok := sent[0].Message.(*envelope.GRPCEndMessage); !ok {
				t.Errorf("client received %T, want *GRPCEndMessage", sent[0].Message)
			}
		})
	}
}

// TestRunSession_GRPCEndRespond_SendFailureSurfaces guards that the clean
// termination applies only after the terminator was actually delivered: a
// failing client.Send keeps surfacing as an error.
func TestRunSession_GRPCEndRespond_SendFailureSurfaces(t *testing.T) {
	sendErr := errors.New("client gone")
	clientCh := &mockChannel{
		streamID: "grpc-stream",
		nextEnvelopes: []*envelope.Envelope{
			grpcSendEnv(0, &envelope.GRPCStartMessage{Service: "svc", Method: "M"}),
		},
		sendErr: sendErr,
	}
	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return &mockChannel{}, nil
	}
	p := pipeline.New(grpcEndRespondStep{blockSeq: 0, blockedBy: "safety_filter"})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := RunSession(ctx, clientCh, dial, p)
	if !errors.Is(err, sendErr) {
		t.Errorf("RunSession err = %v, want wrapping %v", err, sendErr)
	}
}

// TestRunSession_GRPCEndRespond_UpstreamRelayAfterEndIsClean pins the
// USK-1202 review finding F-1: upstreamToClient may already hold an upstream
// envelope when the proxy delivers its gRPC End terminator. Its client.Send
// then fails (the real grpc Channel refuses anything after End with
// errSendAfterEnd). That failure is a consequence of the proxy ending the
// RPC on purpose, so it must not turn the session result into an error.
//
// The interleaving is forced without sleeps on the hot path: the client's
// Send of the End latches "end sent", releases the upstream envelope, and
// then waits until the relay's Send was attempted and either the errgroup
// ctx was cancelled (pre-fix: the relay failure won errOnce) or a short
// grace period passed.
func TestRunSession_GRPCEndRespond_UpstreamRelayAfterEndIsClean(t *testing.T) {
	errAfterEnd := errors.New("grpc: send after End on this direction")

	var endMu sync.Mutex
	endSent := false
	relayAttempted := make(chan struct{})
	var relayOnce sync.Once

	upstreamGate := make(chan struct{}, 1)
	upstreamCh := &mockChannel{
		streamID: "up",
		nextEnvelopes: []*envelope.Envelope{{
			StreamID:  "up",
			Direction: envelope.Receive,
			Protocol:  envelope.ProtocolGRPC,
			Message:   &envelope.GRPCStartMessage{Service: "svc", Method: "M"},
		}},
		nextGate: upstreamGate,
	}

	clientCh := &mockChannel{
		streamID: "grpc-stream",
		nextEnvelopes: []*envelope.Envelope{
			grpcSendEnv(0, &envelope.GRPCStartMessage{Service: "svc", Method: "M"}),
			grpcSendEnv(1, &envelope.GRPCDataMessage{Payload: []byte("blocked")}),
		},
	}
	clientCh.sendHook = func(ctx context.Context, env *envelope.Envelope) error {
		if _, ok := env.Message.(*envelope.GRPCEndMessage); ok {
			endMu.Lock()
			endSent = true
			endMu.Unlock()
			upstreamGate <- struct{}{}
			<-relayAttempted
			select {
			case <-ctx.Done():
			case <-time.After(500 * time.Millisecond):
			}
			return nil
		}
		endMu.Lock()
		ended := endSent
		endMu.Unlock()
		if ended {
			relayOnce.Do(func() { close(relayAttempted) })
			return errAfterEnd
		}
		return nil
	}

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return upstreamCh, nil
	}
	p := pipeline.New(grpcEndRespondStep{blockSeq: 1, blockedBy: "safety_filter"})

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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := RunSession(ctx, clientCh, dial, p, opts)
	if err != nil {
		t.Errorf("RunSession err = %v, want nil (relay failure after the proxy's End terminator)", err)
	}
	mu.Lock()
	if !completed || completeErr != nil {
		t.Errorf("OnComplete called=%v err=%v, want called with nil", completed, completeErr)
	}
	mu.Unlock()
	select {
	case <-relayAttempted:
	default:
		t.Fatalf("upstream relay Send after End was never attempted; interleaving not exercised")
	}
}
