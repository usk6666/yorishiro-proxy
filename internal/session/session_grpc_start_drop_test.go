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

// dropSendStartStep Drops every Send envelope whose Message is a
// *GRPCStartMessage, with no BlockedBy — the Result shape a plugin DROP on
// grpc.on_start / grpc-web.on_start produces. blockedBy lets a case model a
// policy Step (e.g. BudgetStep) that attributes its Drop.
type dropSendStartStep struct {
	blockedBy string
}

func (s dropSendStartStep) Process(_ context.Context, env *envelope.Envelope) pipeline.Result {
	if env.Direction != envelope.Send {
		return pipeline.Result{Action: pipeline.Continue}
	}
	if _, ok := env.Message.(*envelope.GRPCStartMessage); !ok {
		return pipeline.Result{Action: pipeline.Continue}
	}
	return pipeline.Result{Action: pipeline.Drop, BlockedBy: s.blockedBy}
}

// errDataBeforeStart mirrors the error the real upstream gRPC / gRPC-Web
// Channels return when a Data envelope is sent on a stream whose Start was
// never sent.
var errDataBeforeStart = errors.New("GRPCDataMessage before GRPCStartMessage on Send")

// startTrackingUpstream returns an upstream mock that, like the real gRPC
// Channels, refuses a Data / End envelope before a Start was sent.
func startTrackingUpstream() *mockChannel {
	up := &mockChannel{streamID: "up"}
	started := false
	up.sendHook = func(_ context.Context, env *envelope.Envelope) error {
		up.mu.Lock()
		defer up.mu.Unlock()
		switch env.Message.(type) {
		case *envelope.GRPCStartMessage:
			started = true
		default:
			if !started {
				return errDataBeforeStart
			}
		}
		up.sent = append(up.sent, env)
		return nil
	}
	return up
}

func grpcProtoSendEnv(proto envelope.Protocol, seq int, msg envelope.Message) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  "grpc-stream",
		Sequence:  seq,
		Direction: envelope.Send,
		Protocol:  proto,
		Message:   msg,
	}
}

// TestRunSession_GRPCStartDrop_EndsSessionWithoutDial pins USK-1387: a Drop
// of a Send gRPC / gRPC-Web Start (plugin DROP on on_start, or a policy Step
// such as BudgetStep) ends the RPC at Start time. The upstream is never
// dialed, the following Data / End never reach it, the client Channel is
// closed (the transport then answers RST_STREAM(CANCEL) on h2 or closes the
// HTTP/1.x connection) and the session ends cleanly.
func TestRunSession_GRPCStartDrop_EndsSessionWithoutDial(t *testing.T) {
	for _, tc := range []struct {
		name      string
		proto     envelope.Protocol
		blockedBy string
	}{
		{name: "grpc plugin drop", proto: envelope.ProtocolGRPC},
		{name: "grpc-web plugin drop", proto: envelope.ProtocolGRPCWeb},
		{name: "grpc budget drop", proto: envelope.ProtocolGRPC, blockedBy: "budget"},
		{name: "grpc-web budget drop", proto: envelope.ProtocolGRPCWeb, blockedBy: "budget"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientCh := &mockChannel{
				streamID: "grpc-stream",
				nextEnvelopes: []*envelope.Envelope{
					grpcProtoSendEnv(tc.proto, 0, &envelope.GRPCStartMessage{Service: "svc", Method: "M"}),
					grpcProtoSendEnv(tc.proto, 1, &envelope.GRPCDataMessage{Payload: []byte("payload")}),
					grpcProtoSendEnv(tc.proto, 2, &envelope.GRPCEndMessage{}),
				},
			}
			upstreamCh := startTrackingUpstream()
			var dialMu sync.Mutex
			dialed := 0
			dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
				dialMu.Lock()
				dialed++
				dialMu.Unlock()
				return upstreamCh, nil
			}
			p := pipeline.New(dropSendStartStep{blockedBy: tc.blockedBy})

			var mu sync.Mutex
			var completeErr error
			completed := false
			var dropped []string
			opts := SessionOptions{
				OnComplete: func(_ context.Context, _ string, err error) {
					mu.Lock()
					completed = true
					completeErr = err
					mu.Unlock()
				},
				OnPipelineDrop: func(_ context.Context, _ *envelope.Envelope, by string) {
					mu.Lock()
					dropped = append(dropped, by)
					mu.Unlock()
				},
			}

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			start := time.Now()
			err := RunSession(ctx, clientCh, dial, p, opts)
			elapsed := time.Since(start)

			if err != nil {
				t.Errorf("RunSession err = %v after %v, want nil (RPC dropped by proxy)", err, elapsed)
			}
			if elapsed > 2*time.Second {
				t.Errorf("RunSession took %v, want prompt return at the Start Drop", elapsed)
			}
			dialMu.Lock()
			gotDial := dialed
			dialMu.Unlock()
			if gotDial != 0 {
				t.Errorf("upstream dialed %d times, want 0", gotDial)
			}
			if n := len(upstreamCh.getSent()); n != 0 {
				t.Errorf("upstream received %d envelopes, want 0", n)
			}
			if n := len(clientCh.getSent()); n != 0 {
				t.Errorf("client received %d envelopes, want 0 (DROP answers no gRPC status)", n)
			}
			if clientCh.getCloseCalls() == 0 {
				t.Errorf("client Channel not closed; the transport would not end the RPC")
			}
			mu.Lock()
			defer mu.Unlock()
			if !completed || completeErr != nil {
				t.Errorf("OnComplete called=%v err=%v, want called with nil", completed, completeErr)
			}
			if tc.blockedBy != "" && (len(dropped) != 1 || dropped[0] != tc.blockedBy) {
				t.Errorf("OnPipelineDrop calls = %v, want [%s] (audit attribution kept)", dropped, tc.blockedBy)
			}
			if tc.blockedBy == "" && len(dropped) != 0 {
				t.Errorf("OnPipelineDrop calls = %v, want none for an unattributed Drop", dropped)
			}
		})
	}
}

// TestRunSession_NonGRPCStartDrop_KeepsSessionOpen pins that the Start-Drop
// teardown is keyed on a Send gRPC / gRPC-Web Start only: a Dropped HTTP
// request still leaves the session loop running so the next request on the
// same Channel is forwarded (HTTP/1.x keep-alive), and a Dropped gRPC Data
// envelope (not a Start) does not end the session either.
func TestRunSession_NonGRPCStartDrop_KeepsSessionOpen(t *testing.T) {
	t.Run("http drop then forward", func(t *testing.T) {
		first := &envelope.Envelope{
			StreamID: "s", Sequence: 0, Direction: envelope.Send, Protocol: envelope.ProtocolHTTP,
			Message: &envelope.HTTPMessage{Method: "GET", Path: "/drop"},
		}
		second := &envelope.Envelope{
			StreamID: "s", Sequence: 1, Direction: envelope.Send, Protocol: envelope.ProtocolHTTP,
			Message: &envelope.HTTPMessage{Method: "GET", Path: "/ok"},
		}
		clientCh := &mockChannel{streamID: "s", nextEnvelopes: []*envelope.Envelope{first, second}}
		upstreamCh := &mockChannel{streamID: "up"}
		dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
			return upstreamCh, nil
		}
		p := pipeline.New(dropSeqStep{seq: 0})
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := RunSession(ctx, clientCh, dial, p); err != nil {
			t.Fatalf("RunSession err = %v, want nil", err)
		}
		got := upstreamCh.getSent()
		if len(got) != 1 || got[0].Message.(*envelope.HTTPMessage).Path != "/ok" {
			t.Errorf("upstream received %d envelopes, want only /ok", len(got))
		}
	})

	t.Run("grpc data drop does not end session", func(t *testing.T) {
		clientCh := &mockChannel{
			streamID: "grpc-stream",
			nextEnvelopes: []*envelope.Envelope{
				grpcProtoSendEnv(envelope.ProtocolGRPC, 0, &envelope.GRPCStartMessage{Service: "svc", Method: "M"}),
				grpcProtoSendEnv(envelope.ProtocolGRPC, 1, &envelope.GRPCDataMessage{Payload: []byte("x")}),
				grpcProtoSendEnv(envelope.ProtocolGRPC, 2, &envelope.GRPCEndMessage{}),
			},
		}
		upstreamCh := startTrackingUpstream()
		dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
			return upstreamCh, nil
		}
		p := pipeline.New(dropSeqStep{seq: 1})
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := RunSession(ctx, clientCh, dial, p); err != nil {
			t.Fatalf("RunSession err = %v, want nil", err)
		}
		if n := len(upstreamCh.getSent()); n != 2 {
			t.Errorf("upstream received %d envelopes, want 2 (Start, End)", n)
		}
	})
}

// dropSeqStep Drops the Send envelope at seq without attribution.
type dropSeqStep struct {
	seq int
}

func (s dropSeqStep) Process(_ context.Context, env *envelope.Envelope) pipeline.Result {
	if env.Direction == envelope.Send && env.Sequence == s.seq {
		return pipeline.Result{Action: pipeline.Drop}
	}
	return pipeline.Result{Action: pipeline.Continue}
}
