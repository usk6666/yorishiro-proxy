package session

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// receiveStep applies fn to Receive-direction envelopes and continues every
// Send envelope.
type receiveStep func(env *envelope.Envelope) pipeline.Result

func (f receiveStep) Process(_ context.Context, env *envelope.Envelope) pipeline.Result {
	if env.Direction != envelope.Receive {
		return pipeline.Result{Action: pipeline.Continue}
	}
	return f(env)
}

func httpRecvEnv(seq, status int) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID: "s", Sequence: seq, Direction: envelope.Receive, Protocol: envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{Status: status},
	}
}

func httpSendReq() *envelope.Envelope {
	return &envelope.Envelope{
		StreamID: "s", Sequence: 0, Direction: envelope.Send, Protocol: envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{Method: "GET", Path: "/"},
	}
}

// sessionResult runs RunSession with an OnComplete / OnPipelineDrop probe.
type sessionResult struct {
	err       error
	completed bool
	compErr   error
	dropped   []string
}

func runProbedSession(t *testing.T, client layer.Channel, upstream *mockChannel, p *pipeline.Pipeline) sessionResult {
	t.Helper()
	var mu sync.Mutex
	var res sessionResult
	opts := SessionOptions{
		OnComplete: func(_ context.Context, _ string, err error) {
			mu.Lock()
			res.completed = true
			res.compErr = err
			mu.Unlock()
		},
		OnPipelineDrop: func(_ context.Context, _ *envelope.Envelope, by string) {
			mu.Lock()
			res.dropped = append(res.dropped, by)
			mu.Unlock()
		},
	}
	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) { return upstream, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	err := RunSession(ctx, client, dial, p, opts)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("RunSession took %v, want a prompt return", elapsed)
	}
	mu.Lock()
	defer mu.Unlock()
	res.err = err
	return res
}

// TestRunSession_ReceiveRespondWithoutResponse_NotForwarded: a Receive-
// direction Respond that carries no response envelope must not silently
// forward the upstream envelope it replaced. The session logs a Warn and
// treats it as a Drop.
func TestRunSession_ReceiveRespondWithoutResponse_NotForwarded(t *testing.T) {
	var logBuf bytes.Buffer
	var logMu sync.Mutex
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(lockedBuf{mu: &logMu, buf: &logBuf}, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)

	client := &mockChannel{streamID: "s", nextEnvelopes: []*envelope.Envelope{httpSendReq()}}
	upstream := &mockChannel{streamID: "up", nextEnvelopes: []*envelope.Envelope{httpRecvEnv(1, 200)}}
	p := pipeline.New(receiveStep(func(*envelope.Envelope) pipeline.Result {
		return pipeline.Result{Action: pipeline.Respond}
	}))

	res := runProbedSession(t, client, upstream, p)
	if res.err != nil {
		t.Errorf("RunSession err = %v, want nil", res.err)
	}
	if sent := client.getSent(); len(sent) != 0 {
		t.Errorf("client received %d envelopes (first %#v), want 0: the replaced upstream response must not be forwarded", len(sent), sent[0].Message)
	}
	logMu.Lock()
	logs := logBuf.String()
	logMu.Unlock()
	if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "Respond without response") {
		t.Errorf("no Warn for the Respond without a response; logs:\n%s", logs)
	}
}

type lockedBuf struct {
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (w lockedBuf) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

// TestRunSession_ReceivePolicyRespond_DeliversAndEndsExchange: a policy Step
// (intercept drop of a held response) answers a Receive envelope with a 403
// Respond carrying BlockedBy. The session reports the attribution, delivers
// the 403 instead of the upstream response, and stops relaying the exchange,
// so the upstream's final response after a held-and-dropped 1xx cannot reach
// the client as a second response.
func TestRunSession_ReceivePolicyRespond_DeliversAndEndsExchange(t *testing.T) {
	client := &mockChannel{streamID: "s", nextEnvelopes: []*envelope.Envelope{httpSendReq()}}
	upstream := &mockChannel{streamID: "up", nextEnvelopes: []*envelope.Envelope{httpRecvEnv(1, 103), httpRecvEnv(2, 200)}}
	p := pipeline.New(receiveStep(func(env *envelope.Envelope) pipeline.Result {
		if env.Message.(*envelope.HTTPMessage).Status != 103 {
			return pipeline.Result{Action: pipeline.Continue}
		}
		return pipeline.Result{
			Action:    pipeline.Respond,
			Response:  httpRecvEnv(env.Sequence, 403),
			BlockedBy: pipeline.BlockedByInterceptDrop,
		}
	}))

	res := runProbedSession(t, client, upstream, p)
	if res.err != nil {
		t.Errorf("RunSession err = %v, want nil", res.err)
	}
	sent := client.getSent()
	if len(sent) != 1 {
		t.Fatalf("client received %d envelopes, want exactly the 403", len(sent))
	}
	if m := sent[0].Message.(*envelope.HTTPMessage); m.Status != 403 {
		t.Errorf("client received status %d, want the policy 403", m.Status)
	}
	if len(res.dropped) != 1 || res.dropped[0] != pipeline.BlockedByInterceptDrop {
		t.Errorf("OnPipelineDrop calls = %v, want [%s]", res.dropped, pipeline.BlockedByInterceptDrop)
	}
}

func grpcRecvEnv(proto envelope.Protocol, seq int, msg envelope.Message) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID: "grpc-stream", Sequence: seq, Direction: envelope.Receive, Protocol: proto, Message: msg,
	}
}

func grpcUnaryClient(proto envelope.Protocol) *mockChannel {
	return &mockChannel{
		streamID: "grpc-stream",
		nextEnvelopes: []*envelope.Envelope{
			grpcProtoSendEnv(proto, 0, &envelope.GRPCStartMessage{Service: "svc", Method: "M"}),
			grpcProtoSendEnv(proto, 1, &envelope.GRPCDataMessage{Payload: []byte("hi"), EndStream: true}),
		},
	}
}

func grpcUnaryUpstream(proto envelope.Protocol) *mockChannel {
	return &mockChannel{
		streamID: "up",
		nextEnvelopes: []*envelope.Envelope{
			grpcRecvEnv(proto, 0, &envelope.GRPCStartMessage{}),
			grpcRecvEnv(proto, 1, &envelope.GRPCDataMessage{Payload: []byte("hi")}),
			grpcRecvEnv(proto, 2, &envelope.GRPCEndMessage{Status: 0}),
		},
	}
}

// TestRunSession_ReceiveGRPCStartRespond_EndsRPC: a RESPOND_GRPC on the
// response-side on_start of a native-gRPC / gRPC-Web RPC delivers only the
// plugin's End to the client (the Layer renders it Trailers-Only), never the
// upstream's response, tears the upstream down and ends the session cleanly.
func TestRunSession_ReceiveGRPCStartRespond_EndsRPC(t *testing.T) {
	for _, proto := range []envelope.Protocol{envelope.ProtocolGRPC, envelope.ProtocolGRPCWeb} {
		t.Run(string(proto), func(t *testing.T) {
			client := grpcUnaryClient(proto)
			upstream := grpcUnaryUpstream(proto)
			p := pipeline.New(receiveStep(func(env *envelope.Envelope) pipeline.Result {
				if _, ok := env.Message.(*envelope.GRPCStartMessage); !ok {
					return pipeline.Result{Action: pipeline.Continue}
				}
				return pipeline.Result{Action: pipeline.Respond, Response: grpcRecvEnv(proto, 1,
					&envelope.GRPCEndMessage{Status: 7, Message: "denied by plugin"})}
			}))

			res := runProbedSession(t, client, upstream, p)
			if res.err != nil {
				t.Errorf("RunSession err = %v, want nil (the proxy ended the RPC on purpose)", res.err)
			}
			if !res.completed || res.compErr != nil {
				t.Errorf("OnComplete called=%v err=%v, want called with nil", res.completed, res.compErr)
			}
			sent := client.getSent()
			if len(sent) != 1 {
				t.Fatalf("client received %d envelopes, want only the plugin End", len(sent))
			}
			if end, ok := sent[0].Message.(*envelope.GRPCEndMessage); !ok || end.Status != 7 {
				t.Errorf("client received %#v, want GRPCEnd status 7", sent[0].Message)
			}
			if upstream.getCloseCalls() == 0 {
				t.Error("upstream Channel not closed; the upstream stream would stay half-open")
			}
		})
	}
}

// TestRunSession_ReceiveGRPCStartDrop_EndsRPC: a DROP on the response-side
// on_start ends the RPC with no gRPC status: nothing of the upstream's
// response reaches the client, the client Channel is closed (RST_STREAM on
// h2, connection close on HTTP/1.x gRPC-Web) and the session ends cleanly.
func TestRunSession_ReceiveGRPCStartDrop_EndsRPC(t *testing.T) {
	for _, proto := range []envelope.Protocol{envelope.ProtocolGRPC, envelope.ProtocolGRPCWeb} {
		t.Run(string(proto), func(t *testing.T) {
			client := grpcUnaryClient(proto)
			upstream := grpcUnaryUpstream(proto)
			p := pipeline.New(receiveStep(func(env *envelope.Envelope) pipeline.Result {
				if _, ok := env.Message.(*envelope.GRPCStartMessage); !ok {
					return pipeline.Result{Action: pipeline.Continue}
				}
				return pipeline.Result{Action: pipeline.Drop}
			}))

			res := runProbedSession(t, client, upstream, p)
			if res.err != nil {
				t.Errorf("RunSession err = %v, want nil", res.err)
			}
			if !res.completed || res.compErr != nil {
				t.Errorf("OnComplete called=%v err=%v, want called with nil", res.completed, res.compErr)
			}
			if sent := client.getSent(); len(sent) != 0 {
				t.Errorf("client received %d envelopes (first %#v), want 0", len(sent), sent[0].Message)
			}
			if client.getCloseCalls() == 0 {
				t.Error("client Channel not closed; the transport would not end the RPC")
			}
		})
	}
}
