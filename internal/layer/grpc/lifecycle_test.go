package grpc

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

func builtinHook(name string, fn func(msg starlark.Value, ctx starlark.Value)) starlark.Callable {
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		if len(args) != 2 {
			return nil, fmt.Errorf("hook expects (msg, ctx); got %d args", len(args))
		}
		fn(args[0], args[1])
		return starlark.None, nil
	})
}

// TestGRPC_OnEnd_FiresOnceForTrailers verifies that the (grpc, on_end)
// hook fires exactly once when the inner stream concludes with an
// H2TrailersEvent (the unary-RPC happy path: HEADERS + DATA + TRAILERS).
func TestGRPC_OnEnd_FiresOnceForTrailers(t *testing.T) {
	t.Parallel()

	engine := pluginv2.NewEngine(nil)
	var fires atomic.Int32
	var sawStatus int64
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoGRPC,
		Event:      pluginv2.EventOnEnd,
		Phase:      pluginv2.PhaseNone,
		PluginName: "test",
		Fn: builtinHook("end", func(msg starlark.Value, _ starlark.Value) {
			fires.Add(1)
			d := msg.(*starlark.Dict)
			v, _, _ := d.Get(starlark.String("status"))
			if n, ok := v.(starlark.Int); ok {
				if i, ok := n.Int64(); ok {
					sawStatus = i
				}
			}
		}),
	})

	stub := newStubInner("stream-1")
	stub.pushHeaders(envelope.Send, []byte("HDRS"), &http2.H2HeadersEvent{
		Method:    "POST",
		Scheme:    "https",
		Authority: "service.example.com",
		Path:      "/echo.Echo/Unary",
		Headers: []envelope.KeyValue{
			{Name: "content-type", Value: "application/grpc"},
		},
	})
	stub.pushHeaders(envelope.Receive, []byte("RHDRS"), &http2.H2HeadersEvent{
		Status: 200,
		Headers: []envelope.KeyValue{
			{Name: "content-type", Value: "application/grpc"},
		},
	})
	stub.pushData(envelope.Receive, makeLPM(false, []byte("payload")), false)
	stub.pushTrailers(envelope.Receive, []byte("TRL"), []envelope.KeyValue{
		{Name: "grpc-status", Value: "0"},
		{Name: "grpc-message", Value: ""},
	})

	ch := Wrap(stub, nil, RoleServer, WithLifecycleEngine(engine))
	defer ch.Close()

	// Drain envelopes: SendStart + RecvStart + RecvData + RecvEnd = 4
	envs := drainNext(t, ch, 4)
	if _, ok := envs[3].Message.(*envelope.GRPCEndMessage); !ok {
		t.Fatalf("envs[3].Message = %T, want *GRPCEndMessage", envs[3].Message)
	}

	if got := fires.Load(); got != 1 {
		t.Errorf("on_end fired %d times, want 1", got)
	}
	if sawStatus != 0 {
		t.Errorf("on_end status = %d, want 0 (OK)", sawStatus)
	}
}

// TestGRPC_OnEnd_FiresOnceForTrailersOnlyResponse verifies the D4 path:
// trailers-only response (HEADERS with END_STREAM + grpc-status) emits
// both Start and End in a single absorb call. The hook fires once for
// the End even though both are queued in one pass.
func TestGRPC_OnEnd_FiresOnceForTrailersOnlyResponse(t *testing.T) {
	t.Parallel()

	engine := pluginv2.NewEngine(nil)
	var fires atomic.Int32
	var sawStatus int64
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoGRPC,
		Event:      pluginv2.EventOnEnd,
		Phase:      pluginv2.PhaseNone,
		PluginName: "test",
		Fn: builtinHook("end", func(msg starlark.Value, _ starlark.Value) {
			fires.Add(1)
			d := msg.(*starlark.Dict)
			v, _, _ := d.Get(starlark.String("status"))
			n := v.(starlark.Int)
			if i, ok := n.Int64(); ok {
				sawStatus = i
			}
		}),
	})

	stub := newStubInner("stream-1")
	stub.pushHeaders(envelope.Receive, []byte("HPACK-trailers-only"), &http2.H2HeadersEvent{
		Status:    200,
		EndStream: true,
		Headers: []envelope.KeyValue{
			{Name: "content-type", Value: "application/grpc"},
			{Name: "grpc-status", Value: "13"},
		},
	})

	ch := Wrap(stub, nil, RoleClient, WithLifecycleEngine(engine))
	defer ch.Close()

	envs := drainNext(t, ch, 2)
	if _, ok := envs[0].Message.(*envelope.GRPCStartMessage); !ok {
		t.Fatalf("envs[0].Message = %T, want *GRPCStartMessage", envs[0].Message)
	}
	if _, ok := envs[1].Message.(*envelope.GRPCEndMessage); !ok {
		t.Fatalf("envs[1].Message = %T, want *GRPCEndMessage", envs[1].Message)
	}

	if got := fires.Load(); got != 1 {
		t.Errorf("on_end fired %d times, want 1", got)
	}
	if sawStatus != 13 {
		t.Errorf("on_end status = %d, want 13", sawStatus)
	}
}

// TestGRPC_OnEnd_NoEngine_NoOp verifies that without WithLifecycleEngine
// the wrapper does not deref a nil engine on End emission.
func TestGRPC_OnEnd_NoEngine_NoOp(t *testing.T) {
	t.Parallel()

	stub := newStubInner("stream-1")
	stub.pushHeaders(envelope.Receive, []byte("RHDRS"), &http2.H2HeadersEvent{
		Status:    200,
		EndStream: true,
		Headers: []envelope.KeyValue{
			{Name: "content-type", Value: "application/grpc"},
			{Name: "grpc-status", Value: "0"},
		},
	})

	ch := Wrap(stub, nil, RoleClient)
	defer ch.Close()

	envs := drainNext(t, ch, 2)
	if len(envs) != 2 {
		t.Fatalf("len(envs) = %d, want 2", len(envs))
	}
}

// TestGRPC_OnEnd_FailSoftOnPluginError verifies that a Starlark runtime
// error inside the hook does not propagate to the channel. The next
// envelope drain still succeeds.
func TestGRPC_OnEnd_FailSoftOnPluginError(t *testing.T) {
	t.Parallel()

	engine := pluginv2.NewEngine(nil)
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoGRPC,
		Event:      pluginv2.EventOnEnd,
		Phase:      pluginv2.PhaseNone,
		PluginName: "kaboom",
		Fn: starlark.NewBuiltin("kaboom", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
			return nil, fmt.Errorf("simulated plugin error")
		}),
	})

	stub := newStubInner("stream-1")
	stub.pushHeaders(envelope.Receive, []byte("RHDRS"), &http2.H2HeadersEvent{
		Status:    200,
		EndStream: true,
		Headers: []envelope.KeyValue{
			{Name: "content-type", Value: "application/grpc"},
			{Name: "grpc-status", Value: "0"},
		},
	})

	ch := Wrap(stub, nil, RoleClient, WithLifecycleEngine(engine))
	defer ch.Close()

	envs := drainNext(t, ch, 2)
	if _, ok := envs[1].Message.(*envelope.GRPCEndMessage); !ok {
		t.Fatalf("envs[1].Message = %T, want *GRPCEndMessage (plugin error must not break wire)", envs[1].Message)
	}
	_ = context.Background()
}
