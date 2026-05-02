package grpcweb

import (
	"fmt"
	"sync/atomic"
	"testing"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
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

// TestGRPCWeb_OnEnd_FiresOnceForEmbeddedTrailer verifies the natural
// happy path: response body carries data + an embedded trailer LPM with
// grpc-status, and (grpc-web, on_end) fires once with the parsed status.
func TestGRPCWeb_OnEnd_FiresOnceForEmbeddedTrailer(t *testing.T) {
	t.Parallel()

	engine := pluginv2.NewEngine(nil)
	var fires atomic.Int32
	var sawStatus int64
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoGRPCWeb,
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

	payload := []byte("response-msg")
	trailer := []byte("grpc-status: 0\r\ngrpc-message: OK\r\n")
	body := append([]byte{}, EncodeFrame(false, false, payload)...)
	body = append(body, EncodeFrame(true, false, trailer)...)

	headers := []envelope.KeyValue{
		{Name: "content-type", Value: "application/grpc-web+proto"},
	}
	in := mustHTTPResponseEnv("s-1", headers, body, 200)

	mock := newMockChannel("s-1", in)
	ch := Wrap(mock, RoleClient, WithLifecycleEngine(engine))
	defer ch.Close()

	envs := drainEnvelopes(t, ch, 5)
	if len(envs) != 3 {
		t.Fatalf("got %d envelopes, want 3 (Start+Data+End)", len(envs))
	}

	if got := fires.Load(); got != 1 {
		t.Errorf("on_end fired %d times, want 1", got)
	}
	if sawStatus != 0 {
		t.Errorf("on_end status = %d, want 0", sawStatus)
	}
}

// TestGRPCWeb_OnEnd_FiresForMissingTrailerAnomaly verifies that the
// response-with-data-but-no-trailer path (which the wrapper synthesizes
// an End for with AnomalyMissingGRPCWebTrailer) also fires on_end once.
func TestGRPCWeb_OnEnd_FiresForMissingTrailerAnomaly(t *testing.T) {
	t.Parallel()

	engine := pluginv2.NewEngine(nil)
	var fires atomic.Int32
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoGRPCWeb,
		Event:      pluginv2.EventOnEnd,
		Phase:      pluginv2.PhaseNone,
		PluginName: "test",
		Fn: builtinHook("end", func(_ starlark.Value, _ starlark.Value) {
			fires.Add(1)
		}),
	})

	payload := []byte("orphan")
	body := append([]byte{}, EncodeFrame(false, false, payload)...) // no trailer

	headers := []envelope.KeyValue{
		{Name: "content-type", Value: "application/grpc-web+proto"},
	}
	in := mustHTTPResponseEnv("s-1", headers, body, 200)

	mock := newMockChannel("s-1", in)
	ch := Wrap(mock, RoleClient, WithLifecycleEngine(engine))
	defer ch.Close()

	_ = drainEnvelopes(t, ch, 5)
	if got := fires.Load(); got != 1 {
		t.Errorf("on_end fired %d times, want 1 (missing-trailer anomaly path)", got)
	}
}

// TestGRPCWeb_OnEnd_NoEngine_NoOp verifies no nil-deref when the
// lifecycleEngine is absent.
func TestGRPCWeb_OnEnd_NoEngine_NoOp(t *testing.T) {
	t.Parallel()

	payload := []byte("p")
	trailer := []byte("grpc-status: 0\r\n")
	body := append([]byte{}, EncodeFrame(false, false, payload)...)
	body = append(body, EncodeFrame(true, false, trailer)...)
	in := mustHTTPResponseEnv("s-1", []envelope.KeyValue{
		{Name: "content-type", Value: "application/grpc-web+proto"},
	}, body, 200)

	mock := newMockChannel("s-1", in)
	ch := Wrap(mock, RoleClient) // no lifecycle engine
	defer ch.Close()

	envs := drainEnvelopes(t, ch, 5)
	if len(envs) != 3 {
		t.Fatalf("got %d envelopes, want 3", len(envs))
	}
}
