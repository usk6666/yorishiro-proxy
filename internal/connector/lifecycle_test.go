package connector

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

func builtinHook(name string, fn func(msg starlark.Value, ctx starlark.Value) starlark.Value) starlark.Callable {
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		if len(args) != 2 {
			return nil, fmt.Errorf("hook expects (msg, ctx); got %d args", len(args))
		}
		return fn(args[0], args[1]), nil
	})
}

// TestListener_PluginV2_OnConnect_DropClosesConnection verifies that a
// (connection, on_connect) hook returning DROP closes the accepted TCP
// connection before any peek/dispatch occurs.
func TestListener_PluginV2_OnConnect_DropClosesConnection(t *testing.T) {
	detector := NewDetector()
	detector.Register(ProtocolHTTP1, &fakeFactory{kind: ProtocolHTTP1})

	engine := pluginv2.NewEngine(nil)
	var dispatchCount atomic.Int32
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoConnection,
		Event:      pluginv2.EventOnConnect,
		Phase:      pluginv2.PhaseNone,
		PluginName: "guard",
		Fn: builtinHook("drop", func(_ starlark.Value, _ starlark.Value) starlark.Value {
			return starlark.String("DROP")
		}),
	})

	recorder := &recordingDispatcher{}
	cfg := ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Dispatch: DispatcherFunc(func(c context.Context, p *PeekConn, k ProtocolKind, f CodecFactory) error {
			dispatchCount.Add(1)
			return recorder.Dispatch(c, p, k, f)
		}),
	}
	l, _ := startListener(t, cfg)
	l.SetPluginV2Engine(engine)

	conn, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// On DROP, the listener closes conn before peeking. The client side
	// observes either an immediate Read EOF or a write that fails. Wait
	// briefly for the listener side to act.
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected EOF/error on DROPed connection; got nil")
	}

	// Dispatcher must NOT have been called.
	if got := dispatchCount.Load(); got != 0 {
		t.Errorf("dispatch called %d times, want 0 (DROP must short-circuit before detect)", got)
	}
}

// TestListener_PluginV2_OnDisconnect_FiresAfterDrop verifies that
// connection.on_disconnect still fires even when on_connect DROPs the
// connection — the connection WAS accepted, then closed.
func TestListener_PluginV2_OnDisconnect_FiresAfterDrop(t *testing.T) {
	detector := NewDetector()

	engine := pluginv2.NewEngine(nil)
	var disconnectFires atomic.Int32
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoConnection,
		Event:      pluginv2.EventOnConnect,
		Phase:      pluginv2.PhaseNone,
		PluginName: "guard",
		Fn: builtinHook("drop", func(_ starlark.Value, _ starlark.Value) starlark.Value {
			return starlark.String("DROP")
		}),
	})
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoConnection,
		Event:      pluginv2.EventOnDisconnect,
		Phase:      pluginv2.PhaseNone,
		PluginName: "trace",
		Fn: builtinHook("disc", func(_ starlark.Value, _ starlark.Value) starlark.Value {
			disconnectFires.Add(1)
			return starlark.None
		}),
	})

	cfg := ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Dispatch: DispatcherFunc(func(c context.Context, p *PeekConn, k ProtocolKind, f CodecFactory) error { return nil }),
	}
	l, _ := startListener(t, cfg)
	l.SetPluginV2Engine(engine)

	conn, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	waitFor(t, 500*time.Millisecond, func() bool {
		return disconnectFires.Load() >= 1
	})
	if got := disconnectFires.Load(); got != 1 {
		t.Errorf("on_disconnect fired %d times, want 1", got)
	}
}

// TestSOCKS5_PluginV2_OnConnect_DropClosesPC verifies that
// (socks5, on_connect) returning DROP terminates the SOCKS5 handler
// after Negotiate succeeds and BEFORE BuildConnectionStack.
func TestSOCKS5_PluginV2_OnConnect_DropClosesPC(t *testing.T) {
	t.Parallel()

	engine := pluginv2.NewEngine(nil)
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoSOCKS5,
		Event:      pluginv2.EventOnConnect,
		Phase:      pluginv2.PhaseNone,
		PluginName: "guard",
		Fn: builtinHook("drop", func(_ starlark.Value, _ starlark.Value) starlark.Value {
			return starlark.String("DROP")
		}),
	})

	var stackCalled atomic.Bool
	handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
		Negotiator:     NewSOCKS5Negotiator(nil),
		PluginV2Engine: engine,
		OnStack: func(ctx context.Context, stack *ConnectionStack, clientSnap, upstreamSnap *envelope.TLSSnapshot, target string) {
			stackCalled.Store(true)
		},
	})

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	go func() {
		defer clientConn.Close()
		_, _ = clientConn.Write([]byte{0x05, 0x01, 0x00})
		buf := make([]byte, 2)
		if _, err := clientConn.Read(buf); err != nil {
			return
		}
		host := "example.com"
		req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
		req = append(req, []byte(host)...)
		req = append(req, 0x01, 0xBB)
		_, _ = clientConn.Write(req)
		reply := make([]byte, 10)
		_, _ = clientConn.Read(reply)
	}()

	pc := NewPeekConn(serverConn)
	ctx := ContextWithConnID(context.Background(), "test-conn")
	if err := handler(ctx, pc); err != nil {
		t.Errorf("handler returned error: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	if stackCalled.Load() {
		t.Error("OnStack must not be called after socks5.on_connect DROP")
	}
}

// TestFireTLSHandshakeHook_ServerSide verifies that fireTLSHandshakeHook
// dispatches (tls, on_handshake) with side="server" and the snapshot's
// SNI / ALPN exposed via the payload dict.
func TestFireTLSHandshakeHook_ServerSide(t *testing.T) {
	t.Parallel()

	engine := pluginv2.NewEngine(nil)
	var sawSide string
	var sawSNI string
	var sawALPN string
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoTLS,
		Event:      pluginv2.EventOnHandshake,
		Phase:      pluginv2.PhaseNone,
		PluginName: "tls-trace",
		Fn: builtinHook("tls", func(msg starlark.Value, _ starlark.Value) starlark.Value {
			d := msg.(*starlark.Dict)
			v, _, _ := d.Get(starlark.String("side"))
			sawSide = string(v.(starlark.String))
			v, _, _ = d.Get(starlark.String("sni"))
			sawSNI = string(v.(starlark.String))
			v, _, _ = d.Get(starlark.String("alpn"))
			sawALPN = string(v.(starlark.String))
			return starlark.None
		}),
	})

	snap := &envelope.TLSSnapshot{SNI: "example.com", ALPN: "h2"}
	cfg := &BuildConfig{PluginV2Engine: engine}
	fireTLSHandshakeHook(context.Background(), cfg, "server", snap)

	if sawSide != "server" {
		t.Errorf("side = %q, want server", sawSide)
	}
	if sawSNI != "example.com" {
		t.Errorf("sni = %q, want example.com", sawSNI)
	}
	if sawALPN != "h2" {
		t.Errorf("alpn = %q, want h2", sawALPN)
	}
}

// TestFireTLSHandshakeHook_NoEngine_NoOp verifies that fireTLSHandshakeHook
// is a no-op without a PluginV2Engine — no panic, no work.
func TestFireTLSHandshakeHook_NoEngine_NoOp(t *testing.T) {
	t.Parallel()
	cfg := &BuildConfig{}
	fireTLSHandshakeHook(context.Background(), cfg, "client", &envelope.TLSSnapshot{SNI: "x"})
}

// TestFireTLSHandshakeHook_DropDisallowed_FailsSoft verifies that a hook
// returning DROP (which is not in the surface ActionMask for
// (tls, on_handshake)) is fail-soft Warn'd and does not panic the helper.
func TestFireTLSHandshakeHook_DropDisallowed_FailsSoft(t *testing.T) {
	t.Parallel()

	engine := pluginv2.NewEngine(nil)
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoTLS,
		Event:      pluginv2.EventOnHandshake,
		Phase:      pluginv2.PhaseNone,
		PluginName: "bad",
		Fn: builtinHook("bad", func(_ starlark.Value, _ starlark.Value) starlark.Value {
			return starlark.String("DROP")
		}),
	})

	cfg := &BuildConfig{PluginV2Engine: engine}
	fireTLSHandshakeHook(context.Background(), cfg, "server", &envelope.TLSSnapshot{SNI: "x"})
}

// TestListener_PluginV2_OnConnect_ContinueLetsThrough verifies that a
// CONTINUE outcome from on_connect lets the connection proceed to
// detection / dispatch normally.
func TestListener_PluginV2_OnConnect_ContinueLetsThrough(t *testing.T) {
	detector := NewDetector()
	detector.Register(ProtocolHTTP1, &fakeFactory{kind: ProtocolHTTP1})

	engine := pluginv2.NewEngine(nil)
	var connectFires atomic.Int32
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoConnection,
		Event:      pluginv2.EventOnConnect,
		Phase:      pluginv2.PhaseNone,
		PluginName: "trace",
		Fn: builtinHook("trace", func(_ starlark.Value, _ starlark.Value) starlark.Value {
			connectFires.Add(1)
			return starlark.None
		}),
	})

	recorder := &recordingDispatcher{}
	cfg := ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Dispatch: recorder,
	}
	l, _ := startListener(t, cfg)
	l.SetPluginV2Engine(engine)

	conn, err := net.Dial("tcp", l.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	waitFor(t, 500*time.Millisecond, func() bool {
		return len(recorder.snapshot()) >= 1
	})
	if got := connectFires.Load(); got != 1 {
		t.Errorf("on_connect fired %d times, want 1", got)
	}
	if entries := recorder.snapshot(); len(entries) != 1 {
		t.Errorf("dispatch entries = %d, want 1 (CONTINUE must let through)", len(entries))
	}
}
