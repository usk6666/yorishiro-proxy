package ws

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"sync/atomic"
	"testing"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// builtinHook returns a Starlark Callable that wraps fn. fn receives the
// raw msg + ctx values and returns whatever Starlark value the test wants
// to drive action interpretation (usually starlark.None for Continue).
func builtinHook(name string, fn func(msg starlark.Value, ctx starlark.Value)) starlark.Callable {
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		if len(args) != 2 {
			return nil, fmt.Errorf("hook expects (msg, ctx); got %d args", len(args))
		}
		fn(args[0], args[1])
		return starlark.None, nil
	})
}

// TestWS_OnClose_FiresWithObservedClosePayload verifies that when the
// peer sends a Close frame, the (ws, on_close) hook fires once at
// terminate time with the observed CloseCode and CloseReason.
func TestWS_OnClose_FiresWithObservedClosePayload(t *testing.T) {
	t.Parallel()

	closeBody := make([]byte, 2+len("bye"))
	binary.BigEndian.PutUint16(closeBody[:2], 1000)
	copy(closeBody[2:], "bye")
	wire := makeFrame(t, true, OpcodeClose, closeBody)
	rwc := newFakeRWC(wire)

	engine := pluginv2.NewEngine(nil)
	var observed atomic.Int32
	var sawCode int64
	var sawReason string

	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoWS,
		Event:      pluginv2.EventOnClose,
		Phase:      pluginv2.PhaseNone,
		PluginName: "test",
		Fn: builtinHook("close", func(msg starlark.Value, _ starlark.Value) {
			observed.Add(1)
			d, ok := msg.(*starlark.Dict)
			if !ok {
				t.Errorf("msg is %T, want *starlark.Dict", msg)
				return
			}
			if v, _, _ := d.Get(starlark.String("close_code")); v != nil {
				if n, ok := v.(starlark.Int); ok {
					if i, ok := n.Int64(); ok {
						sawCode = i
					}
				}
			}
			if v, _, _ := d.Get(starlark.String("close_reason")); v != nil {
				if s, ok := v.(starlark.String); ok {
					sawReason = string(s)
				}
			}
		}),
	})

	l := New(rwc, rwc, rwc, "s-1", RoleClient, WithLifecycleEngine(engine))
	defer l.Close()
	ch := <-l.Channels()

	// Drain Close envelope, then Next must return io.EOF and trigger
	// markTerminated → fireOnClose.
	if _, err := ch.Next(context.Background()); err != nil {
		t.Fatalf("first Next (Close-frame env): %v", err)
	}
	_, err := ch.Next(context.Background())
	if err != io.EOF {
		t.Fatalf("second Next: err = %v, want io.EOF", err)
	}

	if got := observed.Load(); got != 1 {
		t.Errorf("on_close fire count = %d, want 1", got)
	}
	if sawCode != 1000 {
		t.Errorf("on_close close_code = %d, want 1000", sawCode)
	}
	if sawReason != "bye" {
		t.Errorf("on_close close_reason = %q, want bye", sawReason)
	}
}

// TestWS_OnClose_AbnormalClose_SyntheticPayload verifies that when the
// channel terminates without ever observing a Close frame (pre-frame EOF),
// (ws, on_close) still fires with a synthetic CloseCode=1006 payload.
func TestWS_OnClose_AbnormalClose_SyntheticPayload(t *testing.T) {
	t.Parallel()

	rwc := newFakeRWC(nil) // empty input → pre-frame EOF
	engine := pluginv2.NewEngine(nil)
	var sawCode int64

	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoWS,
		Event:      pluginv2.EventOnClose,
		Phase:      pluginv2.PhaseNone,
		PluginName: "test",
		Fn: builtinHook("close", func(msg starlark.Value, _ starlark.Value) {
			d := msg.(*starlark.Dict)
			v, _, _ := d.Get(starlark.String("close_code"))
			n := v.(starlark.Int)
			if i, ok := n.Int64(); ok {
				sawCode = i
			}
		}),
	})

	l := New(rwc, rwc, rwc, "s-1", RoleClient, WithLifecycleEngine(engine))
	defer l.Close()
	ch := <-l.Channels()

	if _, err := ch.Next(context.Background()); err != io.EOF {
		t.Fatalf("Next: err = %v, want io.EOF (graceful)", err)
	}
	if sawCode != 1006 {
		t.Errorf("synthetic close_code = %d, want 1006 (abnormal closure)", sawCode)
	}
}

// TestWS_OnClose_FiresOnceUnderConcurrentTermination ensures sync.Once on
// markTerminated keeps fireOnClose to a single firing under concurrent
// termination paths (Layer.Close + Next-driven EOF racing).
func TestWS_OnClose_FiresOnceUnderConcurrentTermination(t *testing.T) {
	t.Parallel()

	rwc := newFakeRWC(nil)
	engine := pluginv2.NewEngine(nil)
	var fires atomic.Int32

	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoWS,
		Event:      pluginv2.EventOnClose,
		Phase:      pluginv2.PhaseNone,
		PluginName: "test",
		Fn: builtinHook("close", func(_ starlark.Value, _ starlark.Value) {
			fires.Add(1)
		}),
	})

	l := New(rwc, rwc, rwc, "s-1", RoleClient, WithLifecycleEngine(engine))
	ch := <-l.Channels()

	// Drive Next to EOF first, then explicit Close; both reach
	// markTerminated.
	_, _ = ch.Next(context.Background())
	_ = l.Close()
	if got := fires.Load(); got != 1 {
		t.Errorf("on_close fired %d times, want 1", got)
	}
}

// TestWS_OnClose_NoEngine_NoOp verifies that without a lifecycleEngine
// the channel teardown path runs identically to the legacy code.
func TestWS_OnClose_NoEngine_NoOp(t *testing.T) {
	t.Parallel()

	rwc := newFakeRWC(nil)
	l := New(rwc, rwc, rwc, "s-1", RoleClient) // no WithLifecycleEngine
	defer l.Close()
	ch := <-l.Channels()

	// Should EOF cleanly without any panic on nil engine deref.
	if _, err := ch.Next(context.Background()); err != io.EOF {
		t.Fatalf("Next: err = %v, want io.EOF", err)
	}
}

// TestWS_OnClose_HookFiresBeforeStateRelease verifies the USK-670
// ordering contract: on_close runs while transaction_state is still
// readable. The plugin reads ctx.transaction_state.get("k") and observes
// the value an earlier-on-the-channel write seeded.
func TestWS_OnClose_HookFiresBeforeStateRelease(t *testing.T) {
	t.Parallel()

	rwc := newFakeRWC(nil)
	engine := pluginv2.NewEngine(nil)
	var seen string

	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoWS,
		Event:      pluginv2.EventOnClose,
		Phase:      pluginv2.PhaseNone,
		PluginName: "test",
		Fn: builtinHook("close", func(_ starlark.Value, ctx starlark.Value) {
			c, ok := ctx.(*pluginv2.Ctx)
			if !ok {
				t.Errorf("ctx is %T, want *pluginv2.Ctx", ctx)
				return
			}
			ts, err := c.Attr("transaction_state")
			if err != nil || ts == nil {
				t.Errorf("transaction_state Attr: err=%v val=%v", err, ts)
				return
			}
			get, err := ts.(starlark.HasAttrs).Attr("get")
			if err != nil || get == nil {
				t.Errorf("transaction_state.get Attr: err=%v val=%v", err, get)
				return
			}
			thread := &starlark.Thread{}
			ret, err := starlark.Call(thread, get.(starlark.Callable), starlark.Tuple{starlark.String("k")}, nil)
			if err != nil {
				t.Errorf("get(k): %v", err)
				return
			}
			if s, ok := ret.(starlark.String); ok {
				seen = string(s)
			}
		}),
	})

	envCtx := envelope.EnvelopeContext{ConnID: "conn-1"}
	l := New(rwc, rwc, rwc, "s-1", RoleClient,
		WithEnvelopeContext(envCtx),
		WithStateReleaser(engine),
		WithLifecycleEngine(engine),
	)
	ch := <-l.Channels()

	// Seed transaction_state via a synthetic envelope (Engine.NewCtx
	// auto-creates the ScopedState on first call). For (ConnID,
	// StreamID="s-1") on a non-HTTP protocol, transactionKey() picks
	// StreamID. So seed by calling NewCtx directly with a matching env.
	seedEnv := &envelope.Envelope{
		StreamID: "s-1",
		Protocol: envelope.ProtocolWebSocket,
		Context:  envCtx,
	}
	seedCtx := engine.NewCtx(seedEnv)
	ts, _ := seedCtx.Attr("transaction_state")
	set, _ := ts.(starlark.HasAttrs).Attr("set")
	thread := &starlark.Thread{}
	if _, err := starlark.Call(thread, set.(starlark.Callable),
		starlark.Tuple{starlark.String("k"), starlark.String("v-from-prior-hook")}, nil); err != nil {
		t.Fatalf("seed set: %v", err)
	}

	if _, err := ch.Next(context.Background()); err != io.EOF {
		t.Fatalf("Next: err = %v, want io.EOF", err)
	}
	_ = ch.Close()

	if seen != "v-from-prior-hook" {
		t.Errorf("on_close saw transaction_state[k] = %q, want %q (state must still be live when hook fires)", seen, "v-from-prior-hook")
	}
}
