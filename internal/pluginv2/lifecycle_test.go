package pluginv2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// builtinLifecycleHook is the lifecycle counterpart of builtinHook
// (dispatch_test.go). The plugin sees an opaque starlark.Value first arg
// (a frozen dict supplied by FireLifecycle) and a *Ctx second arg.
func builtinLifecycleHook(name string, fn func(msg starlark.Value, c *Ctx) (starlark.Value, error)) starlark.Callable {
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		if len(args) != 2 {
			return nil, fmt.Errorf("hook expects (msg, ctx); got %d args", len(args))
		}
		c, ok := args[1].(*Ctx)
		if !ok {
			return nil, fmt.Errorf("arg 1 not *Ctx: %T", args[1])
		}
		return fn(args[0], c)
	})
}

func TestFireLifecycle_NilEngine_ReturnsContinue(t *testing.T) {
	var e *Engine
	action, err := e.FireLifecycle(context.Background(), ProtoConnection, EventOnConnect, nil, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if action != ActionContinue {
		t.Errorf("Action = %v, want Continue", action)
	}
}

func TestFireLifecycle_NoHooks_ReturnsContinue(t *testing.T) {
	e := NewEngine(nil)
	action, err := e.FireLifecycle(context.Background(), ProtoConnection, EventOnConnect, nil, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if action != ActionContinue {
		t.Errorf("Action = %v, want Continue", action)
	}
}

func TestFireLifecycle_RegistrationOrder(t *testing.T) {
	e := NewEngine(nil)
	var observed []string

	e.Registry().Register(Hook{
		Protocol: ProtoConnection, Event: EventOnConnect, Phase: PhaseNone,
		PluginName: "p1",
		Fn: builtinLifecycleHook("p1", func(msg starlark.Value, c *Ctx) (starlark.Value, error) {
			observed = append(observed, "p1")
			return starlark.None, nil
		}),
	})
	e.Registry().Register(Hook{
		Protocol: ProtoConnection, Event: EventOnConnect, Phase: PhaseNone,
		PluginName: "p2",
		Fn: builtinLifecycleHook("p2", func(msg starlark.Value, c *Ctx) (starlark.Value, error) {
			observed = append(observed, "p2")
			return starlark.None, nil
		}),
	})
	e.Registry().Register(Hook{
		Protocol: ProtoConnection, Event: EventOnConnect, Phase: PhaseNone,
		PluginName: "p3",
		Fn: builtinLifecycleHook("p3", func(msg starlark.Value, c *Ctx) (starlark.Value, error) {
			observed = append(observed, "p3")
			return starlark.None, nil
		}),
	})

	payload := BuildConnectionConnectDict("conn-1", "1.2.3.4", "default")
	action, err := e.FireLifecycle(context.Background(), ProtoConnection, EventOnConnect, nil, payload)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if action != ActionContinue {
		t.Errorf("Action = %v, want Continue", action)
	}
	want := []string{"p1", "p2", "p3"}
	if len(observed) != len(want) {
		t.Fatalf("observed = %v, want %v", observed, want)
	}
	for i, v := range want {
		if observed[i] != v {
			t.Errorf("observed[%d] = %q, want %q", i, observed[i], v)
		}
	}
}

func TestFireLifecycle_DropShortCircuits(t *testing.T) {
	e := NewEngine(nil)
	var calls []string

	e.Registry().Register(Hook{
		Protocol: ProtoConnection, Event: EventOnConnect, Phase: PhaseNone,
		PluginName: "p1",
		Fn: builtinLifecycleHook("p1", func(msg starlark.Value, c *Ctx) (starlark.Value, error) {
			calls = append(calls, "p1")
			return starlark.None, nil
		}),
	})
	e.Registry().Register(Hook{
		Protocol: ProtoConnection, Event: EventOnConnect, Phase: PhaseNone,
		PluginName: "p2-drops",
		Fn: builtinLifecycleHook("p2", func(msg starlark.Value, c *Ctx) (starlark.Value, error) {
			calls = append(calls, "p2-drops")
			return starlark.String("DROP"), nil
		}),
	})
	e.Registry().Register(Hook{
		Protocol: ProtoConnection, Event: EventOnConnect, Phase: PhaseNone,
		PluginName: "p3-never",
		Fn: builtinLifecycleHook("p3", func(msg starlark.Value, c *Ctx) (starlark.Value, error) {
			calls = append(calls, "p3-never")
			return starlark.None, nil
		}),
	})

	payload := BuildConnectionConnectDict("conn-1", "1.2.3.4", "default")
	action, err := e.FireLifecycle(context.Background(), ProtoConnection, EventOnConnect, nil, payload)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if action != ActionDrop {
		t.Errorf("Action = %v, want Drop", action)
	}
	if len(calls) != 2 {
		t.Fatalf("expected p1 + p2 only; got %v", calls)
	}
}

func TestFireLifecycle_DisallowedDropOnObservationEvent_FailsSoft(t *testing.T) {
	e := NewEngine(nil)
	var saw []string

	e.Registry().Register(Hook{
		Protocol: ProtoWS, Event: EventOnClose, Phase: PhaseNone,
		PluginName: "bad-drop",
		Fn: builtinLifecycleHook("bad", func(msg starlark.Value, c *Ctx) (starlark.Value, error) {
			saw = append(saw, "bad-drop")
			// (ws, on_close) accepts CONTINUE only — DROP is disallowed.
			return starlark.String("DROP"), nil
		}),
	})
	e.Registry().Register(Hook{
		Protocol: ProtoWS, Event: EventOnClose, Phase: PhaseNone,
		PluginName: "next",
		Fn: builtinLifecycleHook("next", func(msg starlark.Value, c *Ctx) (starlark.Value, error) {
			saw = append(saw, "next")
			return starlark.None, nil
		}),
	})

	payload := BuildWSCloseDict(&envelope.WSMessage{Opcode: envelope.WSClose, CloseCode: 1000})
	action, err := e.FireLifecycle(context.Background(), ProtoWS, EventOnClose, nil, payload)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if action != ActionContinue {
		t.Errorf("Action = %v, want Continue (fail-soft)", action)
	}
	want := []string{"bad-drop", "next"}
	if len(saw) != 2 || saw[0] != want[0] || saw[1] != want[1] {
		t.Errorf("saw = %v, want %v", saw, want)
	}
}

func TestFireLifecycle_PluginRuntimeError_FailsSoft(t *testing.T) {
	e := NewEngine(nil)
	var saw []string

	e.Registry().Register(Hook{
		Protocol: ProtoTLS, Event: EventOnHandshake, Phase: PhaseNone,
		PluginName: "exploder",
		Fn: builtinLifecycleHook("explode", func(msg starlark.Value, c *Ctx) (starlark.Value, error) {
			saw = append(saw, "exploder")
			return nil, errors.New("kaboom")
		}),
	})
	e.Registry().Register(Hook{
		Protocol: ProtoTLS, Event: EventOnHandshake, Phase: PhaseNone,
		PluginName: "next",
		Fn: builtinLifecycleHook("next", func(msg starlark.Value, c *Ctx) (starlark.Value, error) {
			saw = append(saw, "next")
			return starlark.None, nil
		}),
	})

	payload := BuildTLSHandshakeDict("server", &envelope.TLSSnapshot{SNI: "example.com"})
	action, err := e.FireLifecycle(context.Background(), ProtoTLS, EventOnHandshake, nil, payload)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if action != ActionContinue {
		t.Errorf("Action = %v, want Continue", action)
	}
	if len(saw) != 2 || saw[0] != "exploder" || saw[1] != "next" {
		t.Errorf("saw = %v; expected exploder then next", saw)
	}
}

func TestFireLifecycle_NilMsgSubstitutesEmptyDict(t *testing.T) {
	e := NewEngine(nil)
	var got starlark.Value

	e.Registry().Register(Hook{
		Protocol: ProtoConnection, Event: EventOnDisconnect, Phase: PhaseNone,
		PluginName: "p",
		Fn: builtinLifecycleHook("p", func(msg starlark.Value, c *Ctx) (starlark.Value, error) {
			got = msg
			return starlark.None, nil
		}),
	})

	if _, err := e.FireLifecycle(context.Background(), ProtoConnection, EventOnDisconnect, nil, nil); err != nil {
		t.Fatalf("err = %v", err)
	}
	if got == nil {
		t.Fatalf("hook did not receive msg")
	}
	d, ok := got.(*starlark.Dict)
	if !ok {
		t.Fatalf("msg is not *starlark.Dict; got %T", got)
	}
	if d.Len() != 0 {
		t.Errorf("msg dict has %d entries; want 0", d.Len())
	}
}

func TestFireLifecycle_CtxFromEnv_ClientAddrPopulated(t *testing.T) {
	e := NewEngine(nil)
	var seen string

	e.Registry().Register(Hook{
		Protocol: ProtoTLS, Event: EventOnHandshake, Phase: PhaseNone,
		PluginName: "p",
		Fn: builtinLifecycleHook("p", func(msg starlark.Value, c *Ctx) (starlark.Value, error) {
			if c == nil {
				return nil, errors.New("nil ctx")
			}
			v, err := c.Attr("client_addr")
			if err != nil {
				return nil, err
			}
			s, ok := v.(starlark.String)
			if !ok {
				return nil, fmt.Errorf("client_addr is %T not String", v)
			}
			seen = string(s)
			return starlark.None, nil
		}),
	})

	addr, _ := net.ResolveTCPAddr("tcp", "10.20.30.40:54321")
	env := &envelope.Envelope{
		Context: envelope.EnvelopeContext{
			ConnID:     "conn-1",
			ClientAddr: addr,
		},
	}
	payload := BuildTLSHandshakeDict("server", &envelope.TLSSnapshot{SNI: "example.com"})
	if _, err := e.FireLifecycle(context.Background(), ProtoTLS, EventOnHandshake, env, payload); err != nil {
		t.Fatalf("err = %v", err)
	}
	if seen != "10.20.30.40" {
		t.Errorf("client_addr = %q, want 10.20.30.40", seen)
	}
}

func TestBuildConnectionConnectDict_Frozen(t *testing.T) {
	d := BuildConnectionConnectDict("c1", "1.2.3.4", "default")
	if err := d.SetKey(starlark.String("conn_id"), starlark.String("evil")); err == nil {
		t.Error("SetKey on frozen dict should fail")
	}
	v, ok, err := d.Get(starlark.String("client_addr"))
	if err != nil || !ok {
		t.Fatalf("Get(client_addr): ok=%v err=%v", ok, err)
	}
	if s := string(v.(starlark.String)); s != "1.2.3.4" {
		t.Errorf("client_addr = %q, want 1.2.3.4", s)
	}
}

func TestBuildTLSHandshakeDict_NilSnapshot(t *testing.T) {
	d := BuildTLSHandshakeDict("client", nil)
	if err := d.SetKey(starlark.String("__probe__"), starlark.None); err == nil {
		t.Error("dict is not frozen (SetKey succeeded)")
	}
	v, _, err := d.Get(starlark.String("side"))
	if err != nil {
		t.Fatalf("Get(side): %v", err)
	}
	if s := string(v.(starlark.String)); s != "client" {
		t.Errorf("side = %q, want client", s)
	}
	v, _, err = d.Get(starlark.String("sni"))
	if err != nil {
		t.Fatalf("Get(sni): %v", err)
	}
	if s := string(v.(starlark.String)); s != "" {
		t.Errorf("sni = %q, want empty", s)
	}
}

func TestBuildWSCloseDict_NilMessage(t *testing.T) {
	d := BuildWSCloseDict(nil)
	if err := d.SetKey(starlark.String("__probe__"), starlark.None); err == nil {
		t.Error("dict is not frozen (SetKey succeeded)")
	}
	v, _, err := d.Get(starlark.String("opcode"))
	if err != nil {
		t.Fatalf("Get(opcode): %v", err)
	}
	n, ok := v.(starlark.Int)
	if !ok {
		t.Fatalf("opcode is not Int: %T", v)
	}
	got, ok := n.Int64()
	if !ok || got != int64(envelope.WSClose) {
		t.Errorf("opcode = %v, want %v", got, envelope.WSClose)
	}
}

func TestBuildGRPCEndDict_TrailersList(t *testing.T) {
	m := &envelope.GRPCEndMessage{
		Status:  0,
		Message: "ok",
		Trailers: []envelope.KeyValue{
			{Name: "x-trace-id", Value: "abc"},
			{Name: "X-DUPE", Value: "first"},
			{Name: "x-dupe", Value: "second"},
		},
	}
	d := BuildGRPCEndDict(m)
	v, _, err := d.Get(starlark.String("trailers"))
	if err != nil {
		t.Fatalf("Get(trailers): %v", err)
	}
	list, ok := v.(*starlark.List)
	if !ok {
		t.Fatalf("trailers is not *starlark.List: %T", v)
	}
	if list.Len() != 3 {
		t.Fatalf("trailers len = %d, want 3", list.Len())
	}
	tup, ok := list.Index(1).(starlark.Tuple)
	if !ok || len(tup) != 2 {
		t.Fatalf("trailers[1] is not 2-tuple: %v", list.Index(1))
	}
	if string(tup[0].(starlark.String)) != "X-DUPE" {
		t.Errorf("trailers[1].name = %q, want X-DUPE (preserved case)", tup[0])
	}
}
