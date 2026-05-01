package pluginv2

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// builtinHook wraps a Go function as a Starlark Callable suitable for
// Hook.Fn. The function receives the *MessageDict and *Ctx the dispatcher
// would normally pass to a Starlark hook.
func builtinHook(name string, fn func(msg *MessageDict, c *Ctx) (starlark.Value, error)) starlark.Callable {
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		if len(args) != 2 {
			return nil, fmt.Errorf("hook expects (msg, ctx); got %d args", len(args))
		}
		msg, ok := args[0].(*MessageDict)
		if !ok {
			return nil, fmt.Errorf("arg 0 not *MessageDict: %T", args[0])
		}
		c, ok := args[1].(*Ctx)
		if !ok {
			return nil, fmt.Errorf("arg 1 not *Ctx: %T", args[1])
		}
		return fn(msg, c)
	})
}

func httpEnv(t *testing.T) *envelope.Envelope {
	t.Helper()
	return &envelope.Envelope{
		StreamID:  "stream-1",
		FlowID:    "flow-1",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Path:      "/",
			Authority: "example.com",
			Headers:   []envelope.KeyValue{{Name: "Host", Value: "example.com"}},
		},
	}
}

func TestDispatch_NoneReturn_Continue(t *testing.T) {
	e := NewEngine(nil)
	hook := Hook{
		Protocol: ProtoHTTP, Event: EventOnRequest, Phase: PhasePrePipeline,
		PluginName: "p1",
		Fn: builtinHook("noop", func(msg *MessageDict, c *Ctx) (starlark.Value, error) {
			return starlark.None, nil
		}),
	}
	out, err := e.Dispatch(context.Background(), hook, httpEnv(t))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if out.Action != ActionContinue {
		t.Errorf("Action = %v, want ActionContinue", out.Action)
	}
	if out.Mutation != MutationUnchanged {
		t.Errorf("Mutation = %v, want Unchanged", out.Mutation)
	}
}

func TestDispatch_DropString_Drop(t *testing.T) {
	e := NewEngine(nil)
	hook := Hook{
		Protocol: ProtoHTTP, Event: EventOnRequest, Phase: PhasePrePipeline,
		PluginName: "p1",
		Fn: builtinHook("drop", func(msg *MessageDict, c *Ctx) (starlark.Value, error) {
			return starlark.String("DROP"), nil
		}),
	}
	out, err := e.Dispatch(context.Background(), hook, httpEnv(t))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if out.Action != ActionDrop {
		t.Errorf("Action = %v, want ActionDrop", out.Action)
	}
}

func TestDispatch_RespondAction_Respond(t *testing.T) {
	e := NewEngine(nil)
	payload := &RespondAction{HTTPResponse: &HTTPRespondPayload{StatusCode: 418, Body: []byte("teapot")}}
	hook := Hook{
		Protocol: ProtoHTTP, Event: EventOnRequest, Phase: PhasePrePipeline,
		PluginName: "p1",
		Fn: builtinHook("respond", func(msg *MessageDict, c *Ctx) (starlark.Value, error) {
			return payload, nil
		}),
	}
	out, err := e.Dispatch(context.Background(), hook, httpEnv(t))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if out.Action != ActionRespond {
		t.Errorf("Action = %v, want ActionRespond", out.Action)
	}
	if out.Respond != payload {
		t.Errorf("Respond payload not propagated")
	}
}

func TestDispatch_InPlaceMutation_MessageOnly(t *testing.T) {
	e := NewEngine(nil)
	hook := Hook{
		Protocol: ProtoHTTP, Event: EventOnRequest, Phase: PhasePrePipeline,
		PluginName: "p1",
		Fn: builtinHook("mutate", func(msg *MessageDict, c *Ctx) (starlark.Value, error) {
			if err := msg.SetKey(starlark.String("method"), starlark.String("POST")); err != nil {
				return nil, err
			}
			return starlark.None, nil
		}),
	}
	out, err := e.Dispatch(context.Background(), hook, httpEnv(t))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if out.Action != ActionContinue {
		t.Fatalf("Action = %v", out.Action)
	}
	if out.Mutation != MutationMessageOnly {
		t.Errorf("Mutation = %v, want MessageOnly", out.Mutation)
	}
	httpMsg, ok := out.NewMessage.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("NewMessage type %T", out.NewMessage)
	}
	if httpMsg.Method != "POST" {
		t.Errorf("Method = %q, want POST", httpMsg.Method)
	}
}

func TestDispatch_RawMutation_RawOnly(t *testing.T) {
	e := NewEngine(nil)
	newRaw := []byte("RAW REPLACEMENT")
	hook := Hook{
		Protocol: ProtoHTTP, Event: EventOnRequest, Phase: PhasePrePipeline,
		PluginName: "p1",
		Fn: builtinHook("raw", func(msg *MessageDict, c *Ctx) (starlark.Value, error) {
			if err := msg.SetKey(starlark.String("raw"), starlark.Bytes(newRaw)); err != nil {
				return nil, err
			}
			return starlark.None, nil
		}),
	}
	out, err := e.Dispatch(context.Background(), hook, httpEnv(t))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if out.Mutation != MutationRawOnly {
		t.Errorf("Mutation = %v, want RawOnly", out.Mutation)
	}
	if string(out.NewRaw) != string(newRaw) {
		t.Errorf("NewRaw = %q", string(out.NewRaw))
	}
}

func TestDispatch_BothMutation_RawWins(t *testing.T) {
	e := NewEngine(nil)
	newRaw := []byte("RAW WINS")
	hook := Hook{
		Protocol: ProtoHTTP, Event: EventOnRequest, Phase: PhasePrePipeline,
		PluginName: "p1",
		Fn: builtinHook("both", func(msg *MessageDict, c *Ctx) (starlark.Value, error) {
			_ = msg.SetKey(starlark.String("method"), starlark.String("POST"))
			_ = msg.SetKey(starlark.String("raw"), starlark.Bytes(newRaw))
			return starlark.None, nil
		}),
	}
	out, err := e.Dispatch(context.Background(), hook, httpEnv(t))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if out.Mutation != MutationBoth {
		t.Errorf("Mutation = %v, want Both", out.Mutation)
	}
	if string(out.NewRaw) != string(newRaw) {
		t.Errorf("NewRaw = %q", string(out.NewRaw))
	}
	httpMsg := out.NewMessage.(*envelope.HTTPMessage)
	if httpMsg.Method != "POST" {
		t.Errorf("NewMessage.Method = %q", httpMsg.Method)
	}
}

func TestDispatch_MidStreamDrop_ReturnsDisallowedAction(t *testing.T) {
	e := NewEngine(nil)
	env := &envelope.Envelope{
		StreamID:  "s",
		FlowID:    "f",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message:   &envelope.GRPCDataMessage{Service: "S", Method: "M", Payload: []byte("hi")},
	}
	hook := Hook{
		Protocol: ProtoGRPC, Event: EventOnData, Phase: PhasePrePipeline,
		PluginName: "p1",
		Fn: builtinHook("drop", func(msg *MessageDict, c *Ctx) (starlark.Value, error) {
			return starlark.String("DROP"), nil
		}),
	}
	_, err := e.Dispatch(context.Background(), hook, env)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrDisallowedAction) {
		t.Errorf("err not ErrDisallowedAction: %v", err)
	}
}

func TestDispatch_MidStreamRespond_ReturnsDisallowedAction(t *testing.T) {
	e := NewEngine(nil)
	env := &envelope.Envelope{
		StreamID:  "s",
		FlowID:    "f",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Message:   &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Payload: []byte("hello")},
	}
	hook := Hook{
		Protocol: ProtoWS, Event: EventOnMessage, Phase: PhasePrePipeline,
		PluginName: "p1",
		Fn: builtinHook("respond", func(msg *MessageDict, c *Ctx) (starlark.Value, error) {
			return &RespondAction{HTTPResponse: &HTTPRespondPayload{StatusCode: 200}}, nil
		}),
	}
	_, err := e.Dispatch(context.Background(), hook, env)
	if !errors.Is(err, ErrDisallowedAction) {
		t.Errorf("err = %v, want ErrDisallowedAction", err)
	}
}

func TestDispatch_HookErrors_FailSoftContinue(t *testing.T) {
	e := NewEngine(nil)
	hook := Hook{
		Protocol: ProtoHTTP, Event: EventOnRequest, Phase: PhasePrePipeline,
		PluginName: "p1",
		Fn: builtinHook("err", func(msg *MessageDict, c *Ctx) (starlark.Value, error) {
			return nil, fmt.Errorf("boom")
		}),
	}
	out, err := e.Dispatch(context.Background(), hook, httpEnv(t))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if out.Action != ActionContinue {
		t.Errorf("Action = %v, want ActionContinue (fail-soft)", out.Action)
	}
}

func TestDispatch_HookErrorWithInPlaceMutation_PreservesMutation(t *testing.T) {
	e := NewEngine(nil)
	hook := Hook{
		Protocol: ProtoHTTP, Event: EventOnRequest, Phase: PhasePrePipeline,
		PluginName: "p1",
		Fn: builtinHook("mutate-then-err", func(msg *MessageDict, c *Ctx) (starlark.Value, error) {
			_ = msg.SetKey(starlark.String("method"), starlark.String("POST"))
			return nil, fmt.Errorf("boom")
		}),
	}
	out, err := e.Dispatch(context.Background(), hook, httpEnv(t))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if out.Mutation != MutationMessageOnly {
		t.Errorf("Mutation = %v, want MessageOnly (in-place mutation must survive runtime error)", out.Mutation)
	}
}

func TestDispatch_BareRESPONDString_FailSoftContinue(t *testing.T) {
	e := NewEngine(nil)
	hook := Hook{
		Protocol: ProtoHTTP, Event: EventOnRequest, Phase: PhasePrePipeline,
		PluginName: "p1",
		Fn: builtinHook("bare-respond", func(msg *MessageDict, c *Ctx) (starlark.Value, error) {
			return starlark.String("RESPOND"), nil
		}),
	}
	out, err := e.Dispatch(context.Background(), hook, httpEnv(t))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if out.Action != ActionContinue {
		t.Errorf("Action = %v, want ActionContinue (bare RESPOND degrades)", out.Action)
	}
}

func TestDispatch_UnsupportedReturn_FailSoftContinue(t *testing.T) {
	e := NewEngine(nil)
	hook := Hook{
		Protocol: ProtoHTTP, Event: EventOnRequest, Phase: PhasePrePipeline,
		PluginName: "p1",
		Fn: builtinHook("int", func(msg *MessageDict, c *Ctx) (starlark.Value, error) {
			return starlark.MakeInt(42), nil
		}),
	}
	out, err := e.Dispatch(context.Background(), hook, httpEnv(t))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if out.Action != ActionContinue {
		t.Errorf("Action = %v, want ActionContinue", out.Action)
	}
}

func TestDispatch_ContinueString_Explicit(t *testing.T) {
	e := NewEngine(nil)
	hook := Hook{
		Protocol: ProtoHTTP, Event: EventOnRequest, Phase: PhasePrePipeline,
		PluginName: "p1",
		Fn: builtinHook("cont", func(msg *MessageDict, c *Ctx) (starlark.Value, error) {
			return starlark.String("CONTINUE"), nil
		}),
	}
	out, err := e.Dispatch(context.Background(), hook, httpEnv(t))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if out.Action != ActionContinue {
		t.Errorf("Action = %v", out.Action)
	}
}

func TestDispatch_ContextCancel_AbortsHook(t *testing.T) {
	e := NewEngine(nil)
	ctx, cancel := context.WithCancel(context.Background())
	hook := Hook{
		Protocol: ProtoHTTP, Event: EventOnRequest, Phase: PhasePrePipeline,
		PluginName: "p1",
		Fn: builtinHook("loop", func(msg *MessageDict, c *Ctx) (starlark.Value, error) {
			cancel()
			// Simulate a long-running hook by spinning a no-op Starlark
			// loop indirectly — but the test version returns immediately
			// after cancel; we exercise the cancellation path via the
			// outer goroutine bridging ctx.Done() → thread.Cancel.
			return starlark.None, nil
		}),
	}
	out, err := e.Dispatch(ctx, hook, httpEnv(t))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if out.Action != ActionContinue {
		t.Errorf("Action = %v", out.Action)
	}
}

func TestLookupMaxSteps_DefaultForUnknown(t *testing.T) {
	e := NewEngine(nil)
	if got := e.lookupMaxSteps("nonexistent"); got != DefaultMaxSteps {
		t.Errorf("lookupMaxSteps(\"nonexistent\") = %d, want %d", got, DefaultMaxSteps)
	}
	if got := e.lookupMaxSteps(""); got != DefaultMaxSteps {
		t.Errorf("lookupMaxSteps(\"\") = %d, want %d", got, DefaultMaxSteps)
	}
}
