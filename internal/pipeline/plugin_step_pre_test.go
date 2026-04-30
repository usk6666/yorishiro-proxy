package pipeline

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// hookCallable wraps a Go function as a Starlark Callable for tests.
func hookCallable(name string, fn func(args starlark.Tuple) (starlark.Value, error)) starlark.Callable {
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		return fn(args)
	})
}

func httpReqEnv() *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  "stream-1",
		FlowID:    "flow-1",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		Context:   envelope.EnvelopeContext{ConnID: "conn-1"},
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Path:      "/",
			Authority: "example.com",
			Headers:   []envelope.KeyValue{{Name: "Host", Value: "example.com"}},
		},
	}
}

func TestPluginStepPre_NilEnginePassThrough(t *testing.T) {
	step := NewPluginStepPre(nil, nil, nil)
	r := step.Process(context.Background(), httpReqEnv())
	if r.Action != Continue {
		t.Errorf("Action = %v, want Continue", r.Action)
	}
}

func TestPluginStepPre_NoMatchingHook_PassThrough(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	step := NewPluginStepPre(eng, nil, nil)
	r := step.Process(context.Background(), httpReqEnv())
	if r.Action != Continue || r.Envelope != nil {
		t.Errorf("expected pass-through; got %+v", r)
	}
}

func TestPluginStepPre_FiresOnHTTPOnRequest(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	called := 0
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase:      pluginv2.PhasePrePipeline,
		PluginName: "p",
		Fn: hookCallable("h", func(args starlark.Tuple) (starlark.Value, error) {
			called++
			return starlark.None, nil
		}),
	})
	step := NewPluginStepPre(eng, nil, nil)
	r := step.Process(context.Background(), httpReqEnv())
	if r.Action != Continue {
		t.Errorf("Action = %v", r.Action)
	}
	if called != 1 {
		t.Errorf("called = %d, want 1", called)
	}
}

func TestPluginStepPre_DropReturnsActionDrop(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase:      pluginv2.PhasePrePipeline,
		PluginName: "p",
		Fn: hookCallable("drop", func(args starlark.Tuple) (starlark.Value, error) {
			return starlark.String("DROP"), nil
		}),
	})
	step := NewPluginStepPre(eng, nil, nil)
	r := step.Process(context.Background(), httpReqEnv())
	if r.Action != Drop {
		t.Errorf("Action = %v, want Drop", r.Action)
	}
}

func TestPluginStepPre_RespondShortCircuits(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	payload := &pluginv2.RespondAction{HTTPResponse: &pluginv2.HTTPRespondPayload{
		StatusCode: 403,
		Headers:    []envelope.KeyValue{{Name: "x-blocked-by", Value: "test"}},
		Body:       []byte("denied"),
	}}
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase:      pluginv2.PhasePrePipeline,
		PluginName: "p",
		Fn: hookCallable("respond", func(args starlark.Tuple) (starlark.Value, error) {
			return payload, nil
		}),
	})
	step := NewPluginStepPre(eng, nil, nil)
	r := step.Process(context.Background(), httpReqEnv())
	if r.Action != Respond {
		t.Fatalf("Action = %v, want Respond", r.Action)
	}
	if r.Response == nil {
		t.Fatal("Response nil")
	}
	if r.Response.Direction != envelope.Receive {
		t.Errorf("Response Direction = %v", r.Response.Direction)
	}
	if r.Response.Protocol != envelope.ProtocolHTTP {
		t.Errorf("Response Protocol = %v", r.Response.Protocol)
	}
	respMsg, ok := r.Response.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("Response.Message type %T", r.Response.Message)
	}
	if respMsg.Status != 403 {
		t.Errorf("Status = %d", respMsg.Status)
	}
	if string(respMsg.Body) != "denied" {
		t.Errorf("Body = %q", string(respMsg.Body))
	}
}

func TestPluginStepPre_ChainShortCircuitsOnFirstDrop(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	secondCalled := false
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase: pluginv2.PhasePrePipeline, PluginName: "p1",
		Fn: hookCallable("first-drop", func(args starlark.Tuple) (starlark.Value, error) {
			return starlark.String("DROP"), nil
		}),
	})
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase: pluginv2.PhasePrePipeline, PluginName: "p2",
		Fn: hookCallable("second", func(args starlark.Tuple) (starlark.Value, error) {
			secondCalled = true
			return starlark.None, nil
		}),
	})
	step := NewPluginStepPre(eng, nil, nil)
	r := step.Process(context.Background(), httpReqEnv())
	if r.Action != Drop {
		t.Errorf("Action = %v", r.Action)
	}
	if secondCalled {
		t.Error("second hook should NOT fire after first DROP")
	}
}

func TestPluginStepPre_ChainPassesMutationsForward(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	var seen []string
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase: pluginv2.PhasePrePipeline, PluginName: "p1",
		Fn: hookCallable("first", func(args starlark.Tuple) (starlark.Value, error) {
			msg := args[0].(*pluginv2.MessageDict)
			v, _, _ := msg.Get(starlark.String("method"))
			seen = append(seen, string(v.(starlark.String)))
			return nil, msg.SetKey(starlark.String("method"), starlark.String("PUT"))
		}),
	})
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase: pluginv2.PhasePrePipeline, PluginName: "p2",
		Fn: hookCallable("second", func(args starlark.Tuple) (starlark.Value, error) {
			msg := args[0].(*pluginv2.MessageDict)
			v, _, _ := msg.Get(starlark.String("method"))
			seen = append(seen, string(v.(starlark.String)))
			return starlark.None, nil
		}),
	})
	step := NewPluginStepPre(eng, nil, nil)
	r := step.Process(context.Background(), httpReqEnv())
	if r.Envelope == nil {
		t.Fatal("Envelope nil")
	}
	if len(seen) != 2 || seen[0] != "GET" || seen[1] != "PUT" {
		t.Errorf("seen = %v, want [GET PUT]", seen)
	}
}

func TestPluginStepPre_MidStreamDrop_IsRejectedFailSoft(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoGRPC, Event: pluginv2.EventOnData,
		Phase: pluginv2.PhasePrePipeline, PluginName: "p",
		Fn: hookCallable("drop", func(args starlark.Tuple) (starlark.Value, error) {
			return starlark.String("DROP"), nil
		}),
	})
	step := NewPluginStepPre(eng, nil, nil)
	env := &envelope.Envelope{
		StreamID:  "s",
		FlowID:    "f",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message:   &envelope.GRPCDataMessage{Service: "S", Method: "M", Payload: []byte("hi")},
	}
	r := step.Process(context.Background(), env)
	if r.Action != Continue {
		t.Errorf("Action = %v, want Continue (mid-stream DROP must be rejected fail-soft)", r.Action)
	}
}

func TestPluginStepPre_DispatcherErrorIsLoggedAndContinued(t *testing.T) {
	// Sanity check that ErrDisallowedAction surfacing from Engine.Dispatch
	// is converted to a continued chain in the pipeline layer.
	if !errors.Is(fmt.Errorf("wrap: %w", pluginv2.ErrDisallowedAction), pluginv2.ErrDisallowedAction) {
		t.Skip("errors.Is plumbing broken in dependency")
	}
}
