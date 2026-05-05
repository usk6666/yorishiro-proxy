package pipeline

import (
	"context"
	"strings"
	"testing"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

func TestPluginStepPost_NilEnginePassThrough(t *testing.T) {
	step := NewPluginStepPost(nil, nil, nil)
	r := step.Process(context.Background(), httpReqEnv())
	if r.Action != Continue || r.Envelope != nil {
		t.Errorf("expected pass-through; got %+v", r)
	}
}

func TestPluginStepPost_FiresOnPostPhase(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	preCalls, postCalls := 0, 0
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase: pluginv2.PhasePrePipeline, PluginName: "p",
		Fn: hookCallable("pre", func(args starlark.Tuple) (starlark.Value, error) {
			preCalls++
			return starlark.None, nil
		}),
	})
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase: pluginv2.PhasePostPipeline, PluginName: "p",
		Fn: hookCallable("post", func(args starlark.Tuple) (starlark.Value, error) {
			postCalls++
			return starlark.None, nil
		}),
	})

	post := NewPluginStepPost(eng, nil, nil)
	if r := post.Process(context.Background(), httpReqEnv()); r.Action != Continue {
		t.Errorf("Action = %v", r.Action)
	}
	if preCalls != 0 {
		t.Errorf("pre fired in PluginStepPost: %d", preCalls)
	}
	if postCalls != 1 {
		t.Errorf("post fired %d times, want 1", postCalls)
	}
}

func TestPluginStepPost_HeaderMutation_RegeneratesRawViaHTTP1Encoder(t *testing.T) {
	// AC#5: PluginStepPost で Headers mutation → http1.EncodeWireBytes で
	// modified variant の Raw が再生成、RecordStep が記録.

	// http1.EncodeWireBytes requires a parsed envelope context; build one
	// using the production builder so the encoder has what it needs.
	env := http1.BuildSendEnvelope(
		"GET", "https", "example.com", "/", "",
		[]envelope.KeyValue{{Name: "Host", Value: "example.com"}},
		nil,
	)

	reg := NewWireEncoderRegistry()
	reg.Register(envelope.ProtocolHTTP, http1.EncodeWireBytes)

	eng := pluginv2.NewEngine(nil)
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase: pluginv2.PhasePostPipeline, PluginName: "signer",
		Fn: hookCallable("add-hdr", func(args starlark.Tuple) (starlark.Value, error) {
			msg := args[0].(*pluginv2.MessageDict)
			hdrsV, _, _ := msg.Get(starlark.String("headers"))
			hv := hdrsV.(*pluginv2.HeadersValue)
			appendBuiltin, _ := hv.Attr("append")
			thread := &starlark.Thread{Name: "test"}
			_, err := starlark.Call(thread, appendBuiltin,
				starlark.Tuple{starlark.String("X-Signature"), starlark.String("abc123")}, nil)
			return starlark.None, err
		}),
	})

	step := NewPluginStepPost(eng, reg, nil)
	r := step.Process(context.Background(), env)
	if r.Envelope == nil {
		t.Fatal("expected new envelope after mutation")
	}
	if !strings.Contains(string(r.Envelope.Raw), "X-Signature: abc123") {
		t.Errorf("Raw missing regenerated header; got: %q", string(r.Envelope.Raw))
	}
	httpMsg, ok := r.Envelope.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("Message type %T", r.Envelope.Message)
	}
	found := false
	for _, kv := range httpMsg.Headers {
		if kv.Name == "X-Signature" && kv.Value == "abc123" {
			found = true
		}
	}
	if !found {
		t.Errorf("Message.Headers missing X-Signature: %+v", httpMsg.Headers)
	}
}

func TestPluginStepPost_RawInjection_VerbatimWins(t *testing.T) {
	// AC#6: PluginStepPost で msg["raw"] 注入 → verbatim で wire に書き出される
	// (Message 変更は無視 — raw wins per RFC §9.3 D4).
	env := http1.BuildSendEnvelope(
		"GET", "https", "example.com", "/", "",
		[]envelope.KeyValue{{Name: "Host", Value: "example.com"}},
		nil,
	)

	reg := NewWireEncoderRegistry()
	// Encoder is intentionally unrelated bytes — the test asserts that even
	// with an encoder available, raw injection wins (the encoder's output
	// for the new Message would be different from `customRaw`).
	reg.Register(envelope.ProtocolHTTP, http1.EncodeWireBytes)

	customRaw := []byte("CUSTOM RAW SMUGGLED PAYLOAD")
	eng := pluginv2.NewEngine(nil)
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase: pluginv2.PhasePostPipeline, PluginName: "smuggler",
		Fn: hookCallable("inject", func(args starlark.Tuple) (starlark.Value, error) {
			msg := args[0].(*pluginv2.MessageDict)
			// Mutate Message AND raw — RFC §9.3 D4 says raw wins.
			_ = msg.SetKey(starlark.String("method"), starlark.String("DELETE"))
			return starlark.None, msg.SetKey(starlark.String("raw"), starlark.Bytes(customRaw))
		}),
	})

	step := NewPluginStepPost(eng, reg, nil)
	r := step.Process(context.Background(), env)
	if r.Envelope == nil {
		t.Fatal("expected new envelope")
	}
	if string(r.Envelope.Raw) != string(customRaw) {
		t.Errorf("Raw = %q, want verbatim custom bytes", string(r.Envelope.Raw))
	}
}

func TestPluginStepPost_MessageOnly_NoEncoder_PreservesOriginalRaw(t *testing.T) {
	// Q-7: When MessageOnly mutation hits and no encoder is registered,
	// preserve original Raw and pass through (with Debug log; not asserted).
	env := httpReqEnv()
	originalRaw := append([]byte(nil), env.Raw...)

	eng := pluginv2.NewEngine(nil)
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase: pluginv2.PhasePostPipeline, PluginName: "p",
		Fn: hookCallable("mutate", func(args starlark.Tuple) (starlark.Value, error) {
			msg := args[0].(*pluginv2.MessageDict)
			return starlark.None, msg.SetKey(starlark.String("method"), starlark.String("POST"))
		}),
	})

	step := NewPluginStepPost(eng, nil /* no encoders */, nil)
	r := step.Process(context.Background(), env)
	if r.Envelope == nil {
		t.Fatal("expected envelope (Message changed)")
	}
	if string(r.Envelope.Raw) != string(originalRaw) {
		t.Errorf("Raw should be preserved; got %q", string(r.Envelope.Raw))
	}
	httpMsg := r.Envelope.Message.(*envelope.HTTPMessage)
	if httpMsg.Method != "POST" {
		t.Errorf("Message.Method = %q, want POST", httpMsg.Method)
	}
}

func TestPluginStepPost_MessageOnly_EncoderFailsSoft_PreservesRaw(t *testing.T) {
	// UQ-C / Q-6: encoder returns (nil, nil) → keep originalRaw.
	env := httpReqEnv()
	originalRaw := append([]byte(nil), env.Raw...)

	reg := NewWireEncoderRegistry()
	reg.Register(envelope.ProtocolHTTP, func(*envelope.Envelope) ([]byte, error) {
		return nil, nil // fail-soft
	})

	eng := pluginv2.NewEngine(nil)
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase: pluginv2.PhasePostPipeline, PluginName: "p",
		Fn: hookCallable("mutate", func(args starlark.Tuple) (starlark.Value, error) {
			msg := args[0].(*pluginv2.MessageDict)
			return starlark.None, msg.SetKey(starlark.String("method"), starlark.String("POST"))
		}),
	})

	step := NewPluginStepPost(eng, reg, nil)
	r := step.Process(context.Background(), env)
	if r.Envelope == nil {
		t.Fatal("expected envelope")
	}
	if string(r.Envelope.Raw) != string(originalRaw) {
		t.Errorf("fail-soft must preserve original Raw; got %q", string(r.Envelope.Raw))
	}
}

func TestPluginStepPost_WSMessage_FiresOnMessage(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	called := 0
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoWS, Event: pluginv2.EventOnMessage,
		Phase: pluginv2.PhasePostPipeline, PluginName: "p",
		Fn: hookCallable("ws", func(args starlark.Tuple) (starlark.Value, error) {
			called++
			return starlark.None, nil
		}),
	})
	env := &envelope.Envelope{
		StreamID:  "s",
		FlowID:    "f",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Message:   &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Payload: []byte("hi")},
	}
	step := NewPluginStepPost(eng, nil, nil)
	step.Process(context.Background(), env)
	if called != 1 {
		t.Errorf("called = %d", called)
	}
}

func TestPluginStepPost_GRPCData_FiresOnData(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	called := 0
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoGRPC, Event: pluginv2.EventOnData,
		Phase: pluginv2.PhasePostPipeline, PluginName: "p",
		Fn: hookCallable("grpc", func(args starlark.Tuple) (starlark.Value, error) {
			called++
			return starlark.None, nil
		}),
	})
	env := &envelope.Envelope{
		StreamID:  "s",
		FlowID:    "f",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message:   &envelope.GRPCDataMessage{Service: "S", Method: "M", Payload: []byte("p")},
	}
	step := NewPluginStepPost(eng, nil, nil)
	step.Process(context.Background(), env)
	if called != 1 {
		t.Errorf("called = %d", called)
	}
}

func TestPluginStepPost_SSE_FiresOnEvent(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	called := 0
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoSSE, Event: pluginv2.EventOnEvent,
		Phase: pluginv2.PhasePostPipeline, PluginName: "p",
		Fn: hookCallable("sse", func(args starlark.Tuple) (starlark.Value, error) {
			called++
			return starlark.None, nil
		}),
	})
	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolSSE,
		Message:   &envelope.SSEMessage{Data: "x"},
	}
	step := NewPluginStepPost(eng, nil, nil)
	step.Process(context.Background(), env)
	if called != 1 {
		t.Errorf("called = %d", called)
	}
}

func TestPluginStepPost_Raw_FiresOnChunk(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	called := 0
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoRaw, Event: pluginv2.EventOnChunk,
		Phase: pluginv2.PhasePostPipeline, PluginName: "p",
		Fn: hookCallable("raw", func(args starlark.Tuple) (starlark.Value, error) {
			called++
			return starlark.None, nil
		}),
	})
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolRaw,
		Message:   &envelope.RawMessage{Bytes: []byte("x")},
	}
	step := NewPluginStepPost(eng, nil, nil)
	step.Process(context.Background(), env)
	if called != 1 {
		t.Errorf("called = %d", called)
	}
}
