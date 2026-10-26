package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
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

// TestPluginStepPre_DispatcherErrorIsLoggedAndContinued drives the real
// PluginStepPre with two hooks on (grpc, on_data, pre_pipeline): the first
// returns "DROP", which Engine.Dispatch rejects with ErrDisallowedAction
// because grpc on_data is mid-stream. The dispatcher must log that error at
// Warn and continue the chain — the second hook still runs and the step
// returns Continue.
func TestPluginStepPre_DispatcherErrorIsLoggedAndContinued(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoGRPC, Event: pluginv2.EventOnData,
		Phase: pluginv2.PhasePrePipeline, PluginName: "dropper",
		Fn: hookCallable("drop", func(args starlark.Tuple) (starlark.Value, error) {
			return starlark.String("DROP"), nil
		}),
	})
	secondCalls := 0
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoGRPC, Event: pluginv2.EventOnData,
		Phase: pluginv2.PhasePrePipeline, PluginName: "counter",
		Fn: hookCallable("count", func(args starlark.Tuple) (starlark.Value, error) {
			secondCalls++
			return starlark.None, nil
		}),
	})

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	step := NewPluginStepPre(eng, nil, logger)
	env := &envelope.Envelope{
		StreamID:  "s",
		FlowID:    "f",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message:   &envelope.GRPCDataMessage{Service: "S", Method: "M", Payload: []byte("hi")},
	}
	r := step.Process(context.Background(), env)

	if r.Action != Continue {
		t.Errorf("Action = %v, want Continue", r.Action)
	}
	if secondCalls != 1 {
		t.Errorf("second hook called %d times, want 1 (chain must continue past the rejected outcome)", secondCalls)
	}

	var found bool
	for _, line := range bytes.Split(bytes.TrimSpace(logBuf.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("unmarshal log line %q: %v", line, err)
		}
		if rec["msg"] != "plugin: hook outcome rejected; treating as continue" {
			continue
		}
		found = true
		if rec["level"] != "WARN" {
			t.Errorf("log level = %v, want WARN", rec["level"])
		}
		if rec["plugin"] != "dropper" {
			t.Errorf("log plugin = %v, want dropper", rec["plugin"])
		}
		errStr, _ := rec["error"].(string)
		if !strings.Contains(errStr, "disallowed") {
			t.Errorf("log error = %q, want it to contain %q", errStr, "disallowed")
		}
	}
	if !found {
		t.Errorf("no 'hook outcome rejected' Warn log; got logs:\n%s", logBuf.String())
	}
}

// TestPluginStepPre_RespondShapeMismatchIsLoggedAndContinued drives the real
// PluginStepPre with two hooks on (grpc-web, on_start, pre_pipeline): the
// first returns an HTTP-shaped action.RESPOND, which no gRPC-Web Channel can
// render, so Engine.Dispatch refuses it. The dispatcher must log that at
// Warn (naming the plugin and pointing at action.RESPOND_GRPC), the second
// hook must still run and its metadata edit must survive, and the step must
// return Continue rather than Respond.
func TestPluginStepPre_RespondShapeMismatchIsLoggedAndContinued(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoGRPCWeb, Event: pluginv2.EventOnStart,
		Phase: pluginv2.PhasePrePipeline, PluginName: "http-responder",
		Fn: hookCallable("respond", func(args starlark.Tuple) (starlark.Value, error) {
			return &pluginv2.RespondAction{HTTPResponse: &pluginv2.HTTPRespondPayload{
				StatusCode: 403,
				Headers:    []envelope.KeyValue{{Name: "Content-Type", Value: "text/plain"}},
				Body:       []byte("denied"),
			}}, nil
		}),
	})
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoGRPCWeb, Event: pluginv2.EventOnStart,
		Phase: pluginv2.PhasePrePipeline, PluginName: "tagger",
		Fn: hookCallable("tag", func(args starlark.Tuple) (starlark.Value, error) {
			msg, ok := args[0].(*pluginv2.MessageDict)
			if !ok {
				return nil, fmt.Errorf("arg 0 not *MessageDict: %T", args[0])
			}
			md := pluginv2.NewHeadersValue([]envelope.KeyValue{{Name: "x-tagged", Value: "yes"}})
			if err := msg.SetKey(starlark.String("metadata"), md); err != nil {
				return nil, err
			}
			return starlark.None, nil
		}),
	})

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	step := NewPluginStepPre(eng, nil, logger)
	env := &envelope.Envelope{
		StreamID:  "s",
		FlowID:    "f",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPCWeb,
		Message:   &envelope.GRPCStartMessage{Service: "pkg.Echo", Method: "Say"},
	}
	r := step.Process(context.Background(), env)

	if r.Action != Continue {
		t.Fatalf("Action = %v (Response %+v), want Continue (mismatched RESPOND must be refused)", r.Action, r.Response)
	}
	if r.Envelope == nil {
		t.Fatal("Envelope nil, want the tagger hook's mutated envelope")
	}
	start, ok := r.Envelope.Message.(*envelope.GRPCStartMessage)
	if !ok {
		t.Fatalf("Message type %T, want *GRPCStartMessage", r.Envelope.Message)
	}
	var tagged bool
	for _, kv := range start.Metadata {
		if kv.Name == "x-tagged" && kv.Value == "yes" {
			tagged = true
		}
	}
	if !tagged {
		t.Errorf("Metadata = %v, want the second hook's x-tagged: yes", start.Metadata)
	}

	var found bool
	for _, line := range bytes.Split(bytes.TrimSpace(logBuf.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			t.Fatalf("unmarshal log line %q: %v", line, err)
		}
		if rec["msg"] != "plugin: hook outcome rejected; treating as continue" {
			continue
		}
		found = true
		if rec["level"] != "WARN" {
			t.Errorf("log level = %v, want WARN", rec["level"])
		}
		if rec["plugin"] != "http-responder" {
			t.Errorf("log plugin = %v, want http-responder", rec["plugin"])
		}
		errStr, _ := rec["error"].(string)
		if !strings.Contains(errStr, "action.RESPOND_GRPC") {
			t.Errorf("log error = %q, want it to point at action.RESPOND_GRPC", errStr)
		}
	}
	if !found {
		t.Errorf("no 'hook outcome rejected' Warn log; got logs:\n%s", logBuf.String())
	}
}
