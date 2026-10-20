package pipeline

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	grpclayer "github.com/usk6666/yorishiro-proxy/internal/layer/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/layer/httpaggregator"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// RFC-001 §9.3 D4 h2 policy: a plugin msg["raw"] on an envelope whose
// destination Layer writes a header block (h2 HTTPMessage, gRPC Start /
// End, gRPC-Web Start) cannot be written verbatim. The Pipeline refuses it
// before RecordStep so the recorded modified variant matches the wire:
// RawOnly → Unchanged, Both → MessageOnly.

// h2PolicyRegistry mirrors proxybuild's defaultHTTP2WireEncoderRegistry
// for the HTTP slot.
func h2PolicyRegistry() *WireEncoderRegistry {
	r := NewWireEncoderRegistry()
	r.Register(envelope.ProtocolHTTP, httpaggregator.EncodeWireBytes)
	r.RegisterRawWinsPolicy(envelope.ProtocolHTTP, httpaggregator.RawWinsSupported)
	return r
}

func captureLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

func h2ReqEnv() *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  "stream-h2",
		FlowID:    "flow-h2",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("observed-hpack-fragment"),
		Context:   envelope.EnvelopeContext{ConnID: "conn-h2"},
		Message: &envelope.HTTPMessage{
			Method: "GET", Scheme: "https", Authority: "example.com", Path: "/",
			Headers: []envelope.KeyValue{{Name: "x-marker", Value: "orig"}},
		},
	}
}

// rawAndHeaderHook writes msg["raw"] and, when addHeader, also appends a
// header (a MutationBoth outcome).
func rawAndHeaderHook(proto, event string, raw []byte, addHeader bool) pluginv2.Hook {
	return pluginv2.Hook{
		Protocol: proto, Event: event,
		Phase: pluginv2.PhasePostPipeline, PluginName: "h2raw",
		Fn: hookCallable("inject", func(args starlark.Tuple) (starlark.Value, error) {
			msg := args[0].(*pluginv2.MessageDict)
			if addHeader {
				v, _, err := msg.Get(starlark.String("headers"))
				if err != nil {
					return nil, err
				}
				appendFn, err := v.(starlark.HasAttrs).Attr("append")
				if err != nil {
					return nil, err
				}
				if _, err := starlark.Call(&starlark.Thread{}, appendFn, starlark.Tuple{starlark.String("x-plugin"), starlark.String("1")}, nil); err != nil {
					return nil, err
				}
			}
			return starlark.None, msg.SetKey(starlark.String("raw"), starlark.Bytes(raw))
		}),
	}
}

// TestPluginRawWinsPolicy_H2_RawOnlyRefused (Test Plan T7).
func TestPluginRawWinsPolicy_H2_RawOnlyRefused(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	eng.Registry().Register(rawAndHeaderHook(pluginv2.ProtoHTTP, pluginv2.EventOnRequest, []byte("PLUGIN-RAW"), false))
	logger, logs := captureLogger()

	in := h2ReqEnv()
	r := NewPluginStepPost(eng, h2PolicyRegistry(), logger).Process(context.Background(), in)
	out := in
	if r.Envelope != nil {
		out = r.Envelope
	}
	if out.RawAuthoritative {
		t.Error("RawAuthoritative = true on an h2 HTTPMessage; the h2 Layer cannot write msg[\"raw\"] verbatim")
	}
	if !bytes.Equal(out.Raw, []byte("observed-hpack-fragment")) {
		t.Errorf("Raw = %q, want the observed bytes untouched", out.Raw)
	}
	got := logs.String()
	for _, want := range []string{"level=WARN", "plugin=h2raw", "hook=http.on_request"} {
		if !strings.Contains(got, want) {
			t.Errorf("refusal log missing %q; logs:\n%s", want, got)
		}
	}
}

// TestPluginRawWinsPolicy_H2_RepeatRefusalLogsDebug: the refusal Warn
// fires once per (plugin, protocol.event, phase); a second identical
// refusal on the same Step is logged at Debug, not Warn.
func TestPluginRawWinsPolicy_H2_RepeatRefusalLogsDebug(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	eng.Registry().Register(rawAndHeaderHook(pluginv2.ProtoHTTP, pluginv2.EventOnRequest, []byte("PLUGIN-RAW"), false))
	logger, logs := captureLogger()
	step := NewPluginStepPost(eng, h2PolicyRegistry(), logger)

	step.Process(context.Background(), h2ReqEnv())
	first := logs.String()
	if n := strings.Count(first, "level=WARN"); n != 1 {
		t.Fatalf("first refusal: WARN lines = %d, want 1; logs:\n%s", n, first)
	}
	logs.Reset()

	step.Process(context.Background(), h2ReqEnv())
	second := logs.String()
	if strings.Contains(second, "level=WARN") {
		t.Errorf("second identical refusal logged at WARN; want DEBUG. logs:\n%s", second)
	}
	for _, want := range []string{"level=DEBUG", "msg[\\\"raw\\\"] cannot be written verbatim", "plugin=h2raw", "hook=http.on_request"} {
		if !strings.Contains(second, want) {
			t.Errorf("second refusal log missing %q; logs:\n%s", want, second)
		}
	}
}

// TestPluginRawWinsPolicy_H2_BothBecomesMessageOnly (Test Plan T7).
func TestPluginRawWinsPolicy_H2_BothBecomesMessageOnly(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	eng.Registry().Register(rawAndHeaderHook(pluginv2.ProtoHTTP, pluginv2.EventOnRequest, []byte("PLUGIN-RAW"), true))
	logger, _ := captureLogger()

	r := NewPluginStepPost(eng, h2PolicyRegistry(), logger).Process(context.Background(), h2ReqEnv())
	if r.Envelope == nil {
		t.Fatal("Both mutation produced no envelope; the Message edit was lost")
	}
	out := r.Envelope
	if out.RawAuthoritative {
		t.Error("RawAuthoritative = true after a refused Both mutation")
	}
	if bytes.Equal(out.Raw, []byte("PLUGIN-RAW")) {
		t.Error("Raw = plugin bytes; want the encoder output for the mutated Message")
	}
	msg := out.Message.(*envelope.HTTPMessage)
	found := false
	for _, kv := range msg.Headers {
		if kv.Name == "x-plugin" && kv.Value == "1" {
			found = true
		}
	}
	if !found {
		t.Errorf("Message headers = %v, want x-plugin: 1 applied", msg.Headers)
	}
}

// TestPluginRawWinsPolicy_H1RegistryStillHonoursRaw (Test Plan T8):
// the h1 route registers no policy, so RawOnly still marks the envelope.
func TestPluginRawWinsPolicy_H1RegistryStillHonoursRaw(t *testing.T) {
	reg := NewWireEncoderRegistry()
	reg.Register(envelope.ProtocolHTTP, http1.EncodeWireBytes)

	eng := pluginv2.NewEngine(nil)
	eng.Registry().Register(rawAndHeaderHook(pluginv2.ProtoHTTP, pluginv2.EventOnRequest, []byte("PLUGIN-RAW"), false))
	r := NewPluginStepPost(eng, reg, nil).Process(context.Background(), httpReqEnv())
	if r.Envelope == nil || !r.Envelope.RawWins() || !bytes.Equal(r.Envelope.Raw, []byte("PLUGIN-RAW")) {
		t.Fatalf("h1 RawOnly not honoured: %+v", r.Envelope)
	}

	// Untouched envelope → Result{} (same pointer downstream).
	eng2 := pluginv2.NewEngine(nil)
	eng2.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest, Phase: pluginv2.PhasePostPipeline, PluginName: "noop",
		Fn: hookCallable("noop", func(starlark.Tuple) (starlark.Value, error) { return starlark.None, nil }),
	})
	if r := NewPluginStepPost(eng2, reg, nil).Process(context.Background(), httpReqEnv()); r.Envelope != nil {
		t.Errorf("untouched envelope produced a new envelope: %+v", r.Envelope)
	}
}

func grpcEnv(proto envelope.Protocol, msg envelope.Message) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID: "s-grpc", FlowID: "f-grpc", Direction: envelope.Send,
		Protocol: proto, Raw: []byte("observed"), Message: msg,
		Context: envelope.EnvelopeContext{ConnID: "c-grpc"},
	}
}

// sharedPolicyRegistry mirrors proxybuild's defaultSharedEncoders for
// the gRPC / gRPC-Web slots.
func sharedPolicyRegistry() *WireEncoderRegistry {
	r := NewWireEncoderRegistry()
	r.Register(envelope.ProtocolGRPC, grpclayer.EncodeWireBytes)
	r.RegisterRawWinsPolicy(envelope.ProtocolGRPC, grpclayer.RawWinsSupported)
	r.Register(envelope.ProtocolGRPCWeb, grpcweb.EncodeWireBytes)
	r.RegisterRawWinsPolicy(envelope.ProtocolGRPCWeb, grpcweb.RawWinsSupported)
	return r
}

// TestPluginRawWinsPolicy_GRPC (Test Plan T9, dispatcher half).
func TestPluginRawWinsPolicy_GRPC(t *testing.T) {
	cases := []struct {
		name      string
		proto     envelope.Protocol
		pluginPro string
		event     string
		msg       envelope.Message
		wantWins  bool
	}{
		{"grpc start refused", envelope.ProtocolGRPC, pluginv2.ProtoGRPC, pluginv2.EventOnStart, &envelope.GRPCStartMessage{Service: "s", Method: "m"}, false},
		{"grpc data honoured", envelope.ProtocolGRPC, pluginv2.ProtoGRPC, pluginv2.EventOnData, &envelope.GRPCDataMessage{Payload: []byte("p")}, true},
		{"grpc-web start refused", envelope.ProtocolGRPCWeb, pluginv2.ProtoGRPCWeb, pluginv2.EventOnStart, &envelope.GRPCStartMessage{Service: "s", Method: "m"}, false},
		{"grpc-web data honoured", envelope.ProtocolGRPCWeb, pluginv2.ProtoGRPCWeb, pluginv2.EventOnData, &envelope.GRPCDataMessage{Payload: []byte("p")}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng := pluginv2.NewEngine(nil)
			eng.Registry().Register(rawAndHeaderHook(tc.pluginPro, tc.event, []byte("PLUGIN-RAW"), false))
			// Pre phase hook too, so PluginStepPre is exercised.
			h := rawAndHeaderHook(tc.pluginPro, tc.event, []byte("PLUGIN-RAW"), false)
			h.Phase = pluginv2.PhasePrePipeline
			eng.Registry().Register(h)
			logger, _ := captureLogger()

			out, _, _ := New(NewPluginStepPre(eng, sharedPolicyRegistry(), logger), NewPluginStepPost(eng, sharedPolicyRegistry(), logger)).
				Run(context.Background(), grpcEnv(tc.proto, tc.msg))
			if got := out.RawWins(); got != tc.wantWins {
				t.Errorf("RawWins() = %v, want %v (Raw=%q)", got, tc.wantWins, out.Raw)
			}
			if !tc.wantWins && !bytes.Equal(out.Raw, []byte("observed")) {
				t.Errorf("refused envelope Raw = %q, want observed bytes", out.Raw)
			}
		})
	}
}

// TestWireEncoderRegistry_RawWinsPolicy (Test Plan T10, registry half).
func TestWireEncoderRegistry_RawWinsPolicy(t *testing.T) {
	var nilReg *WireEncoderRegistry
	if !nilReg.RawWinsSupported(h2ReqEnv()) {
		t.Error("nil registry must default to supported")
	}
	r := NewWireEncoderRegistry()
	if !r.RawWinsSupported(h2ReqEnv()) {
		t.Error("unregistered protocol must default to supported")
	}
	r.RegisterRawWinsPolicy(envelope.ProtocolHTTP, func(*envelope.Envelope) bool { return false })
	if r.RawWinsSupported(h2ReqEnv()) {
		t.Error("registered refusing policy ignored")
	}
	if !r.RawWinsSupported(grpcEnv(envelope.ProtocolGRPC, &envelope.GRPCStartMessage{})) {
		t.Error("policy for http leaked to grpc")
	}
	r.RegisterRawWinsPolicy(envelope.ProtocolHTTP, nil)
	if !r.RawWinsSupported(h2ReqEnv()) {
		t.Error("nil policy must remove the registration")
	}
}
