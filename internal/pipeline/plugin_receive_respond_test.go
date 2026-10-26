package pipeline

import (
	"bytes"
	"context"
	"testing"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

const (
	upstreamRespHead = "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n"
	upstreamRespBody = "upstream-body-spills"
)

// respondHook returns a hook that answers every envelope with
// action.RESPOND(418, "plugin").
func respondHook(protocol, event string, phase pluginv2.Phase) pluginv2.Hook {
	return pluginv2.Hook{
		Protocol: protocol, Event: event, Phase: phase, PluginName: "responder",
		Fn: hookCallable("respond", func(starlark.Tuple) (starlark.Value, error) {
			return &pluginv2.RespondAction{HTTPResponse: &pluginv2.HTTPRespondPayload{
				StatusCode: 418,
				Headers:    []envelope.KeyValue{{Name: "Content-Type", Value: "text/plain"}},
				Body:       []byte("plugin"),
			}}, nil
		}),
	}
}

// opaqueMarker stands in for a Layer's Opaque state (h1 *opaqueHTTP1).
type opaqueMarker struct{}

// spilledH1Response is the shape the HTTP/1.x upstream Layer hands the
// session for an over-threshold response: Raw is the header section and
// HTTPMessage.BodyBuffer the file-backed decoded body (refCount=1), with
// the Layer's Opaque attached.
func spilledH1Response(t *testing.T, dir string) *envelope.Envelope {
	t.Helper()
	return &envelope.Envelope{
		StreamID:  "stream-resp",
		FlowID:    "flow-resp",
		Sequence:  1,
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte(upstreamRespHead),
		Context:   envelope.EnvelopeContext{ConnID: "conn-resp", TargetHost: "example.com:80"},
		Opaque:    &opaqueMarker{},
		Message: &envelope.HTTPMessage{
			Status:       200,
			StatusReason: "OK",
			Headers:      []envelope.KeyValue{{Name: "Content-Length", Value: "20"}},
			BodyBuffer:   newSpillFile(t, dir, upstreamRespBody),
		},
	}
}

// TestPluginStepPre_ReceiveRespond_SubstitutesResponse pins the http.on_response
// RESPOND-replace contract: on a Receive-direction HTTPMessage the plugin
// response supersedes the upstream response in place. The Pipeline returns
// Continue with a substitute that keeps the exchange identity, drops the
// Layer's Opaque (so the client Layer writes the substitute, not a patch of
// the upstream head), carries the encoder's bytes as Raw, and releases the
// upstream body. RecordStep then records the upstream response as the
// original variant and the plugin response as the modified one.
func TestPluginStepPre_ReceiveRespond_SubstitutesResponse(t *testing.T) {
	for _, phase := range []pluginv2.Phase{pluginv2.PhasePrePipeline, pluginv2.PhasePostPipeline} {
		t.Run(string(phase), func(t *testing.T) {
			dir := t.TempDir()
			env := spilledH1Response(t, dir)
			pre := env.Message.(*envelope.HTTPMessage).BodyBuffer

			eng := pluginv2.NewEngine(nil)
			eng.Registry().Register(respondHook(pluginv2.ProtoHTTP, pluginv2.EventOnResponse, phase))
			// A second hook in the same phase must not run: the first
			// RESPOND wins.
			eng.Registry().Register(pluginv2.Hook{
				Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnResponse, Phase: phase, PluginName: "late",
				Fn: hookCallable("late", func(args starlark.Tuple) (starlark.Value, error) {
					msg := args[0].(*pluginv2.MessageDict)
					return starlark.None, msg.SetKey(starlark.String("status"), starlark.MakeInt(299))
				}),
			})
			encoders := NewWireEncoderRegistry()
			encoders.Register(envelope.ProtocolHTTP, http1.EncodeWireBytes)

			store := &mockWriter{}
			var step Step = NewPluginStepPre(eng, encoders, nil)
			if phase == pluginv2.PhasePostPipeline {
				step = NewPluginStepPost(eng, encoders, nil)
			}
			o := New(step, NewRecordStep(store, nil, WithWireEncoderRegistry(encoders))).RunDetailed(context.Background(), env)

			if o.Action != Continue {
				t.Fatalf("Action = %v (Response %+v), want Continue with the plugin response substituted", o.Action, o.Response)
			}
			out := o.Envelope
			msg, ok := out.Message.(*envelope.HTTPMessage)
			if !ok || msg.Status != 418 || string(msg.Body) != "plugin" {
				t.Fatalf("Message = %#v, want the plugin's 418 \"plugin\"", out.Message)
			}
			if out.StreamID != env.StreamID || out.FlowID != env.FlowID || out.Sequence != env.Sequence ||
				out.Direction != envelope.Receive || out.Context.ConnID != env.Context.ConnID {
				t.Errorf("identity = (%s, %s, %d, %v, %s), want the upstream response's (%s, %s, %d, Receive, %s)",
					out.StreamID, out.FlowID, out.Sequence, out.Direction, out.Context.ConnID,
					env.StreamID, env.FlowID, env.Sequence, env.Context.ConnID)
			}
			if out.Opaque != nil {
				t.Errorf("Opaque = %v, want nil (the client Layer must not patch the upstream head)", out.Opaque)
			}
			if out.RawAuthoritative {
				t.Error("RawAuthoritative = true, want false")
			}
			want, err := http1.EncodeWireBytes(out)
			if err != nil {
				t.Fatalf("EncodeWireBytes: %v", err)
			}
			if !bytes.Equal(out.Raw, want) {
				t.Errorf("Raw = %q, want the encoder output %q", out.Raw, want)
			}

			if got := variantFlow(t, store, "original").RawBytes; string(got) != upstreamRespHead {
				t.Errorf("original variant raw = %q, want the upstream bytes %q", got, upstreamRespHead)
			}
			if got := variantFlow(t, store, "modified").RawBytes; !bytes.Equal(got, want) {
				t.Errorf("modified variant raw = %q, want the bytes the client gets %q", got, want)
			}

			simulateBackstop(pre, nil, out)
			if n := countPluginSpillFiles(t, dir); n != 0 {
				t.Errorf("%d spill files left after the backstop, want 0 (upstream body leaked)", n)
			}
		})
	}
}

// TestPluginStepPre_SendRespond_StillResponds is the over-reach guard: an
// http.on_request RESPOND keeps returning Action=Respond, so the session
// answers the client without dialing the upstream.
func TestPluginStepPre_SendRespond_StillResponds(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	eng.Registry().Register(respondHook(pluginv2.ProtoHTTP, pluginv2.EventOnRequest, pluginv2.PhasePrePipeline))

	r := NewPluginStepPre(eng, nil, nil).Process(context.Background(), httpReqEnv())
	if r.Action != Respond || r.Response == nil {
		t.Fatalf("Action = %v Response = %v, want Respond with the plugin response", r.Action, r.Response)
	}
	if m, ok := r.Response.Message.(*envelope.HTTPMessage); !ok || m.Status != 418 {
		t.Errorf("Response message = %#v, want status 418", r.Response.Message)
	}
}
