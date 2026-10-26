package pluginv2

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// receiveHTTPEnv returns a Receive-direction HTTP response envelope with the
// given status and headers.
func receiveHTTPEnv(status int, headers ...envelope.KeyValue) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID: "s", FlowID: "f", Direction: envelope.Receive,
		Protocol: envelope.ProtocolHTTP,
		Message:  &envelope.HTTPMessage{Status: status, Headers: headers},
	}
}

// TestDispatch_RespondOnInformationalResponse drives a hook loaded from a
// real Starlark script through Engine.Dispatch on Receive-direction HTTP
// responses. A RESPOND on an informational 1xx response (other than 101) is
// refused with ErrDisallowedAction: the upstream's final response follows on
// the same exchange, so honouring it would hand the client two final
// responses. RESPOND on a final response and on a 101 WebSocket upgrade
// response stays accepted.
func TestDispatch_RespondOnInformationalResponse(t *testing.T) {
	wsHeaders := []envelope.KeyValue{
		{Name: "Connection", Value: "Upgrade"},
		{Name: "Upgrade", Value: "websocket"},
	}
	cases := []struct {
		name     string
		protocol string
		event    string
		env      *envelope.Envelope
		refused  bool
	}{
		{name: "100 continue", protocol: ProtoHTTP, event: EventOnResponse, env: receiveHTTPEnv(100), refused: true},
		{name: "103 early hints", protocol: ProtoHTTP, event: EventOnResponse, env: receiveHTTPEnv(103), refused: true},
		{name: "199", protocol: ProtoHTTP, event: EventOnResponse, env: receiveHTTPEnv(199), refused: true},
		{name: "200 final", protocol: ProtoHTTP, event: EventOnResponse, env: receiveHTTPEnv(200), refused: false},
		{name: "404 final", protocol: ProtoHTTP, event: EventOnResponse, env: receiveHTTPEnv(404), refused: false},
		{name: "101 ws upgrade", protocol: ProtoWS, event: EventOnUpgrade, env: receiveHTTPEnv(101, wsHeaders...), refused: false},
	}
	for _, tc := range cases {
		for _, phase := range []Phase{PhasePrePipeline, PhasePostPipeline} {
			t.Run(fmt.Sprintf("%s/%s", tc.name, phase), func(t *testing.T) {
				path := writeScript(t, fmt.Sprintf(`
def hook(msg, ctx):
    return action.RESPOND(status_code=418, body=b"plugin")

register_hook(%q, %q, hook, phase=%q)
`, tc.protocol, tc.event, string(phase)))
				eng := NewEngine(nil)
				if err := eng.LoadPlugins(context.Background(), []PluginConfig{{Path: path, OnError: string(OnErrorAbort)}}); err != nil {
					t.Fatalf("LoadPlugins: %v", err)
				}
				hooks := eng.Registry().Lookup(tc.protocol, tc.event, phase)
				if len(hooks) != 1 {
					t.Fatalf("registered hooks = %d, want 1", len(hooks))
				}

				out, err := eng.Dispatch(context.Background(), hooks[0], tc.env)

				if tc.refused {
					if !errors.Is(err, ErrDisallowedAction) {
						t.Fatalf("Dispatch = (%+v, %v), want ErrDisallowedAction (RESPOND on an informational response)", out, err)
					}
					return
				}
				if err != nil {
					t.Fatalf("Dispatch err = %v, want nil", err)
				}
				if out.Action != ActionRespond || out.Respond == nil || out.Respond.HTTPResponse == nil {
					t.Fatalf("outcome = %+v, want ActionRespond with an HTTP payload", out)
				}
			})
		}
	}
}
