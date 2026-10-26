package pluginv2

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// respondShapeEnv returns a representative envelope for each surface entry
// that permits RESPOND.
func respondShapeEnv(t *testing.T, protocol, event string) *envelope.Envelope {
	t.Helper()
	switch protocol + "." + event {
	case ProtoGRPCWeb + "." + EventOnStart:
		return &envelope.Envelope{
			StreamID: "s", FlowID: "f", Direction: envelope.Send,
			Protocol: envelope.ProtocolGRPCWeb,
			Message:  &envelope.GRPCStartMessage{Service: "pkg.Echo", Method: "Say"},
		}
	case ProtoGRPC + "." + EventOnStart:
		return &envelope.Envelope{
			StreamID: "s", FlowID: "f", Direction: envelope.Send,
			Protocol: envelope.ProtocolGRPC,
			Message:  &envelope.GRPCStartMessage{Service: "pkg.Echo", Method: "Say"},
		}
	case ProtoHTTP + "." + EventOnRequest:
		return httpEnv(t)
	case ProtoHTTP + "." + EventOnResponse:
		return &envelope.Envelope{
			StreamID: "s", FlowID: "f", Direction: envelope.Receive,
			Protocol: envelope.ProtocolHTTP,
			Message:  &envelope.HTTPMessage{Status: 200, StatusReason: "OK"},
		}
	case ProtoWS + "." + EventOnUpgrade:
		return &envelope.Envelope{
			StreamID: "s", FlowID: "f", Direction: envelope.Send,
			Protocol: envelope.ProtocolHTTP,
			Message: &envelope.HTTPMessage{
				Method: "GET", Path: "/ws", Authority: "example.com",
				Headers: []envelope.KeyValue{
					{Name: "Host", Value: "example.com"},
					{Name: "Connection", Value: "Upgrade"},
					{Name: "Upgrade", Value: "websocket"},
				},
			},
		}
	}
	t.Fatalf("no fixture envelope for (%s, %s)", protocol, event)
	return nil
}

// TestDispatch_RespondShapeMismatch_ReturnsDisallowedAction drives a hook
// loaded from a real Starlark script through Engine.Dispatch for every
// surface entry that permits RESPOND, in both phases. A RESPOND whose shape
// does not match the hook's protocol family (HTTP action.RESPOND on a gRPC
// hook, action.RESPOND_GRPC on an HTTP-family hook) is refused with
// ErrDisallowedAction naming the right builtin; the matching shape is still
// returned as ActionRespond (over-rejection guard).
func TestDispatch_RespondShapeMismatch_ReturnsDisallowedAction(t *testing.T) {
	const (
		httpRespond = `action.RESPOND(status_code=403, headers=[("Content-Type", "text/plain")], body=b"denied")`
		grpcRespond = `action.RESPOND_GRPC(status=16, message="denied")`
	)
	hooks := []struct {
		protocol, event string
		grpcFamily      bool
	}{
		{ProtoGRPCWeb, EventOnStart, true},
		{ProtoGRPC, EventOnStart, true},
		{ProtoHTTP, EventOnRequest, false},
		{ProtoHTTP, EventOnResponse, false},
		{ProtoWS, EventOnUpgrade, false},
	}
	phases := []Phase{PhasePrePipeline, PhasePostPipeline}

	for _, h := range hooks {
		for _, phase := range phases {
			for _, shape := range []string{"http", "grpc"} {
				name := fmt.Sprintf("%s.%s/%s/%s", h.protocol, h.event, phase, shape)
				t.Run(name, func(t *testing.T) {
					expr := httpRespond
					if shape == "grpc" {
						expr = grpcRespond
					}
					path := writeScript(t, fmt.Sprintf(`
def hook(msg, ctx):
    return %s

register_hook(%q, %q, hook, phase=%q)
`, expr, h.protocol, h.event, string(phase)))
					eng := NewEngine(nil)
					if err := eng.LoadPlugins(context.Background(), []PluginConfig{{Path: path, OnError: string(OnErrorAbort)}}); err != nil {
						t.Fatalf("LoadPlugins: %v", err)
					}
					registered := eng.Registry().Lookup(h.protocol, h.event, phase)
					if len(registered) != 1 {
						t.Fatalf("registered hooks = %d, want 1", len(registered))
					}

					out, err := eng.Dispatch(context.Background(), registered[0], respondShapeEnv(t, h.protocol, h.event))

					matching := (shape == "grpc") == h.grpcFamily
					if matching {
						if err != nil {
							t.Fatalf("Dispatch err = %v, want nil (matching shape must be honored)", err)
						}
						if out.Action != ActionRespond || out.Respond == nil {
							t.Fatalf("outcome = %+v, want ActionRespond with payload", out)
						}
						return
					}
					if !errors.Is(err, ErrDisallowedAction) {
						t.Fatalf("Dispatch err = %v (outcome %+v), want ErrDisallowedAction", err, out)
					}
					wantHint := "use action.RESPOND_GRPC"
					if !h.grpcFamily {
						wantHint = "use action.RESPOND"
					}
					if !strings.HasSuffix(err.Error(), wantHint) {
						t.Errorf("err = %q, want it to end with %q", err.Error(), wantHint)
					}
				})
			}
		}
	}
}
