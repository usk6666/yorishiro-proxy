package pipeline

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// USK-1393: a plugin DROP / RESPOND is recorded. The dispatcher attributes
// the outcome (blocked_by="plugin" on DROP only, plugin identity tags on
// both) and asks RunDetailed to run the RecordStep that the short-circuit
// would otherwise skip, on the terminating envelope and on the synthesized
// response.

// outcomeHook returns a hook named "gate" whose callable returns ret.
func outcomeHook(protocol, event string, phase pluginv2.Phase, ret starlark.Value) pluginv2.Hook {
	return pluginv2.Hook{
		Protocol: protocol, Event: event, Phase: phase, PluginName: "gate",
		Fn: hookCallable("gate", func(starlark.Tuple) (starlark.Value, error) {
			return ret, nil
		}),
	}
}

func http418Respond() *pluginv2.RespondAction {
	return &pluginv2.RespondAction{HTTPResponse: &pluginv2.HTTPRespondPayload{
		StatusCode: 418,
		Headers:    []envelope.KeyValue{{Name: "Content-Type", Value: "text/plain"}},
		Body:       []byte("plugin"),
	}}
}

func grpcStartSendEnv() *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  "stream-grpc",
		FlowID:    "flow-grpc-start",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Context:   envelope.EnvelopeContext{ConnID: "conn-grpc"},
		Message: &envelope.GRPCStartMessage{
			Service: "pkg.Echo",
			Method:  "Say",
			Scheme:  "https",
		},
	}
}

// newTempStore opens a fresh SQLite flow store under t.TempDir.
func newTempStore(t *testing.T) *flow.SQLiteStore {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := flow.NewSQLiteStore(context.Background(), filepath.Join(t.TempDir(), "flows.db"), logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func phaseStep(eng *pluginv2.Engine, phase pluginv2.Phase) Step {
	if phase == pluginv2.PhasePostPipeline {
		return NewPluginStepPost(eng, nil, nil)
	}
	return NewPluginStepPre(eng, nil, nil)
}

var bothPhases = []pluginv2.Phase{pluginv2.PhasePrePipeline, pluginv2.PhasePostPipeline}

// T1: the outcome carries blocked_by="plugin" on DROP only and the plugin
// identity annotations on both DROP and RESPOND.
func TestPluginOutcome_Attribution(t *testing.T) {
	for _, phase := range bothPhases {
		t.Run(string(phase)+"/drop", func(t *testing.T) {
			eng := pluginv2.NewEngine(nil)
			eng.Registry().Register(outcomeHook(pluginv2.ProtoHTTP, pluginv2.EventOnRequest, phase, starlark.String("DROP")))
			o := New(phaseStep(eng, phase)).RunDetailed(context.Background(), httpReqEnv())
			if o.Action != Drop {
				t.Fatalf("Action = %v, want Drop", o.Action)
			}
			if o.BlockedBy != BlockedByPlugin {
				t.Errorf("BlockedBy = %q, want %q", o.BlockedBy, BlockedByPlugin)
			}
			assertPluginTags(t, o.Annotations, "http.on_request", string(phase))
		})
		t.Run(string(phase)+"/respond", func(t *testing.T) {
			eng := pluginv2.NewEngine(nil)
			eng.Registry().Register(outcomeHook(pluginv2.ProtoHTTP, pluginv2.EventOnRequest, phase, http418Respond()))
			o := New(phaseStep(eng, phase)).RunDetailed(context.Background(), httpReqEnv())
			if o.Action != Respond {
				t.Fatalf("Action = %v, want Respond", o.Action)
			}
			if o.BlockedBy != "" {
				t.Errorf("BlockedBy = %q, want empty (RESPOND is not a block)", o.BlockedBy)
			}
			assertPluginTags(t, o.Annotations, "http.on_request", string(phase))
		})
	}
}

func assertPluginTags(t *testing.T, tags map[string]string, hook, phase string) {
	t.Helper()
	want := map[string]string{"plugin": "gate", "plugin_hook": hook, "plugin_phase": phase}
	for k, v := range want {
		if tags[k] != v {
			t.Errorf("tags[%q] = %q, want %q (tags %v)", k, tags[k], v, tags)
		}
	}
}

// T2: RunDetailed runs the RecordStep after a plugin DROP / RESPOND on the
// terminating envelope and, for RESPOND, on the synthesized response.
func TestPluginOutcome_RecordsTerminatingEnvelope(t *testing.T) {
	ctx := context.Background()
	t.Run("http drop", func(t *testing.T) {
		store := newTempStore(t)
		eng := pluginv2.NewEngine(nil)
		eng.Registry().Register(outcomeHook(pluginv2.ProtoHTTP, pluginv2.EventOnRequest, pluginv2.PhasePrePipeline, starlark.String("DROP")))
		env := httpReqEnv()
		o := New(NewPluginStepPre(eng, nil, nil), NewRecordStep(store, nil)).RunDetailed(ctx, env)
		if o.Action != Drop {
			t.Fatalf("Action = %v, want Drop", o.Action)
		}
		st := mustStream(t, store, env.StreamID)
		if st.Protocol != string(envelope.ProtocolHTTP) {
			t.Errorf("Stream.Protocol = %q, want http", st.Protocol)
		}
		assertPluginTags(t, st.Tags, "http.on_request", "pre_pipeline")
		flows := mustFlows(t, store, env.StreamID)
		if len(flows) != 1 || flows[0].Direction != "send" || flows[0].Method != "GET" {
			t.Fatalf("flows = %s, want exactly the dropped GET request", describeFlows(flows))
		}
	})
	t.Run("http respond", func(t *testing.T) {
		store := newTempStore(t)
		eng := pluginv2.NewEngine(nil)
		eng.Registry().Register(outcomeHook(pluginv2.ProtoHTTP, pluginv2.EventOnRequest, pluginv2.PhasePostPipeline, http418Respond()))
		env := httpReqEnv()
		o := New(NewPluginStepPost(eng, nil, nil), NewRecordStep(store, nil)).RunDetailed(ctx, env)
		if o.Action != Respond || o.Response == nil {
			t.Fatalf("Action = %v Response = %v, want Respond with a response", o.Action, o.Response)
		}
		if !o.Response.Context.Synthetic {
			t.Error("Response.Context.Synthetic = false, want true")
		}
		if o.Response.FlowID == env.FlowID {
			t.Errorf("Response.FlowID = request FlowID %q, want a distinct ID", env.FlowID)
		}
		st := mustStream(t, store, env.StreamID)
		assertPluginTags(t, st.Tags, "http.on_request", "post_pipeline")
		flows := mustFlows(t, store, env.StreamID)
		if len(flows) != 2 {
			t.Fatalf("flows = %s, want the request and the plugin response", describeFlows(flows))
		}
		var req, resp *flow.Flow
		for _, f := range flows {
			switch f.Direction {
			case "send":
				req = f
			case "receive":
				resp = f
			}
		}
		if req == nil || req.Method != "GET" || req.Metadata["synthetic"] != "" {
			t.Errorf("send flow = %+v, want the wire GET with no synthetic marker", req)
		}
		if resp == nil || resp.StatusCode != 418 || string(resp.Body) != "plugin" || resp.Metadata["synthetic"] != "true" {
			t.Errorf("receive flow = %+v, want the plugin's 418 marked synthetic=true", resp)
		}
		if resp != nil && resp.Metadata["variant"] != "" {
			t.Errorf("receive flow variant = %q, want none (the response is not a modification of the request)", resp.Metadata["variant"])
		}
	})
	t.Run("grpc start respond", func(t *testing.T) {
		store := newTempStore(t)
		eng := pluginv2.NewEngine(nil)
		eng.Registry().Register(outcomeHook(pluginv2.ProtoGRPC, pluginv2.EventOnStart, pluginv2.PhasePrePipeline,
			&pluginv2.RespondAction{GRPCResponse: &pluginv2.GRPCRespondPayload{Status: 7, Message: "denied by plugin"}}))
		env := grpcStartSendEnv()
		o := New(NewPluginStepPre(eng, nil, nil), NewRecordStep(store, nil)).RunDetailed(ctx, env)
		if o.Action != Respond {
			t.Fatalf("Action = %v, want Respond", o.Action)
		}
		st := mustStream(t, store, env.StreamID)
		if st.Protocol != string(envelope.ProtocolGRPC) {
			t.Errorf("Stream.Protocol = %q, want grpc", st.Protocol)
		}
		flows := mustFlows(t, store, env.StreamID)
		var end *flow.Flow
		for _, f := range flows {
			if f.Direction == "receive" && f.Metadata["grpc_event"] == "end" {
				end = f
			}
		}
		if len(flows) != 2 || end == nil {
			t.Fatalf("flows = %s, want the Start and the synthesized End", describeFlows(flows))
		}
		if end.Metadata["grpc_status"] != "7" || end.Metadata["synthetic"] != "true" {
			t.Errorf("End metadata = %v, want grpc_status=7 synthetic=true", end.Metadata)
		}
	})
	t.Run("policy drop records nothing", func(t *testing.T) {
		store := newTempStore(t)
		policy := stepFunc(func(context.Context, *envelope.Envelope) Result {
			return Result{Action: Drop, BlockedBy: BlockedByTargetScope}
		})
		env := httpReqEnv()
		o := New(policy, NewRecordStep(store, nil)).RunDetailed(ctx, env)
		if o.Action != Drop {
			t.Fatalf("Action = %v, want Drop", o.Action)
		}
		if _, err := store.GetStream(ctx, env.StreamID); err == nil {
			t.Error("a policy Drop recorded a Stream; policy blocks stay Stream-only via OnPipelineDrop")
		}
	})
}

// T3: RecordStep projects EnvelopeContext.Synthetic onto the flow metadata.
func TestRecordStep_ProjectsSyntheticMetadata(t *testing.T) {
	store := &mockWriter{}
	env := httpReqEnv()
	env.Context.Synthetic = true
	NewRecordStep(store, nil).Process(context.Background(), env)
	if len(store.flows) != 1 {
		t.Fatalf("flows = %d, want 1", len(store.flows))
	}
	if got := store.flows[0].Metadata["synthetic"]; got != "true" {
		t.Errorf("Metadata[synthetic] = %q, want \"true\"", got)
	}

	plain := &mockWriter{}
	NewRecordStep(plain, nil).Process(context.Background(), httpReqEnv())
	if _, ok := plain.flows[0].Metadata["synthetic"]; ok {
		t.Errorf("wire envelope carries Metadata[synthetic] = %q, want the key absent", plain.flows[0].Metadata["synthetic"])
	}
}

func mustStream(t *testing.T, store *flow.SQLiteStore, id string) *flow.Stream {
	t.Helper()
	st, err := store.GetStream(context.Background(), id)
	if err != nil {
		t.Fatalf("GetStream(%s): %v — the plugin outcome was not recorded", id, err)
	}
	return st
}

func mustFlows(t *testing.T, store *flow.SQLiteStore, id string) []*flow.Flow {
	t.Helper()
	flows, err := store.GetFlows(context.Background(), id, flow.FlowListOptions{})
	if err != nil {
		t.Fatalf("GetFlows(%s): %v", id, err)
	}
	return flows
}

func describeFlows(flows []*flow.Flow) string {
	out := "["
	for i, f := range flows {
		if i > 0 {
			out += ", "
		}
		out += f.Direction + ":" + f.Method + ":" + f.Metadata["grpc_event"]
	}
	return out + "]"
}
