package pipeline

import (
	"context"
	"sync/atomic"
	"testing"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// TestPluginIntegration_LiveWire_BothPhasesFire covers AC#1: Live HTTPMessage
// で http.on_request の pre が fire し、その後 post も fire (両方).
func TestPluginIntegration_LiveWire_BothPhasesFire(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	var preCount, postCount int32

	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase: pluginv2.PhasePrePipeline, PluginName: "annot",
		Fn: hookCallable("pre", func(args starlark.Tuple) (starlark.Value, error) {
			atomic.AddInt32(&preCount, 1)
			return starlark.None, nil
		}),
	})
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase: pluginv2.PhasePostPipeline, PluginName: "sign",
		Fn: hookCallable("post", func(args starlark.Tuple) (starlark.Value, error) {
			atomic.AddInt32(&postCount, 1)
			return starlark.None, nil
		}),
	})

	live := New(
		NewPluginStepPre(eng, nil, nil),
		NewPluginStepPost(eng, nil, nil),
	)

	_, action, _ := live.Run(context.Background(), httpReqEnv())
	if action != Continue {
		t.Errorf("action = %v, want Continue", action)
	}
	if pre := atomic.LoadInt32(&preCount); pre != 1 {
		t.Errorf("preCount = %d, want 1", pre)
	}
	if post := atomic.LoadInt32(&postCount); post != 1 {
		t.Errorf("postCount = %d, want 1", post)
	}
}

// TestPluginIntegration_ResendBypass_OnlyPostFires covers AC#2: Resend
// HTTPMessage envelope で http.on_request の post のみ fire (pre は fire しない).
//
// The resend Pipeline is constructed via Pipeline.Without(&PluginStepPre{})
// — the orchestrator pattern from the issue text. This is what the
// MacroSendFuncAdapter precedent uses for InterceptStep exclusion.
func TestPluginIntegration_ResendBypass_OnlyPostFires(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	var preCount, postCount int32

	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase: pluginv2.PhasePrePipeline, PluginName: "annot",
		Fn: hookCallable("pre", func(args starlark.Tuple) (starlark.Value, error) {
			atomic.AddInt32(&preCount, 1)
			return starlark.None, nil
		}),
	})
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase: pluginv2.PhasePostPipeline, PluginName: "sign",
		Fn: hookCallable("post", func(args starlark.Tuple) (starlark.Value, error) {
			atomic.AddInt32(&postCount, 1)
			return starlark.None, nil
		}),
	})

	live := New(
		NewPluginStepPre(eng, nil, nil),
		NewPluginStepPost(eng, nil, nil),
	)
	resend := live.Without(&PluginStepPre{})

	_, action, _ := resend.Run(context.Background(), httpReqEnv())
	if action != Continue {
		t.Errorf("action = %v", action)
	}
	if pre := atomic.LoadInt32(&preCount); pre != 0 {
		t.Errorf("preCount = %d, want 0 (PluginStepPre must be excluded from resend)", pre)
	}
	if post := atomic.LoadInt32(&postCount); post != 1 {
		t.Errorf("postCount = %d, want 1", post)
	}
}

// TestPluginIntegration_PipelineOrder_Snapshot covers the canonical Pipeline
// position: PluginStepPre runs after a placeholder Safety stand-in and
// before Intercept; PluginStepPost runs after Macro and before Record.
//
// We use orderRecorder Steps to assert the call sequence; the real
// Scope/RateLimit/Safety/Intercept/Transform/Macro Steps are not
// instantiated here — this test verifies the Step IDENTITY ordering, not
// per-Step semantics (those have their own tests).
func TestPluginIntegration_PipelineOrder_Snapshot(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	var seq []string

	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase: pluginv2.PhasePrePipeline, PluginName: "p",
		Fn: hookCallable("pre", func(args starlark.Tuple) (starlark.Value, error) {
			seq = append(seq, "PluginPre")
			return starlark.None, nil
		}),
	})
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase: pluginv2.PhasePostPipeline, PluginName: "p",
		Fn: hookCallable("post", func(args starlark.Tuple) (starlark.Value, error) {
			seq = append(seq, "PluginPost")
			return starlark.None, nil
		}),
	})

	rec := func(label string) Step {
		return &orderRecorder{label: label, sink: &seq}
	}

	p := New(
		rec("Scope"),
		rec("RateLimit"),
		rec("Safety"),
		NewPluginStepPre(eng, nil, nil),
		rec("Intercept"),
		rec("Transform"),
		rec("Macro"),
		NewPluginStepPost(eng, nil, nil),
		rec("Record"),
	)
	if _, action, _ := p.Run(context.Background(), httpReqEnv()); action != Continue {
		t.Fatalf("action = %v", action)
	}
	want := []string{
		"Scope",
		"RateLimit",
		"Safety",
		"PluginPre",
		"Intercept",
		"Transform",
		"Macro",
		"PluginPost",
		"Record",
	}
	if len(seq) != len(want) {
		t.Fatalf("seq = %v, want %v", seq, want)
	}
	for i := range want {
		if seq[i] != want[i] {
			t.Errorf("seq[%d] = %q, want %q", i, seq[i], want[i])
		}
	}
}

// TestPluginIntegration_PrePostShareCtxState verifies that pre and post
// hooks fired on the same envelope share ctx.transaction_state — the
// USK-670 contract that USK-671 promises.
func TestPluginIntegration_PrePostShareCtxState(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	var observed string

	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase: pluginv2.PhasePrePipeline, PluginName: "p",
		Fn: hookCallable("pre", func(args starlark.Tuple) (starlark.Value, error) {
			c := args[1].(*pluginv2.Ctx)
			tx, _ := c.Attr("transaction_state")
			set, _ := tx.(starlark.HasAttrs).Attr("set")
			thread := &starlark.Thread{Name: "t"}
			_, err := starlark.Call(thread, set,
				starlark.Tuple{starlark.String("k"), starlark.String("v-from-pre")}, nil)
			return starlark.None, err
		}),
	})
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase: pluginv2.PhasePostPipeline, PluginName: "p",
		Fn: hookCallable("post", func(args starlark.Tuple) (starlark.Value, error) {
			c := args[1].(*pluginv2.Ctx)
			tx, _ := c.Attr("transaction_state")
			get, _ := tx.(starlark.HasAttrs).Attr("get")
			thread := &starlark.Thread{Name: "t"}
			v, err := starlark.Call(thread, get, starlark.Tuple{starlark.String("k")}, nil)
			if err != nil {
				return nil, err
			}
			if s, ok := v.(starlark.String); ok {
				observed = string(s)
			}
			return starlark.None, nil
		}),
	})

	live := New(
		NewPluginStepPre(eng, nil, nil),
		NewPluginStepPost(eng, nil, nil),
	)
	if _, action, _ := live.Run(context.Background(), httpReqEnv()); action != Continue {
		t.Fatalf("action = %v", action)
	}
	if observed != "v-from-pre" {
		t.Errorf("post observed %q, want %q (transaction_state should be shared across phases)", observed, "v-from-pre")
	}
}

// TestPluginIntegration_PipelineWithoutMatchesPluginStepPre_TypeIdentity
// guards the Pipeline.Without contract that USK-671 relies on: passing
// any *PluginStepPre instance excludes ALL PluginStepPre instances by
// reflect.TypeOf. If this regresses, the resend bypass breaks.
func TestPluginIntegration_PipelineWithoutMatchesPluginStepPre_TypeIdentity(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	live := New(
		NewPluginStepPre(eng, nil, nil),
		NewPluginStepPost(eng, nil, nil),
	)
	resend := live.Without(&PluginStepPre{})
	if got, want := stepCountByType(resend), 1; got != want {
		t.Errorf("resend pipeline step count = %d, want %d", got, want)
	}
}

// orderRecorder is a Pipeline Step that appends its label to a shared
// slice. Used to assert Pipeline ordering without instantiating the real
// Scope/RateLimit/etc. Steps.
type orderRecorder struct {
	label string
	sink  *[]string
}

func (r *orderRecorder) Process(_ context.Context, _ *envelope.Envelope) Result {
	*r.sink = append(*r.sink, r.label)
	return Result{}
}

// stepCountByType reports how many Steps are present in the Pipeline.
// Used to verify Pipeline.Without's exclusion behavior.
func stepCountByType(p *Pipeline) int { return len(p.steps) }
