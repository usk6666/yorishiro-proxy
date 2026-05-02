package pipeline

import (
	"context"
	"sync/atomic"
	"testing"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
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

// TestPluginIntegration_MessageOnly_EncoderCalledExactlyOnce covers USK-684:
// when PluginStepPost performs a MessageOnly mutation, the per-protocol
// WireEncoder must be invoked exactly ONCE across PluginStepPost +
// RecordStep on the same envelope. Pre-USK-684 the same encoder ran twice
// (once in pluginDispatcher.regenerateRaw to update env.Raw, again in
// RecordStep.applyWireEncode to render modFlow.RawBytes — bit-identical
// output, pure waste on heavy encoders).
//
// The spy encoder in this test increments a counter on every call. The
// modified-variant flow's RawBytes must equal the spy's output (proves
// envelopeToFlow already copied the post-regenerate Raw into modFlow).
func TestPluginIntegration_MessageOnly_EncoderCalledExactlyOnce(t *testing.T) {
	var encodeCalls int32
	spyOutput := []byte("POST / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	spy := func(*envelope.Envelope) ([]byte, error) {
		atomic.AddInt32(&encodeCalls, 1)
		return spyOutput, nil
	}

	reg := NewWireEncoderRegistry()
	reg.Register(envelope.ProtocolHTTP, spy)

	eng := pluginv2.NewEngine(nil)
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase: pluginv2.PhasePostPipeline, PluginName: "p",
		Fn: hookCallable("mutate-method", func(args starlark.Tuple) (starlark.Value, error) {
			msg := args[0].(*pluginv2.MessageDict)
			return starlark.None, msg.SetKey(starlark.String("method"), starlark.String("POST"))
		}),
	})

	store := &mockWriter{}
	p := New(
		NewPluginStepPost(eng, reg, nil),
		NewRecordStep(store, nil, WithWireEncoderRegistry(reg)),
	)

	if _, action, _ := p.Run(context.Background(), httpReqEnv()); action != Continue {
		t.Fatalf("action = %v", action)
	}

	if got := atomic.LoadInt32(&encodeCalls); got != 1 {
		t.Errorf("encoder called %d times, want exactly 1 (USK-684 dedup)", got)
	}

	// Verify the modified variant was recorded with the encoder output.
	// envelopeToFlow copies env.Raw — which is the spy output after
	// regenerateRaw — into modFlow.RawBytes. The skipped applyWireEncode
	// would have produced the same bytes; skipping is byte-equivalent.
	var modFlow *flow.Flow
	for _, fl := range store.flows {
		if fl.Metadata["variant"] == "modified" {
			modFlow = fl
			break
		}
	}
	if modFlow == nil {
		t.Fatal("modified variant flow not recorded")
	}
	if string(modFlow.RawBytes) != string(spyOutput) {
		t.Errorf("modified RawBytes = %q, want spy output %q", modFlow.RawBytes, spyOutput)
	}
	if got := modFlow.Metadata["wire_bytes"]; got != "" {
		t.Errorf("wire_bytes Metadata = %q, want empty (encoder succeeded; tag must not be set)", got)
	}
}

// TestPluginIntegration_MessageOnly_EncoderFailSoft_RecordStepRetries verifies
// that the dedup signal is NOT set when regenerateRaw's encoder failed soft
// (returned (nil, nil)). RecordStep must still run applyWireEncode so the
// modified variant's Metadata["wire_bytes"] is tagged "unavailable".
//
// The spy returns (nil, nil) on every call. PluginStepPost calls it once
// (via regenerateRaw); RecordStep calls it a second time (via
// applyWireEncode) — total 2 calls. RecordStep's second call also
// fail-softs and tags the metadata.
func TestPluginIntegration_MessageOnly_EncoderFailSoft_RecordStepRetries(t *testing.T) {
	var encodeCalls int32
	spy := func(*envelope.Envelope) ([]byte, error) {
		atomic.AddInt32(&encodeCalls, 1)
		return nil, nil // fail-soft
	}

	reg := NewWireEncoderRegistry()
	reg.Register(envelope.ProtocolHTTP, spy)

	eng := pluginv2.NewEngine(nil)
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase: pluginv2.PhasePostPipeline, PluginName: "p",
		Fn: hookCallable("mutate-method", func(args starlark.Tuple) (starlark.Value, error) {
			msg := args[0].(*pluginv2.MessageDict)
			return starlark.None, msg.SetKey(starlark.String("method"), starlark.String("POST"))
		}),
	})

	store := &mockWriter{}
	p := New(
		NewPluginStepPost(eng, reg, nil),
		NewRecordStep(store, nil, WithWireEncoderRegistry(reg)),
	)

	if _, action, _ := p.Run(context.Background(), httpReqEnv()); action != Continue {
		t.Fatalf("action = %v", action)
	}

	if got := atomic.LoadInt32(&encodeCalls); got != 2 {
		t.Errorf("encoder called %d times on fail-soft path, want 2 (regenerateRaw + applyWireEncode retry)", got)
	}

	var modFlow *flow.Flow
	for _, fl := range store.flows {
		if fl.Metadata["variant"] == "modified" {
			modFlow = fl
			break
		}
	}
	if modFlow == nil {
		t.Fatal("modified variant flow not recorded")
	}
	if got := modFlow.Metadata["wire_bytes"]; got != "unavailable" {
		t.Errorf("wire_bytes Metadata = %q, want %q (fail-soft path must still tag)", got, "unavailable")
	}
}

// TestPluginIntegration_RawOnly_DedupSignalCleared verifies that a
// MutationRawOnly outcome does NOT leave the dedup signal set: even though
// PluginStepPost did not call the encoder (Raw was injected verbatim), the
// signal must be false so RecordStep's applyWireEncode runs unchanged.
// This preserves pre-USK-684 behavior on the RawOnly path strictly per the
// Linear ticket's "out of scope" rule for the cousin MutationBoth bug.
func TestPluginIntegration_RawOnly_DedupSignalCleared(t *testing.T) {
	var encodeCalls int32
	encoderOutput := []byte("ENCODED-FROM-MESSAGE")
	spy := func(*envelope.Envelope) ([]byte, error) {
		atomic.AddInt32(&encodeCalls, 1)
		return encoderOutput, nil
	}

	reg := NewWireEncoderRegistry()
	reg.Register(envelope.ProtocolHTTP, spy)

	customRaw := []byte("CUSTOM SMUGGLING PAYLOAD")
	eng := pluginv2.NewEngine(nil)
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase: pluginv2.PhasePostPipeline, PluginName: "p",
		Fn: hookCallable("inject-raw", func(args starlark.Tuple) (starlark.Value, error) {
			msg := args[0].(*pluginv2.MessageDict)
			return starlark.None, msg.SetKey(starlark.String("raw"), starlark.Bytes(customRaw))
		}),
	})

	store := &mockWriter{}
	p := New(
		NewPluginStepPost(eng, reg, nil),
		NewRecordStep(store, nil, WithWireEncoderRegistry(reg)),
	)

	if _, action, _ := p.Run(context.Background(), httpReqEnv()); action != Continue {
		t.Fatalf("action = %v", action)
	}

	// PluginStepPost did NOT call the encoder (RawOnly path).
	// RecordStep's applyWireEncode DID call it (signal cleared), preserving
	// pre-USK-684 behavior. Total: 1 call.
	if got := atomic.LoadInt32(&encodeCalls); got != 1 {
		t.Errorf("encoder called %d times, want 1 (RawOnly: only RecordStep calls)", got)
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
