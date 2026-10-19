package pipeline

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// USK-1079: RFC-001 §9.3 D4 "Raw wins" is carried on the Envelope itself
// (Envelope.RawAuthoritative) so the Layer that writes the wire can see it.
// These tests pin how the Pipeline sets and clears the marker.

// stepFunc adapts a function to the Step interface for tests.
type stepFunc func(ctx context.Context, env *envelope.Envelope) Result

func (f stepFunc) Process(ctx context.Context, env *envelope.Envelope) Result { return f(ctx, env) }

func rawHook(phase pluginv2.Phase, raw []byte) pluginv2.Hook {
	return pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase: phase, PluginName: "smuggler",
		Fn: hookCallable("inject", func(args starlark.Tuple) (starlark.Value, error) {
			msg := args[0].(*pluginv2.MessageDict)
			return starlark.None, msg.SetKey(starlark.String("raw"), starlark.Bytes(raw))
		}),
	}
}

func modifiedFlow(t *testing.T, store *mockWriter) *flow.Flow {
	t.Helper()
	for _, fl := range store.flows {
		if fl.Metadata["variant"] == "modified" {
			return fl
		}
	}
	t.Fatal("modified variant flow not recorded")
	return nil
}

// TestRawWins_RawOnly_MarksEnvelope: a plugin msg["raw"] write must mark
// the resulting envelope so the Layer writes Raw verbatim.
func TestRawWins_RawOnly_MarksEnvelope(t *testing.T) {
	custom := []byte("POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi")
	eng := pluginv2.NewEngine(nil)
	eng.Registry().Register(rawHook(pluginv2.PhasePrePipeline, custom))

	out, action, _ := New(NewPluginStepPre(eng, nil, nil)).Run(context.Background(), httpReqEnv())
	if action != Continue {
		t.Fatalf("action = %v", action)
	}
	if !out.RawAuthoritative {
		t.Error("RawAuthoritative = false after msg[\"raw\"] write; Layer cannot honour D4")
	}
	if !out.RawWins() {
		t.Error("RawWins() = false after msg[\"raw\"] write")
	}
	if !bytes.Equal(out.Raw, custom) {
		t.Errorf("Raw = %q, want plugin bytes", out.Raw)
	}
}

// TestRawWins_LaterMessageOnlyHookClearsMarker: a later hook that only
// changes the Message takes over (last writer wins).
func TestRawWins_LaterMessageOnlyHookClearsMarker(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	eng.Registry().Register(rawHook(pluginv2.PhasePrePipeline, []byte("RAW")))
	eng.Registry().Register(pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase: pluginv2.PhasePostPipeline, PluginName: "msg",
		Fn: hookCallable("method", func(args starlark.Tuple) (starlark.Value, error) {
			msg := args[0].(*pluginv2.MessageDict)
			return starlark.None, msg.SetKey(starlark.String("method"), starlark.String("PUT"))
		}),
	})

	out, _, _ := New(NewPluginStepPre(eng, nil, nil), NewPluginStepPost(eng, nil, nil)).Run(context.Background(), httpReqEnv())
	if out.RawAuthoritative {
		t.Error("RawAuthoritative still set after a later MessageOnly hook; Message mutation would be dropped on the wire")
	}
}

// TestRawWins_TransformClearsMarker (decision U1): a pre_pipeline raw write
// followed by a Transform rule that fires hands the wire back to the
// Message path.
func TestRawWins_TransformClearsMarker(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	eng.Registry().Register(rawHook(pluginv2.PhasePrePipeline, []byte("RAW")))
	te := httprules.NewTransformEngine()
	te.AddRule(httprules.TransformRule{
		ID: "add", Enabled: true, Direction: httprules.DirectionRequest,
		ActionType: httprules.TransformAddHeader, HeaderName: "X-T", HeaderValue: "1",
	})

	out, _, _ := New(NewPluginStepPre(eng, nil, nil), NewTransformStep(te, nil, nil, nil)).Run(context.Background(), httpReqEnv())
	if out.RawAuthoritative {
		t.Error("RawAuthoritative still set after a Transform rule fired; the Transform would be silently dropped on the wire")
	}
}

// TestRawWins_TransformNoMatchKeepsMarker: a Transform engine whose rules
// do not fire must not disturb the marker.
func TestRawWins_TransformNoMatchKeepsMarker(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	eng.Registry().Register(rawHook(pluginv2.PhasePrePipeline, []byte("RAW")))
	te := httprules.NewTransformEngine()
	te.AddRule(httprules.TransformRule{
		ID: "add", Enabled: true, Direction: httprules.DirectionRequest,
		PathPattern: regexp.MustCompile(`^/never$`),
		ActionType:  httprules.TransformAddHeader, HeaderName: "X-T", HeaderValue: "1",
	})

	out, _, _ := New(NewPluginStepPre(eng, nil, nil), NewTransformStep(te, nil, nil, nil)).Run(context.Background(), httpReqEnv())
	if !out.RawAuthoritative {
		t.Error("RawAuthoritative cleared by a Transform rule that did not fire")
	}
}

// TestRawWins_InterceptModifyAfterRaw_RecordsEncodedBytes (Test Plan #9):
// pre_pipeline raw write, then an intercept modify (which replaces the
// envelope with Clone()+Raw=nil, the shape mcp applyHTTPModify produces).
// The wire takes the Message path, so the modified variant must record
// the encoder output — not nil.
func TestRawWins_InterceptModifyAfterRaw_RecordsEncodedBytes(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	eng.Registry().Register(rawHook(pluginv2.PhasePrePipeline, []byte("POST /raw HTTP/1.1\r\nHost: x\r\n\r\n")))

	reg := NewWireEncoderRegistry()
	reg.Register(envelope.ProtocolHTTP, http1.EncodeWireBytes)

	interceptModify := stepFunc(func(_ context.Context, env *envelope.Envelope) Result {
		next := env.Clone()
		next.Raw = nil
		m := next.Message.(*envelope.HTTPMessage)
		m.Headers = append(m.Headers, envelope.KeyValue{Name: "X-Intercepted", Value: "1"})
		return Result{Envelope: next}
	})

	store := &mockWriter{}
	env := http1.BuildSendEnvelope("GET", "http", "example.com", "/orig", "",
		[]envelope.KeyValue{{Name: "Host", Value: "example.com"}}, nil)
	out, _, _ := New(
		NewPluginStepPre(eng, reg, nil),
		interceptModify,
		NewRecordStep(store, nil, WithWireEncoderRegistry(reg)),
	).Run(context.Background(), env)

	if out.RawWins() {
		t.Error("RawWins() = true after intercept modify cleared Raw")
	}
	mod := modifiedFlow(t, store)
	if len(mod.RawBytes) == 0 {
		t.Fatal("modified variant RawBytes is empty; encoder was skipped on a stale raw-wins signal")
	}
	if !strings.Contains(string(mod.RawBytes), "X-Intercepted: 1\r\n") {
		t.Errorf("modified RawBytes = %q, want the intercept-modified message encoding", mod.RawBytes)
	}
}

// TestRawWins_RawOnlyDropsSpilledRawBuffer (Test Plan #10): plugin raw is
// the complete message, so a disk-spilled RawBuffer must not be stitched
// after it.
func TestRawWins_RawOnlyDropsSpilledRawBuffer(t *testing.T) {
	custom := []byte("POST /p HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi")
	eng := pluginv2.NewEngine(nil)
	eng.Registry().Register(rawHook(pluginv2.PhasePostPipeline, custom))

	env := httpReqEnv()
	env.Raw = []byte("POST / HTTP/1.1\r\nContent-Length: 4\r\n\r\n")
	env.RawBuffer = bodybuf.NewMemory([]byte("BODY"))
	defer env.RawBuffer.Release()

	r := NewPluginStepPost(eng, nil, nil).Process(context.Background(), env)
	if r.Envelope == nil {
		t.Fatal("expected a new envelope")
	}
	if r.Envelope.RawBuffer != nil {
		t.Error("RawBuffer kept after msg[\"raw\"] write; WireBytes would append the original body")
	}
	wire, err := r.Envelope.WireBytes(context.Background())
	if err != nil {
		t.Fatalf("WireBytes: %v", err)
	}
	if !bytes.Equal(wire, custom) {
		t.Errorf("WireBytes = %q, want %q", wire, custom)
	}
	if env.RawBuffer == nil {
		t.Error("input envelope RawBuffer must be left for the session refcount backstop")
	}
}
