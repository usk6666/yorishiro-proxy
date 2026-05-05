package pluginv2

import (
	"testing"

	"go.starlark.net/starlark"
)

// stubCallable is a Starlark Callable just rich enough to fill Hook.Fn in
// registry tests that never actually invoke the function.
type stubCallable struct {
	name string
}

func (s *stubCallable) Name() string          { return s.name }
func (s *stubCallable) String() string        { return s.name }
func (s *stubCallable) Type() string          { return "stub_callable" }
func (s *stubCallable) Freeze()               {}
func (s *stubCallable) Truth() starlark.Bool  { return starlark.True }
func (s *stubCallable) Hash() (uint32, error) { return 0, nil }
func (s *stubCallable) CallInternal(_ *starlark.Thread, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, nil
}

func newStub(name string) *stubCallable { return &stubCallable{name: name} }

func TestRegistry_RegisterAndLookup(t *testing.T) {
	r := NewRegistry()
	fn := newStub("h1")
	r.Register(Hook{
		Protocol:   ProtoHTTP,
		Event:      EventOnRequest,
		Phase:      PhasePrePipeline,
		Fn:         fn,
		PluginName: "p1",
	})

	got := r.Lookup(ProtoHTTP, EventOnRequest, PhasePrePipeline)
	if len(got) != 1 {
		t.Fatalf("Lookup len = %d, want 1", len(got))
	}
	if got[0].Fn != fn {
		t.Errorf("Lookup[0].Fn != registered fn")
	}
	if got[0].PluginName != "p1" {
		t.Errorf("PluginName = %q, want %q", got[0].PluginName, "p1")
	}
}

func TestRegistry_LookupMissReturnsNil(t *testing.T) {
	r := NewRegistry()
	if got := r.Lookup(ProtoHTTP, EventOnRequest, PhasePrePipeline); got != nil {
		t.Errorf("expected nil for empty registry, got %v", got)
	}
}

func TestRegistry_PhaseSeparatesEntries(t *testing.T) {
	r := NewRegistry()
	r.Register(Hook{Protocol: ProtoHTTP, Event: EventOnRequest, Phase: PhasePrePipeline, Fn: newStub("pre"), PluginName: "p"})
	r.Register(Hook{Protocol: ProtoHTTP, Event: EventOnRequest, Phase: PhasePostPipeline, Fn: newStub("post"), PluginName: "p"})

	if pre := r.Lookup(ProtoHTTP, EventOnRequest, PhasePrePipeline); len(pre) != 1 || pre[0].Fn.Name() != "pre" {
		t.Errorf("pre lookup = %+v", pre)
	}
	if post := r.Lookup(ProtoHTTP, EventOnRequest, PhasePostPipeline); len(post) != 1 || post[0].Fn.Name() != "post" {
		t.Errorf("post lookup = %+v", post)
	}
}

func TestRegistry_RegistrationOrderPreserved(t *testing.T) {
	r := NewRegistry()
	for i, name := range []string{"a", "b", "c"} {
		r.Register(Hook{
			Protocol:   ProtoHTTP,
			Event:      EventOnRequest,
			Phase:      PhasePrePipeline,
			Fn:         newStub(name),
			PluginName: name,
		})
		if r.Count() != i+1 {
			t.Errorf("after register %d Count() = %d, want %d", i+1, r.Count(), i+1)
		}
	}

	got := r.Lookup(ProtoHTTP, EventOnRequest, PhasePrePipeline)
	if len(got) != 3 {
		t.Fatalf("Lookup len = %d, want 3", len(got))
	}
	for i, want := range []string{"a", "b", "c"} {
		if got[i].Fn.Name() != want {
			t.Errorf("got[%d].Fn.Name() = %q, want %q", i, got[i].Fn.Name(), want)
		}
	}
}

func TestRegistry_LookupReturnsSnapshotCopy(t *testing.T) {
	r := NewRegistry()
	r.Register(Hook{Protocol: ProtoHTTP, Event: EventOnRequest, Phase: PhasePrePipeline, Fn: newStub("a"), PluginName: "p"})

	snap := r.Lookup(ProtoHTTP, EventOnRequest, PhasePrePipeline)
	r.Register(Hook{Protocol: ProtoHTTP, Event: EventOnRequest, Phase: PhasePrePipeline, Fn: newStub("b"), PluginName: "p"})

	if len(snap) != 1 {
		t.Errorf("snapshot mutated by subsequent registration: len = %d", len(snap))
	}
}

func TestRegistry_LifecycleHooksUsePhaseNone(t *testing.T) {
	r := NewRegistry()
	r.Register(Hook{Protocol: ProtoConnection, Event: EventOnConnect, Phase: PhaseNone, Fn: newStub("c"), PluginName: "p"})
	if got := r.Lookup(ProtoConnection, EventOnConnect, PhaseNone); len(got) != 1 {
		t.Errorf("PhaseNone lookup = %+v", got)
	}
	if got := r.Lookup(ProtoConnection, EventOnConnect, PhasePrePipeline); got != nil {
		t.Errorf("PhasePrePipeline lookup should be nil, got %+v", got)
	}
}
