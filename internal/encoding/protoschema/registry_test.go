package protoschema

import (
	"strings"
	"sync"
	"testing"
)

func TestRegistry_RegisterListUnregisterClear(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	specs, err := LoadFileDescriptorSet(testDescBytes, nil)
	if err != nil {
		t.Fatalf("LoadFileDescriptorSet: %v", err)
	}
	r.Register(specs)

	// SayHello on Greeter is present.
	if m := r.LookupMethod("usk.test.Greeter", "SayHello"); m == nil {
		t.Fatal("LookupMethod returned nil for known method")
	}
	// Wrong case is rejected (Resolved #3).
	if m := r.LookupMethod("usk.test.greeter", "SayHello"); m != nil {
		t.Error("LookupMethod accepted lowercase service; want nil")
	}

	// List should report two services (Greeter, Reflective).
	svcs := r.ListServices()
	if len(svcs) != 2 {
		t.Fatalf("ListServices len = %d, want 2", len(svcs))
	}
	// Sorted alphabetically.
	if svcs[0].Service != "usk.test.Greeter" || svcs[1].Service != "usk.test.Reflective" {
		t.Errorf("ListServices order = [%s, %s]", svcs[0].Service, svcs[1].Service)
	}

	// Unregister Greeter; Reflective remains.
	if !r.Unregister("usk.test.Greeter") {
		t.Error("Unregister returned false for known service")
	}
	if m := r.LookupMethod("usk.test.Greeter", "SayHello"); m != nil {
		t.Error("LookupMethod returned non-nil after Unregister")
	}
	if m := r.LookupMethod("usk.test.Reflective", "Lookup"); m == nil {
		t.Error("LookupMethod returned nil for Reflective after Greeter Unregister")
	}

	// Unregister nonexistent service is a no-op returning false.
	if r.Unregister("nope") {
		t.Error("Unregister returned true for unknown service")
	}

	// Clear removes everything.
	r.Clear()
	if len(r.ListServices()) != 0 {
		t.Error("ListServices non-empty after Clear")
	}
}

func TestRegistry_LastWriteWins(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	specs, err := LoadFileDescriptorSet(testDescBytes, nil)
	if err != nil {
		t.Fatalf("LoadFileDescriptorSet: %v", err)
	}
	r.Register(specs)

	// Re-register with a filter to only Greeter — overwrites the Greeter
	// entry but should leave Reflective intact (it's not in the input).
	greeterOnly, err := LoadFileDescriptorSet(testDescBytes, []string{"usk.test.Greeter"})
	if err != nil {
		t.Fatalf("LoadFileDescriptorSet greeter-only: %v", err)
	}
	r.Register(greeterOnly)

	svcs := r.ListServices()
	if len(svcs) != 2 {
		t.Errorf("ListServices len = %d, want 2 (greeter overwrite must not drop reflective)", len(svcs))
	}
}

func TestLoadFileDescriptorSet_ServiceFilter(t *testing.T) {
	t.Parallel()
	specs, err := LoadFileDescriptorSet(testDescBytes, []string{"usk.test.Greeter"})
	if err != nil {
		t.Fatalf("LoadFileDescriptorSet: %v", err)
	}
	if len(specs) != 1 {
		t.Fatalf("filtered specs len = %d, want 1", len(specs))
	}
	if specs[0].Service != "usk.test.Greeter" {
		t.Errorf("service = %q, want usk.test.Greeter", specs[0].Service)
	}
}

func TestLoadFileDescriptorSet_ServiceFilterUnused(t *testing.T) {
	t.Parallel()
	_, err := LoadFileDescriptorSet(testDescBytes, []string{"usk.test.NoSuch"})
	if err == nil {
		t.Fatal("expected error for filter entry not found in descriptor set")
	}
	if !strings.Contains(err.Error(), "usk.test.NoSuch") {
		t.Errorf("error must name the missing service: %q", err.Error())
	}
}

func TestLoadFileDescriptorSet_Empty(t *testing.T) {
	t.Parallel()
	_, err := LoadFileDescriptorSet(nil, nil)
	if err == nil {
		t.Error("expected error for empty input")
	}
}

func TestLoadFileDescriptorSet_SizeCap(t *testing.T) {
	t.Parallel()
	// One byte over the cap.
	huge := make([]byte, MaxDescriptorSetBytes+1)
	_, err := LoadFileDescriptorSet(huge, nil)
	if err == nil {
		t.Fatal("expected error for descriptor over size cap")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Errorf("error must mention size cap: %q", err.Error())
	}
}

func TestLoadFileDescriptorSet_MissingImports(t *testing.T) {
	t.Parallel()
	_, err := LoadFileDescriptorSet(withImportsMissingBytes, nil)
	if err == nil {
		t.Fatal("expected error for descriptor missing imports")
	}
	if !strings.Contains(err.Error(), "include_imports") {
		t.Errorf("error must point at protoc --include_imports flag, got: %q", err.Error())
	}
}

func TestLoadFileDescriptorSet_MalformedBytes(t *testing.T) {
	t.Parallel()
	_, err := LoadFileDescriptorSet([]byte{0xff, 0xff, 0xff, 0xff}, nil)
	if err == nil {
		t.Error("expected error for malformed descriptor bytes")
	}
}

// TestRegistry_ConcurrentReadDuringWrite exercises the atomic-snapshot
// design: parallel readers must never observe a torn or partial state.
// Run under -race to catch any unsafe access.
func TestRegistry_ConcurrentReadDuringWrite(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	specs, err := LoadFileDescriptorSet(testDescBytes, nil)
	if err != nil {
		t.Fatalf("LoadFileDescriptorSet: %v", err)
	}
	r.Register(specs)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// 4 reader goroutines hammering LookupMethod.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				m := r.LookupMethod("usk.test.Greeter", "SayHello")
				if m != nil && m.Name != "SayHello" {
					t.Errorf("torn read: m.Name = %q", m.Name)
					return
				}
			}
		}()
	}

	// Writer churns: register / unregister / clear / re-register.
	for i := 0; i < 100; i++ {
		r.Unregister("usk.test.Greeter")
		r.Register(specs)
	}
	close(stop)
	wg.Wait()
}

func TestRegistry_NilSafe(t *testing.T) {
	t.Parallel()
	var r *Registry
	if r.LookupMethod("a", "b") != nil {
		t.Error("nil Registry.LookupMethod returned non-nil")
	}
	if len(r.ListServices()) != 0 {
		t.Error("nil Registry.ListServices returned non-empty")
	}
	if r.Unregister("x") {
		t.Error("nil Registry.Unregister returned true")
	}
	// Should not panic.
	r.Register([]*ServiceSpec{{Service: "x"}})
	r.Clear()
	if (r.Stats() != Stats{}) {
		t.Error("nil Registry.Stats returned non-zero")
	}
}

func TestRegistry_Stats(t *testing.T) {
	t.Parallel()
	r := NewRegistry()
	if s := r.Stats(); s.Services != 0 || s.Methods != 0 {
		t.Errorf("empty Stats = %+v, want zero", s)
	}
	specs, err := LoadFileDescriptorSet(testDescBytes, nil)
	if err != nil {
		t.Fatalf("LoadFileDescriptorSet: %v", err)
	}
	r.Register(specs)
	s := r.Stats()
	if s.Services != 2 {
		t.Errorf("Stats.Services = %d, want 2", s.Services)
	}
	// 2 methods on Greeter + 1 on Reflective = 3.
	if s.Methods != 3 {
		t.Errorf("Stats.Methods = %d, want 3", s.Methods)
	}
}
