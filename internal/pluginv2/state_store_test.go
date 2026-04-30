package pluginv2

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"go.starlark.net/starlark"
)

func newTestScopeStore(t *testing.T, label string) (*scopeStore, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return newScopeStore(logger, label), &buf
}

func TestScopeStore_GetOrCreateThenRelease(t *testing.T) {
	s, _ := newTestScopeStore(t, "transaction")

	first := s.getOrCreate("conn-A", "flow-1")
	if first == nil {
		t.Fatal("getOrCreate returned nil for valid key")
	}
	again := s.getOrCreate("conn-A", "flow-1")
	if again != first {
		t.Fatal("getOrCreate did not return the same scope on second call")
	}
	if got := s.size(); got != 1 {
		t.Fatalf("size = %d, want 1", got)
	}

	s.release("conn-A", "flow-1")
	if got := s.size(); got != 0 {
		t.Fatalf("size after release = %d, want 0", got)
	}

	// Release of a missing key is a no-op (idempotency).
	s.release("conn-A", "flow-1")
	if got := s.size(); got != 0 {
		t.Fatalf("size after second release = %d, want 0", got)
	}
}

func TestScopeStore_ReleaseZeroesData(t *testing.T) {
	s, _ := newTestScopeStore(t, "stream")

	scope := s.getOrCreate("conn-A", "stream-1")
	_ = scope.set("k", starlark.String("v"))
	if got := scope.get("k"); got != starlark.String("v") {
		t.Fatalf("get = %v, want \"v\"", got)
	}

	s.release("conn-A", "stream-1")

	// A captured pointer should observe an empty dict; subsequent set/get
	// must not resurrect data.
	if got := scope.get("k"); got != starlark.None {
		t.Fatalf("get after release = %v, want None", got)
	}
	if err := scope.set("k", starlark.String("v2")); err != nil {
		t.Fatalf("set after release returned error: %v", err)
	}
	if got := scope.get("k"); got != starlark.None {
		t.Fatalf("get after set on released scope = %v, want None (writes must be dropped)", got)
	}
}

func TestScopeStore_ConnectionIsolation(t *testing.T) {
	s, _ := newTestScopeStore(t, "transaction")

	a := s.getOrCreate("conn-A", "shared-id")
	b := s.getOrCreate("conn-B", "shared-id")
	if a == b {
		t.Fatal("scopes for different ConnIDs aliased")
	}

	_ = a.set("k", starlark.String("from-A"))
	_ = b.set("k", starlark.String("from-B"))

	if got := a.get("k"); got != starlark.String("from-A") {
		t.Fatalf("conn-A read = %v, want \"from-A\"", got)
	}
	if got := b.get("k"); got != starlark.String("from-B") {
		t.Fatalf("conn-B read = %v, want \"from-B\"", got)
	}

	// Releasing one connection's scope must not touch the other's.
	s.release("conn-A", "shared-id")
	if got := b.get("k"); got != starlark.String("from-B") {
		t.Fatalf("conn-B read after conn-A release = %v, want \"from-B\"", got)
	}
}

func TestScopeStore_EmptyConnIDRejected(t *testing.T) {
	s, buf := newTestScopeStore(t, "transaction")

	if v := s.getOrCreate("", "flow-x"); v != nil {
		t.Fatalf("expected nil for empty ConnID, got %v", v)
	}
	if !strings.Contains(buf.String(), "refusing scope with empty ConnID") {
		t.Fatalf("expected Warn log, got %q", buf.String())
	}
	if got := s.size(); got != 0 {
		t.Fatalf("size after empty-ConnID call = %d, want 0", got)
	}
}

// TestScopeStore_EmptyIDRejected guards the symmetric counterpart to
// EmptyConnIDRejected: release() returns early on empty id, so an entry
// inserted with empty id would leak until Engine.Close. getOrCreate must
// reject it at the store boundary.
func TestScopeStore_EmptyIDRejected(t *testing.T) {
	s, buf := newTestScopeStore(t, "transaction")

	if v := s.getOrCreate("conn-A", ""); v != nil {
		t.Fatalf("expected nil for empty id, got %v", v)
	}
	if !strings.Contains(buf.String(), "refusing scope with empty id") {
		t.Fatalf("expected Warn log, got %q", buf.String())
	}
	if got := s.size(); got != 0 {
		t.Fatalf("size after empty-id call = %d, want 0", got)
	}
}

func TestScopeStore_OuterCap(t *testing.T) {
	// Construct a store whose cap we can hit cheaply by overriding the
	// underlying map directly in the test harness. Using the production
	// cap would require allocating 100k entries.
	s, buf := newTestScopeStore(t, "stream")

	// Pre-populate to one below the cap so the next insert succeeds…
	const localCap = scopeStoreCap
	if localCap < 4 {
		t.Skip("scopeStoreCap too small for this test")
	}

	// Use a cheaper proxy: drive the cap by fabricating entries directly
	// via getOrCreate up to a small synthetic limit defined inline.
	// Skipped if the production cap is enormous (the production run
	// exercises this path through the Warn log path).
	if scopeStoreCap > 1024 {
		// Production cap is too high to fill in a unit test. Drop in a
		// direct test of the cap-enforcement branch by injecting
		// synthetic entries.
		s.mu.Lock()
		for i := 0; i < scopeStoreCap; i++ {
			s.scopes[scopeKey{connID: "conn-fill", id: idForCap(i)}] = newScopedState()
		}
		s.mu.Unlock()
		if v := s.getOrCreate("conn-fill", "overflow"); v != nil {
			t.Fatalf("expected nil at cap, got %v", v)
		}
		if !strings.Contains(buf.String(), "scope store full") {
			t.Fatalf("expected cap Warn log, got %q", buf.String())
		}
		return
	}
}

func idForCap(i int) string {
	const digits = "0123456789abcdef"
	var b [16]byte
	for j := 0; j < 16; j++ {
		b[15-j] = digits[(i>>(j*4))&0xF]
	}
	return string(b[:])
}

func TestScopeStore_Purge(t *testing.T) {
	s, _ := newTestScopeStore(t, "transaction")

	scope := s.getOrCreate("conn-A", "flow-1")
	_ = scope.set("k", starlark.String("v"))

	s.purge()

	if got := s.size(); got != 0 {
		t.Fatalf("size after purge = %d, want 0", got)
	}
	if got := scope.get("k"); got != starlark.None {
		t.Fatalf("get on captured scope after purge = %v, want None", got)
	}
}

func TestScopedState_KeyCountCap(t *testing.T) {
	scope := newScopedState()
	for i := 0; i < maxScopedStateKeys; i++ {
		if err := scope.set(idForCap(i), starlark.MakeInt(i)); err != nil {
			t.Fatalf("unexpected error at key %d: %v", i, err)
		}
	}
	err := scope.set("overflow", starlark.String("x"))
	if err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("expected key cap error, got %v", err)
	}
}

func TestScopedState_ValueSizeCap(t *testing.T) {
	scope := newScopedState()
	big := strings.Repeat("a", maxScopedStateValueSize+1)
	if err := scope.set("k", starlark.String(big)); err == nil {
		t.Fatal("expected value size cap error for oversized String")
	}
	if err := scope.set("k", starlark.Bytes(big)); err == nil {
		t.Fatal("expected value size cap error for oversized Bytes")
	}
}

func TestScopedState_RejectsComplexValues(t *testing.T) {
	scope := newScopedState()
	if err := scope.set("k", starlark.NewList(nil)); err == nil {
		t.Fatal("expected error rejecting list value")
	}
	if err := scope.set("k", starlark.NewDict(0)); err == nil {
		t.Fatal("expected error rejecting dict value")
	}
}

func TestScopedState_ConcurrentAccess(t *testing.T) {
	scope := newScopedState()

	const writers = 8
	const reads = 256

	var wg sync.WaitGroup
	wg.Add(writers + writers)

	for i := 0; i < writers; i++ {
		go func(id int) {
			defer wg.Done()
			key := idForCap(id)
			for j := 0; j < reads; j++ {
				_ = scope.set(key, starlark.MakeInt(j))
			}
		}(i)
	}
	for i := 0; i < writers; i++ {
		go func(id int) {
			defer wg.Done()
			key := idForCap(id)
			for j := 0; j < reads; j++ {
				_ = scope.get(key)
			}
		}(i)
	}
	wg.Wait()

	keys := scope.keys()
	if len(keys) != writers {
		t.Fatalf("got %d keys, want %d", len(keys), writers)
	}
}
