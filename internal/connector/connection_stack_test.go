package connector

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// mockLayer is a minimal Layer implementation for testing.
type mockLayer struct {
	id       string
	closed   bool
	mu       sync.Mutex
	closeErr error
	ch       chan layer.Channel
}

func newMockLayer(id string) *mockLayer {
	ch := make(chan layer.Channel, 1)
	ml := &mockLayer{id: id, ch: ch}
	ch <- &mockChannel{streamID: id + "-ch"}
	close(ch)
	return ml
}

func (m *mockLayer) Channels() <-chan layer.Channel { return m.ch }

func (m *mockLayer) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return m.closeErr
}

func (m *mockLayer) isClosed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closed
}

// mockChannel is a minimal Channel implementation for testing.
type mockChannel struct {
	streamID string

	termInit sync.Once
	termDone chan struct{}
}

func (c *mockChannel) ensureTerm() {
	c.termInit.Do(func() { c.termDone = make(chan struct{}) })
}

func (c *mockChannel) StreamID() string                                   { return c.streamID }
func (c *mockChannel) Next(_ context.Context) (*envelope.Envelope, error) { return nil, nil }
func (c *mockChannel) Send(_ context.Context, _ *envelope.Envelope) error { return nil }
func (c *mockChannel) Close() error                                       { return nil }
func (c *mockChannel) Closed() <-chan struct{}                            { c.ensureTerm(); return c.termDone }
func (c *mockChannel) Err() error                                         { return nil }

func TestConnectionStack_PushAndTopmost(t *testing.T) {
	stack := NewConnectionStack("conn-1")

	if stack.ClientTopmost() != nil {
		t.Error("empty stack should have nil ClientTopmost")
	}
	if stack.UpstreamTopmost() != nil {
		t.Error("empty stack should have nil UpstreamTopmost")
	}

	l1 := newMockLayer("client-l1")
	l2 := newMockLayer("client-l2")
	stack.PushClient(l1)
	stack.PushClient(l2)

	if stack.ClientTopmost() != l2 {
		t.Error("ClientTopmost should be the last pushed layer")
	}

	ul := newMockLayer("upstream-l1")
	stack.PushUpstream(ul)
	if stack.UpstreamTopmost() != ul {
		t.Error("UpstreamTopmost should be the pushed layer")
	}
}

func TestConnectionStack_ReplaceClientTop(t *testing.T) {
	stack := NewConnectionStack("conn-1")

	l1 := newMockLayer("original")
	stack.PushClient(l1)

	l2 := newMockLayer("replacement")
	old := stack.ReplaceClientTop(l2)

	if old != l1 {
		t.Error("ReplaceClientTop should return the old layer")
	}
	if stack.ClientTopmost() != l2 {
		t.Error("ClientTopmost should be the replacement after swap")
	}
}

func TestConnectionStack_ReplaceUpstreamTop(t *testing.T) {
	stack := NewConnectionStack("conn-1")

	l1 := newMockLayer("original")
	stack.PushUpstream(l1)

	l2 := newMockLayer("replacement")
	old := stack.ReplaceUpstreamTop(l2)

	if old != l1 {
		t.Error("ReplaceUpstreamTop should return the old layer")
	}
	if stack.UpstreamTopmost() != l2 {
		t.Error("UpstreamTopmost should be the replacement after swap")
	}
}

func TestConnectionStack_ReplaceOnEmpty(t *testing.T) {
	stack := NewConnectionStack("conn-1")

	l := newMockLayer("new")
	old := stack.ReplaceClientTop(l)

	if old != nil {
		t.Error("ReplaceClientTop on empty stack should return nil")
	}
	if stack.ClientTopmost() != l {
		t.Error("ClientTopmost should be set after Replace on empty")
	}
}

func TestConnectionStack_Close_ReverseOrder(t *testing.T) {
	stack := NewConnectionStack("conn-1")

	l1 := newMockLayer("c1")
	l2 := newMockLayer("c2")
	l3 := newMockLayer("c3")

	stack.PushClient(l1)
	stack.PushClient(l2)
	stack.PushClient(l3)

	err := stack.Close()
	if err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}

	// All layers should be closed
	for _, ml := range []*mockLayer{l1, l2, l3} {
		if !ml.isClosed() {
			t.Errorf("layer %s should be closed", ml.id)
		}
	}

	// After close, topmost should be nil
	if stack.ClientTopmost() != nil {
		t.Error("ClientTopmost should be nil after Close")
	}
}

func TestConnectionStack_Close_PropagatesError(t *testing.T) {
	stack := NewConnectionStack("conn-1")

	l1 := newMockLayer("ok")
	l2 := newMockLayer("fail")
	l2.closeErr = errors.New("close failed")

	stack.PushClient(l1)
	stack.PushClient(l2)

	err := stack.Close()
	if err == nil {
		t.Fatal("Close() should return error when a layer fails")
	}
	if !errors.Is(err, l2.closeErr) {
		t.Errorf("Close() error should wrap the layer error, got: %v", err)
	}
}

func TestConnectionStack_ConnID(t *testing.T) {
	stack := NewConnectionStack("test-conn-42")
	if stack.ConnID != "test-conn-42" {
		t.Errorf("ConnID = %q, want %q", stack.ConnID, "test-conn-42")
	}
}

// --- USK-765: per-stream sub-stack overlay (RFC-001 §3.4.1) ---

// TestConnectionStack_RegisterStreamSubStack_HappyPath verifies that
// registration installs the per-stream client / upstream Layer pair on
// the streamSubStacks map and that *ForStream lookups resolve to those
// Layers (not the connection-level Topmost).
func TestConnectionStack_RegisterStreamSubStack_HappyPath(t *testing.T) {
	stack := NewConnectionStack("conn-1")

	connClient := newMockLayer("conn-client")
	connUpstream := newMockLayer("conn-upstream")
	stack.PushClient(connClient)
	stack.PushUpstream(connUpstream)

	swapClient := newMockLayer("swap-client")
	swapUpstream := newMockLayer("swap-upstream")

	if err := stack.RegisterStreamSubStack("stream-A", swapClient, swapUpstream); err != nil {
		t.Fatalf("RegisterStreamSubStack: %v", err)
	}
	if !stack.HasStreamSubStack("stream-A") {
		t.Error("HasStreamSubStack should report true after registration")
	}

	// *ForStream returns the swapped Layer for the registered stream.
	if got := stack.ClientTopmostForStream("stream-A"); got != swapClient {
		t.Errorf("ClientTopmostForStream(stream-A) = %v, want %v", got, swapClient)
	}
	if got := stack.UpstreamTopmostForStream("stream-A"); got != swapUpstream {
		t.Errorf("UpstreamTopmostForStream(stream-A) = %v, want %v", got, swapUpstream)
	}

	// Connection-level accessors are unaffected (RFC-001 §3.4.1
	// multiplex isolation).
	if got := stack.ClientTopmost(); got != connClient {
		t.Errorf("ClientTopmost = %v, want connection-level layer", got)
	}
	if got := stack.UpstreamTopmost(); got != connUpstream {
		t.Errorf("UpstreamTopmost = %v, want connection-level layer", got)
	}
}

// TestConnectionStack_StreamSubStack_MultiplexIsolation is the normative
// MUST from RFC-001 §3.4.1: registering a sub-stack on stream A MUST NOT
// affect stream B. Sibling-stream lookups MUST keep flowing through the
// connection-level h2 Layer.
func TestConnectionStack_StreamSubStack_MultiplexIsolation(t *testing.T) {
	stack := NewConnectionStack("conn-multiplex")

	connClient := newMockLayer("conn-client")
	connUpstream := newMockLayer("conn-upstream")
	stack.PushClient(connClient)
	stack.PushUpstream(connUpstream)

	swapClient := newMockLayer("swap-A-client")
	swapUpstream := newMockLayer("swap-A-upstream")
	if err := stack.RegisterStreamSubStack("stream-A", swapClient, swapUpstream); err != nil {
		t.Fatalf("RegisterStreamSubStack(stream-A): %v", err)
	}

	// Stream A: routed through the swap.
	if got := stack.ClientTopmostForStream("stream-A"); got != swapClient {
		t.Errorf("stream-A ClientTopmostForStream = %v, want swap", got)
	}

	// Stream B (sibling): MUST resolve to the connection-level Layer,
	// not the swap. This is the multiplex-isolation invariant.
	if got := stack.ClientTopmostForStream("stream-B"); got != connClient {
		t.Errorf("stream-B ClientTopmostForStream = %v, want connection-level layer (multiplex-isolation MUST violated)", got)
	}
	if got := stack.UpstreamTopmostForStream("stream-B"); got != connUpstream {
		t.Errorf("stream-B UpstreamTopmostForStream = %v, want connection-level layer", got)
	}

	// Stream C (also unregistered): same fallback semantics.
	if got := stack.ClientTopmostForStream("stream-C"); got != connClient {
		t.Errorf("stream-C ClientTopmostForStream = %v, want connection-level layer", got)
	}

	// Empty streamID falls back to connection-level (defensive: an
	// orchestrator that misconfigures the lookup must not accidentally
	// hit the swap).
	if got := stack.ClientTopmostForStream(""); got != connClient {
		t.Errorf("empty streamID ClientTopmostForStream = %v, want connection-level layer", got)
	}

	// Releasing stream-A's sub-stack must not affect any stream-B lookup
	// nor the connection-level Layers.
	if err := stack.ReleaseStreamSubStack("stream-A"); err != nil {
		t.Fatalf("ReleaseStreamSubStack: %v", err)
	}
	if !swapClient.isClosed() {
		t.Error("ReleaseStreamSubStack should close the per-stream client Layer")
	}
	if !swapUpstream.isClosed() {
		t.Error("ReleaseStreamSubStack should close the per-stream upstream Layer")
	}
	if connClient.isClosed() || connUpstream.isClosed() {
		t.Error("ReleaseStreamSubStack must NOT close connection-level Layers")
	}
	if stack.HasStreamSubStack("stream-A") {
		t.Error("HasStreamSubStack should report false after release")
	}

	// Post-release, stream-A also falls back to the connection-level
	// layer (RFC-001 §3.4.1 lifetime MUST).
	if got := stack.ClientTopmostForStream("stream-A"); got != connClient {
		t.Errorf("post-release stream-A ClientTopmostForStream = %v, want connection-level layer", got)
	}
}

// TestConnectionStack_RegisterStreamSubStack_DoubleRegisterRejected
// covers the single-writer invariant: a second RegisterStreamSubStack on
// the same id must return an error without mutating state.
func TestConnectionStack_RegisterStreamSubStack_DoubleRegisterRejected(t *testing.T) {
	stack := NewConnectionStack("conn-dup")

	first := newMockLayer("first-client")
	if err := stack.RegisterStreamSubStack("stream-X", first, newMockLayer("first-upstream")); err != nil {
		t.Fatalf("first RegisterStreamSubStack: %v", err)
	}

	second := newMockLayer("second-client")
	if err := stack.RegisterStreamSubStack("stream-X", second, newMockLayer("second-upstream")); err == nil {
		t.Error("second RegisterStreamSubStack on the same id should error")
	}
	// State MUST NOT mutate: the first registration is still authoritative.
	if got := stack.ClientTopmostForStream("stream-X"); got != first {
		t.Errorf("after double-register attempt, ClientTopmostForStream = %v, want first registration", got)
	}
}

// TestConnectionStack_RegisterStreamSubStack_GuardArgs ensures the
// constructor rejects nil Layers and empty streamIDs without mutating
// state.
func TestConnectionStack_RegisterStreamSubStack_GuardArgs(t *testing.T) {
	stack := NewConnectionStack("conn-guard")

	if err := stack.RegisterStreamSubStack("", newMockLayer("c"), newMockLayer("u")); err == nil {
		t.Error("empty streamID should error")
	}
	if err := stack.RegisterStreamSubStack("s", nil, newMockLayer("u")); err == nil {
		t.Error("nil client should error")
	}
	if err := stack.RegisterStreamSubStack("s", newMockLayer("c"), nil); err == nil {
		t.Error("nil upstream should error")
	}
	if stack.HasStreamSubStack("s") {
		t.Error("guard failures should not register the sub-stack")
	}
}

// TestConnectionStack_ReleaseStreamSubStack_IdempotentAndUnknownNoop
// verifies that releasing an unknown id is a no-op (returns nil) and
// that releasing the same id twice is also safe.
func TestConnectionStack_ReleaseStreamSubStack_IdempotentAndUnknownNoop(t *testing.T) {
	stack := NewConnectionStack("conn-rel")

	// Unknown id = no-op.
	if err := stack.ReleaseStreamSubStack("never-registered"); err != nil {
		t.Errorf("Release of unknown id should be no-op, got %v", err)
	}

	c := newMockLayer("c")
	u := newMockLayer("u")
	if err := stack.RegisterStreamSubStack("s", c, u); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := stack.ReleaseStreamSubStack("s"); err != nil {
		t.Fatalf("first Release: %v", err)
	}
	// Second release should be a no-op (the id is gone).
	if err := stack.ReleaseStreamSubStack("s"); err != nil {
		t.Errorf("second Release on already-released id: %v", err)
	}
}

// TestConnectionStack_Close_ReleasesUnreleasedSubStacks verifies the
// defensive cascade in Close: any sub-stack still registered at Close
// time has its Layers closed (so a Close path that bypassed the
// stream-terminal release MUST not leak Layer resources).
func TestConnectionStack_Close_ReleasesUnreleasedSubStacks(t *testing.T) {
	stack := NewConnectionStack("conn-close-cascade")

	connClient := newMockLayer("conn-client")
	connUpstream := newMockLayer("conn-upstream")
	stack.PushClient(connClient)
	stack.PushUpstream(connUpstream)

	swapClient := newMockLayer("swap-client")
	swapUpstream := newMockLayer("swap-upstream")
	if err := stack.RegisterStreamSubStack("orphan", swapClient, swapUpstream); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := stack.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !swapClient.isClosed() {
		t.Error("Close should close orphaned sub-stack client")
	}
	if !swapUpstream.isClosed() {
		t.Error("Close should close orphaned sub-stack upstream")
	}
	// HasStreamSubStack reads under the same mutex Close uses; after
	// Close cleared the map, the id is gone.
	if stack.HasStreamSubStack("orphan") {
		t.Error("Close should clear streamSubStacks")
	}
}
