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
