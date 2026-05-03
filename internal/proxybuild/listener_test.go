package proxybuild

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// TestListener_PluginV2EngineNil_AccessorReturnsNil documents the no-engine
// path: PluginV2Engine() must not panic and returns nil.
func TestListener_PluginV2EngineNil_AccessorReturnsNil(t *testing.T) {
	l := &Listener{}
	if got := l.PluginV2Engine(); got != nil {
		t.Errorf("PluginV2Engine on empty Listener = %v, want nil", got)
	}
	// Nil receiver guard.
	var nilL *Listener
	if got := nilL.PluginV2Engine(); got != nil {
		t.Errorf("PluginV2Engine on nil Listener = %v, want nil", got)
	}
}

// TestListener_WrapHandler_NilInner_ReturnsNil mirrors the no-handler
// behavior of FullListener.handlerFor: a nil inner means the listener
// has no handler for that protocol kind, and the wrapped handler must
// also be nil.
func TestListener_WrapHandler_NilInner_ReturnsNil(t *testing.T) {
	l := &Listener{engine: pluginv2.NewEngine(silentLogger())}
	if got := l.wrapHandler(nil); got != nil {
		t.Error("wrapHandler(nil) should return nil")
	}
}

// TestListener_WrapHandler_NoEngine_ReturnsInner ensures the wrapper is
// a pure pass-through when no engine is wired (zero overhead).
func TestListener_WrapHandler_NoEngine_ReturnsInner(t *testing.T) {
	l := &Listener{logger: silentLogger()}
	called := false
	inner := func(_ context.Context, _ *connector.PeekConn) error {
		called = true
		return nil
	}
	wrapped := l.wrapHandler(inner)
	if wrapped == nil {
		t.Fatal("wrapHandler returned nil with non-nil inner and nil engine")
	}
	if err := wrapped(context.Background(), nil); err != nil {
		t.Errorf("wrapped handler returned %v, want nil", err)
	}
	if !called {
		t.Error("inner handler was not called")
	}
}

// TestListener_WrapHandler_EngineWithoutHooks_CallsInner ensures the
// wrapper invokes the inner handler when no hooks are registered (engine
// bound but no plugins loaded).
func TestListener_WrapHandler_EngineWithoutHooks_CallsInner(t *testing.T) {
	engine := pluginv2.NewEngine(silentLogger())
	l := &Listener{
		engine: engine,
		name:   "test",
		logger: silentLogger(),
	}

	var calls atomic.Int32
	inner := func(_ context.Context, _ *connector.PeekConn) error {
		calls.Add(1)
		return nil
	}
	wrapped := l.wrapHandler(inner)
	if wrapped == nil {
		t.Fatal("wrapHandler returned nil")
	}

	if err := wrapped(context.Background(), nil); err != nil {
		t.Errorf("wrapped handler returned %v, want nil", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("inner handler call count = %d, want 1", got)
	}
}

// TestListener_WrapHandler_PropagatesInnerError ensures errors from the
// inner handler are returned as-is.
func TestListener_WrapHandler_PropagatesInnerError(t *testing.T) {
	l := &Listener{
		engine: pluginv2.NewEngine(silentLogger()),
		name:   "test",
		logger: silentLogger(),
	}
	want := errors.New("synthetic")
	inner := func(_ context.Context, _ *connector.PeekConn) error { return want }

	wrapped := l.wrapHandler(inner)
	if got := wrapped(context.Background(), nil); !errors.Is(got, want) {
		t.Errorf("wrapped handler returned %v, want %v", got, want)
	}
}
