package plugin

import (
	"sync/atomic"
	"testing"

	"go.starlark.net/starlark"
)

func TestProxyModule_Shutdown(t *testing.T) {
	var called atomic.Bool
	var gotReason string
	shutdownFn := func(reason string) {
		called.Store(true)
		gotReason = reason
	}

	mod := newProxyModule(shutdownFn)

	thread := &starlark.Thread{Name: "test"}
	shutdownBuiltin := mod.Members["shutdown"]

	_, err := starlark.Call(thread, shutdownBuiltin, starlark.Tuple{starlark.String("too many errors")}, nil)
	if err != nil {
		t.Fatalf("proxy.shutdown: %v", err)
	}

	if !called.Load() {
		t.Error("shutdown function was not called")
	}
	if gotReason != "too many errors" {
		t.Errorf("reason = %q, want %q", gotReason, "too many errors")
	}
}

func TestProxyModule_Shutdown_EmptyReason(t *testing.T) {
	mod := newProxyModule(nil)

	thread := &starlark.Thread{Name: "test"}
	shutdownBuiltin := mod.Members["shutdown"]

	_, err := starlark.Call(thread, shutdownBuiltin, starlark.Tuple{starlark.String("")}, nil)
	if err == nil {
		t.Error("proxy.shutdown with empty reason should return error")
	}
}

func TestProxyModule_Shutdown_NilCallback(t *testing.T) {
	// Should not panic even with nil shutdown function.
	mod := newProxyModule(nil)

	thread := &starlark.Thread{Name: "test"}
	shutdownBuiltin := mod.Members["shutdown"]

	_, err := starlark.Call(thread, shutdownBuiltin, starlark.Tuple{starlark.String("test reason")}, nil)
	if err != nil {
		t.Fatalf("proxy.shutdown with nil callback: %v", err)
	}
}

func TestProxyModule_Shutdown_NoArgs(t *testing.T) {
	mod := newProxyModule(nil)

	thread := &starlark.Thread{Name: "test"}
	shutdownBuiltin := mod.Members["shutdown"]

	_, err := starlark.Call(thread, shutdownBuiltin, starlark.Tuple{}, nil)
	if err == nil {
		t.Error("proxy.shutdown without args should return error")
	}
}

func TestEngine_SetShutdownFunc(t *testing.T) {
	engine := NewEngine(nil)

	var called atomic.Bool
	engine.SetShutdownFunc(func(_ string) {
		called.Store(true)
	})

	if engine.shutdownFn == nil {
		t.Error("shutdownFn is nil after SetShutdownFunc")
	}
}
