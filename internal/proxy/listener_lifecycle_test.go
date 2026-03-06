package proxy_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// hookRecorder records all dispatched hooks for test assertions.
type hookRecorder struct {
	mu      sync.Mutex
	calls   []hookCall
	handler plugin.HookHandler
}

type hookCall struct {
	Hook plugin.Hook
	Data map[string]any
}

func newHookRecorder() *hookRecorder {
	r := &hookRecorder{}
	r.handler = func(_ context.Context, data map[string]any) (*plugin.HookResult, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		// Store a shallow copy of data to avoid mutation from subsequent calls.
		dataCopy := make(map[string]any, len(data))
		for k, v := range data {
			dataCopy[k] = v
		}
		r.calls = append(r.calls, hookCall{Data: dataCopy})
		return &plugin.HookResult{Action: plugin.ActionContinue}, nil
	}
	return r
}

func (r *hookRecorder) getCalls() []hookCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]hookCall, len(r.calls))
	copy(out, r.calls)
	return out
}

func (r *hookRecorder) waitForCalls(n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		count := len(r.calls)
		r.mu.Unlock()
		if count >= n {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// setupEngineWithHooks creates a plugin.Engine with hook handlers registered.
func setupEngineWithHooks(recorders map[plugin.Hook]*hookRecorder) *plugin.Engine {
	engine := plugin.NewEngine(nil)
	for hook, rec := range recorders {
		engine.Registry().Register("test-plugin", hook, rec.handler, plugin.OnErrorSkip)
	}
	return engine
}

func TestListener_OnConnect_Dispatched(t *testing.T) {
	rec := newHookRecorder()
	engine := setupEngineWithHooks(map[plugin.Hook]*hookRecorder{
		plugin.HookOnConnect: rec,
	})

	handler := &slowHandler{delay: 50 * time.Millisecond, name: "test"}
	detector := &slowDetector{handler: handler}
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   testutil.DiscardLogger(),
	})
	listener.SetPluginEngine(engine)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- listener.Start(ctx) }()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("listener not ready")
	}

	conn := dialAndSend(t, listener.Addr())
	defer conn.Close()

	if !rec.waitForCalls(1, 2*time.Second) {
		t.Fatal("on_connect hook was not dispatched")
	}

	calls := rec.getCalls()
	if calls[0].Data["event"] != "connect" {
		t.Errorf("event = %v, want connect", calls[0].Data["event"])
	}

	connInfo, ok := calls[0].Data["conn_info"].(map[string]any)
	if !ok {
		t.Fatal("conn_info is not a map")
	}
	if connInfo["client_addr"] == "" {
		t.Error("client_addr should not be empty")
	}
}

func TestListener_OnDisconnect_Dispatched(t *testing.T) {
	rec := newHookRecorder()
	engine := setupEngineWithHooks(map[plugin.Hook]*hookRecorder{
		plugin.HookOnDisconnect: rec,
	})

	handler := &slowHandler{delay: 50 * time.Millisecond, name: "test"}
	detector := &slowDetector{handler: handler}
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   testutil.DiscardLogger(),
	})
	listener.SetPluginEngine(engine)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- listener.Start(ctx) }()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("listener not ready")
	}

	conn := dialAndSend(t, listener.Addr())
	conn.Close()

	// Wait for the handler to finish (50ms delay) and on_disconnect to fire.
	if !rec.waitForCalls(1, 2*time.Second) {
		t.Fatal("on_disconnect hook was not dispatched")
	}

	calls := rec.getCalls()
	if calls[0].Data["event"] != "disconnect" {
		t.Errorf("event = %v, want disconnect", calls[0].Data["event"])
	}

	durationMs, ok := calls[0].Data["duration_ms"].(int64)
	if !ok {
		t.Fatal("duration_ms is not an int64")
	}
	if durationMs < 0 {
		t.Errorf("duration_ms = %d, want >= 0", durationMs)
	}
}

func TestListener_OnConnectAndDisconnect_BothDispatched(t *testing.T) {
	connectRec := newHookRecorder()
	disconnectRec := newHookRecorder()
	engine := setupEngineWithHooks(map[plugin.Hook]*hookRecorder{
		plugin.HookOnConnect:    connectRec,
		plugin.HookOnDisconnect: disconnectRec,
	})

	handler := &slowHandler{delay: 50 * time.Millisecond, name: "test"}
	detector := &slowDetector{handler: handler}
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   testutil.DiscardLogger(),
	})
	listener.SetPluginEngine(engine)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- listener.Start(ctx) }()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("listener not ready")
	}

	conn := dialAndSend(t, listener.Addr())
	conn.Close()

	// Wait for both hooks to fire.
	if !connectRec.waitForCalls(1, 2*time.Second) {
		t.Fatal("on_connect hook was not dispatched")
	}
	if !disconnectRec.waitForCalls(1, 2*time.Second) {
		t.Fatal("on_disconnect hook was not dispatched")
	}

	connectCalls := connectRec.getCalls()
	disconnectCalls := disconnectRec.getCalls()

	if connectCalls[0].Data["event"] != "connect" {
		t.Errorf("connect event = %v, want connect", connectCalls[0].Data["event"])
	}
	if disconnectCalls[0].Data["event"] != "disconnect" {
		t.Errorf("disconnect event = %v, want disconnect", disconnectCalls[0].Data["event"])
	}
}

func TestListener_NilPluginEngine_NoError(t *testing.T) {
	// Verify that hooks are gracefully skipped when pluginEngine is nil.
	handler := &slowHandler{delay: 50 * time.Millisecond, name: "test"}
	detector := &slowDetector{handler: handler}
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   testutil.DiscardLogger(),
	})
	// Do NOT call SetPluginEngine — pluginEngine is nil.

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- listener.Start(ctx) }()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("listener not ready")
	}

	conn := dialAndSend(t, listener.Addr())
	defer conn.Close()

	// Wait for handler to be entered (proves the connection was processed without panic).
	if !waitForEntered(handler, 1, 2*time.Second) {
		t.Fatal("handler was not entered")
	}
}

func TestListener_SetPluginEngine_Getter(t *testing.T) {
	handler := &slowHandler{delay: 0, name: "test"}
	detector := &slowDetector{handler: handler}
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   testutil.DiscardLogger(),
	})

	if listener.PluginEngine() != nil {
		t.Error("PluginEngine() should be nil initially")
	}

	engine := plugin.NewEngine(nil)
	listener.SetPluginEngine(engine)

	if listener.PluginEngine() != engine {
		t.Error("PluginEngine() should return the set engine")
	}
}

func TestListener_HookError_FailOpen(t *testing.T) {
	// Register a hook that always returns an error via OnErrorAbort.
	// The connection should still be processed (fail-open).
	engine := plugin.NewEngine(nil)
	engine.Registry().Register("error-plugin", plugin.HookOnConnect,
		func(_ context.Context, _ map[string]any) (*plugin.HookResult, error) {
			return nil, &plugin.DispatchError{
				PluginName: "error-plugin",
				Hook:       plugin.HookOnConnect,
				Err:        net.ErrClosed,
			}
		}, plugin.OnErrorAbort)

	handler := &slowHandler{delay: 50 * time.Millisecond, name: "test"}
	detector := &slowDetector{handler: handler}
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   testutil.DiscardLogger(),
	})
	listener.SetPluginEngine(engine)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- listener.Start(ctx) }()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("listener not ready")
	}

	conn := dialAndSend(t, listener.Addr())
	defer conn.Close()

	// Handler should still be entered even though on_connect returned an error.
	if !waitForEntered(handler, 1, 2*time.Second) {
		t.Fatal("handler was not entered despite hook error (fail-open)")
	}
}

func TestListener_MultipleConnections_MultipleHookCalls(t *testing.T) {
	connectRec := newHookRecorder()
	engine := setupEngineWithHooks(map[plugin.Hook]*hookRecorder{
		plugin.HookOnConnect: connectRec,
	})

	handler := &slowHandler{delay: 50 * time.Millisecond, name: "test"}
	detector := &slowDetector{handler: handler}
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   testutil.DiscardLogger(),
	})
	listener.SetPluginEngine(engine)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- listener.Start(ctx) }()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("listener not ready")
	}

	const numConns = 3
	conns := make([]net.Conn, numConns)
	for i := range numConns {
		conns[i] = dialAndSend(t, listener.Addr())
		defer conns[i].Close()
	}

	if !connectRec.waitForCalls(numConns, 2*time.Second) {
		t.Fatalf("expected %d on_connect calls, got %d", numConns, len(connectRec.getCalls()))
	}
}
