package proxybuild

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// newTestManager constructs a Manager whose StackFactory builds a real
// proxybuild Stack via BuildLiveStack with the test-default Deps. The
// listener binds to 127.0.0.1:0 so each test gets a fresh ephemeral port.
func newTestManager(t *testing.T) *Manager {
	t.Helper()
	depsTpl := newTestDeps(t)
	mgr, err := NewManager(ManagerConfig{
		Logger: depsTpl.Logger,
		StackFactory: func(_ context.Context, name, addr string) (*Stack, error) {
			d := newTestDeps(t)
			d.ListenerName = name
			d.ListenAddr = addr
			return BuildLiveStack(context.Background(), d)
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return mgr
}

func TestManager_StartStopDefault(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := newTestManager(t)
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	running, addr := mgr.Status()
	if !running {
		t.Error("Status reports not running after Start")
	}
	if addr == "" {
		t.Error("Status returned empty addr")
	}
	if got := mgr.ListenerCount(); got != 1 {
		t.Errorf("ListenerCount = %d, want 1", got)
	}

	if err := mgr.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if got, _ := mgr.Status(); got {
		t.Error("Status still reports running after Stop")
	}
	if got := mgr.ListenerCount(); got != 0 {
		t.Errorf("ListenerCount = %d, want 0 after Stop", got)
	}
}

func TestManager_StartDefaultTwice_ReturnsErrAlreadyRunning(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := newTestManager(t)
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.StopAll(context.Background())

	err := mgr.Start(ctx, "127.0.0.1:0")
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("Start returned %v, want ErrAlreadyRunning", err)
	}
}

func TestManager_StartNamedTwice_ReturnsErrListenerExists(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := newTestManager(t)
	if err := mgr.StartNamed(ctx, "alpha", "127.0.0.1:0"); err != nil {
		t.Fatalf("StartNamed: %v", err)
	}
	defer mgr.StopAll(context.Background())

	err := mgr.StartNamed(ctx, "alpha", "127.0.0.1:0")
	if !errors.Is(err, ErrListenerExists) {
		t.Errorf("StartNamed returned %v, want ErrListenerExists", err)
	}
}

func TestManager_StopDefault_NotRunning_ReturnsErrNotRunning(t *testing.T) {
	mgr := newTestManager(t)
	err := mgr.Stop(context.Background())
	if !errors.Is(err, ErrNotRunning) {
		t.Errorf("Stop returned %v, want ErrNotRunning", err)
	}
}

func TestManager_StopNamedMissing_ReturnsErrListenerNotFound(t *testing.T) {
	mgr := newTestManager(t)
	err := mgr.StopNamed(context.Background(), "ghost")
	if !errors.Is(err, ErrListenerNotFound) {
		t.Errorf("StopNamed returned %v, want ErrListenerNotFound", err)
	}
}

func TestManager_MultipleListeners(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := newTestManager(t)
	for i, name := range []string{"a", "b", "c"} {
		if err := mgr.StartNamed(ctx, name, "127.0.0.1:0"); err != nil {
			t.Fatalf("StartNamed %s: %v", name, err)
		}
		if got, want := mgr.ListenerCount(), i+1; got != want {
			t.Errorf("after StartNamed %s: ListenerCount = %d, want %d", name, got, want)
		}
	}

	statuses := mgr.ListenerStatuses()
	if len(statuses) != 3 {
		t.Errorf("ListenerStatuses len = %d, want 3", len(statuses))
	}

	if err := mgr.StopAll(context.Background()); err != nil {
		t.Fatalf("StopAll: %v", err)
	}
	if got := mgr.ListenerCount(); got != 0 {
		t.Errorf("ListenerCount = %d, want 0 after StopAll", got)
	}
}

func TestManager_StopAll_NoListeners_ReturnsNil(t *testing.T) {
	mgr := newTestManager(t)
	if err := mgr.StopAll(context.Background()); err != nil {
		t.Errorf("StopAll on empty manager returned %v, want nil", err)
	}
}

func TestManager_DefaultListenAddr(t *testing.T) {
	// We cannot bind 127.0.0.1:8080 reliably in CI; verify the resolution
	// path by intercepting via the factory.
	var observedAddr string
	depsTpl := newTestDeps(t)
	mgr, err := NewManager(ManagerConfig{
		Logger: depsTpl.Logger,
		StackFactory: func(_ context.Context, name, addr string) (*Stack, error) {
			observedAddr = addr
			d := newTestDeps(t)
			d.ListenerName = name
			d.ListenAddr = "127.0.0.1:0" // override so the test does not actually bind 8080
			return BuildLiveStack(context.Background(), d)
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	if err := mgr.Start(context.Background(), ""); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.StopAll(context.Background())

	if observedAddr != defaultListenAddr {
		t.Errorf("factory received addr = %q, want %q", observedAddr, defaultListenAddr)
	}
}

func TestManager_SetMaxConnections_FanOut(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := newTestManager(t)
	if err := mgr.StartNamed(ctx, "a", "127.0.0.1:0"); err != nil {
		t.Fatalf("StartNamed a: %v", err)
	}
	if err := mgr.StartNamed(ctx, "b", "127.0.0.1:0"); err != nil {
		t.Fatalf("StartNamed b: %v", err)
	}
	defer mgr.StopAll(context.Background())

	mgr.SetMaxConnections(42)
	for _, name := range []string{"a", "b"} {
		l := mgr.Listener(name)
		if l == nil {
			t.Fatalf("Listener(%q) is nil", name)
		}
		if got := l.MaxConnections(); got != 42 {
			t.Errorf("listener %s MaxConnections = %d, want 42", name, got)
		}
	}
	if got := mgr.MaxConnections(); got != 42 {
		t.Errorf("Manager.MaxConnections = %d, want 42", got)
	}
}

func TestManager_SetMaxConnections_BeforeStart_AppliesToNewListener(t *testing.T) {
	mgr := newTestManager(t)
	mgr.SetMaxConnections(7)

	if err := mgr.Start(context.Background(), "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.StopAll(context.Background())

	if got := mgr.Listener(DefaultListenerName).MaxConnections(); got != 7 {
		t.Errorf("listener MaxConnections = %d, want 7", got)
	}
}

func TestManager_SetPeekTimeout_FanOut(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := newTestManager(t)
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.StopAll(context.Background())

	mgr.SetPeekTimeout(123 * time.Millisecond)
	if got := mgr.Listener(DefaultListenerName).PeekTimeout(); got != 123*time.Millisecond {
		t.Errorf("listener PeekTimeout = %v, want 123ms", got)
	}
	if got := mgr.PeekTimeout(); got != 123*time.Millisecond {
		t.Errorf("Manager.PeekTimeout = %v, want 123ms", got)
	}
}

func TestManager_UpstreamProxy_RoundTrip(t *testing.T) {
	mgr := newTestManager(t)
	mgr.SetUpstreamProxy("http://127.0.0.1:9999")
	if got := mgr.UpstreamProxy(); got != "http://127.0.0.1:9999" {
		t.Errorf("UpstreamProxy = %q, want round-trip", got)
	}
	mgr.SetUpstreamProxy("")
	if got := mgr.UpstreamProxy(); got != "" {
		t.Errorf("UpstreamProxy after clear = %q, want empty", got)
	}
}

func TestManager_TCPForwards_StubReturnsNotSupported(t *testing.T) {
	mgr := newTestManager(t)
	if err := mgr.StartTCPForwards(context.Background(), nil); !errors.Is(err, ErrTCPForwardsNotSupported) {
		t.Errorf("StartTCPForwards returned %v, want ErrTCPForwardsNotSupported", err)
	}
	if got := mgr.TCPForwardAddrs(); got != nil {
		t.Errorf("TCPForwardAddrs = %v, want nil", got)
	}
}

func TestManager_Uptime_DefaultListenerOnly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := newTestManager(t)
	if got := mgr.Uptime(); got != 0 {
		t.Errorf("Uptime before start = %v, want 0", got)
	}
	if err := mgr.StartNamed(ctx, "non-default", "127.0.0.1:0"); err != nil {
		t.Fatalf("StartNamed: %v", err)
	}
	defer mgr.StopAll(context.Background())
	if got := mgr.Uptime(); got != 0 {
		t.Errorf("Uptime with only non-default listener = %v, want 0", got)
	}
}

func TestManager_StartNamed_BindFailure_Propagates(t *testing.T) {
	// Reserve a port so the manager's bind attempt collides.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	mgr := newTestManager(t)
	err = mgr.StartNamed(context.Background(), "collide", addr)
	if err == nil {
		t.Fatal("expected error binding to occupied port, got nil")
	}
	if got := mgr.ListenerCount(); got != 0 {
		t.Errorf("ListenerCount after failed Start = %d, want 0", got)
	}
}

func TestManager_FactoryError_Propagates(t *testing.T) {
	wantErr := errors.New("synthetic")
	mgr, err := NewManager(ManagerConfig{
		Logger: silentLogger(),
		StackFactory: func(_ context.Context, _, _ string) (*Stack, error) {
			return nil, wantErr
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	got := mgr.Start(context.Background(), "127.0.0.1:0")
	if !errors.Is(got, wantErr) {
		t.Errorf("Start returned %v, want wraps %v", got, wantErr)
	}
}

func TestNewManager_RequiresFactory(t *testing.T) {
	_, err := NewManager(ManagerConfig{Logger: silentLogger()})
	if err == nil {
		t.Fatal("expected error for nil StackFactory, got nil")
	}
}

func TestManager_ListenerStatuses_NilWhenEmpty(t *testing.T) {
	mgr := newTestManager(t)
	if got := mgr.ListenerStatuses(); got != nil {
		t.Errorf("ListenerStatuses on empty manager = %v, want nil", got)
	}
}

func TestManager_ListenerStatuses_AggregatesActiveConnections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := newTestManager(t)
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.StopAll(context.Background())

	if got := mgr.ActiveConnections(); got != 0 {
		t.Errorf("ActiveConnections (idle) = %d, want 0", got)
	}
}

// TestManager_ConcurrentStartStop guards against race regressions in the
// listeners map under simultaneous Start/Stop calls. Run with -race.
func TestManager_ConcurrentStartStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := newTestManager(t)
	const n = 8
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("worker-%d", i)
			if err := mgr.StartNamed(ctx, name, "127.0.0.1:0"); err != nil {
				t.Errorf("StartNamed %s: %v", name, err)
				return
			}
			if err := mgr.StopNamed(context.Background(), name); err != nil {
				t.Errorf("StopNamed %s: %v", name, err)
			}
		}()
	}
	wg.Wait()
	if got := mgr.ListenerCount(); got != 0 {
		t.Errorf("after concurrent start/stop: ListenerCount = %d, want 0", got)
	}
}
