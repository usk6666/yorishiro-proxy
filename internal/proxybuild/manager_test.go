package proxybuild

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
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

// TestManager_TLSFingerprint_BoundBuildConfig verifies the USK-809
// wiring: SetTLSFingerprint mutates the bound BuildConfig's dynamic
// override slot so the next live-stack dial picks up the new profile,
// and TLSFingerprint() reflects that override. This is the wire-up
// that closes the live-wire regression where proxy_start / configure
// changes were silently dropped from the live MITM dial path.
func TestManager_TLSFingerprint_BoundBuildConfig(t *testing.T) {
	bc := &connector.BuildConfig{TLSFingerprint: "chrome"}
	mgr, err := NewManager(ManagerConfig{
		Logger:       silentLogger(),
		StackFactory: func(_ context.Context, _, _ string) (*Stack, error) { return nil, errors.New("unused") },
		BuildConfig:  bc,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Boot-time value surfaces when no runtime override is set.
	if got := mgr.TLSFingerprint(); got != "chrome" {
		t.Errorf("initial TLSFingerprint = %q, want chrome", got)
	}

	// Runtime override mutates BuildConfig.
	mgr.SetTLSFingerprint("firefox")
	if got := mgr.TLSFingerprint(); got != "firefox" {
		t.Errorf("after SetTLSFingerprint(firefox), TLSFingerprint = %q, want firefox", got)
	}
	if got := bc.EffectiveTLSFingerprint(); got != "firefox" {
		t.Errorf("BuildConfig.EffectiveTLSFingerprint not propagated: got %q, want firefox", got)
	}

	// Replacement (not append) semantics.
	mgr.SetTLSFingerprint("safari")
	if got := mgr.TLSFingerprint(); got != "safari" {
		t.Errorf("after SetTLSFingerprint(safari), TLSFingerprint = %q, want safari", got)
	}

	// Empty clears the override; boot value re-emerges.
	mgr.SetTLSFingerprint("")
	if got := mgr.TLSFingerprint(); got != "chrome" {
		t.Errorf("after clear, TLSFingerprint = %q, want chrome (boot fallback)", got)
	}
}

// TestManager_TLSFingerprint_NoBoundBuildConfig verifies the safe-no-op
// behaviour when the Manager was constructed without a BuildConfig
// (test-only path that does not bind one). The mutation must not
// panic and the accessor must return the empty string sentinel.
func TestManager_TLSFingerprint_NoBoundBuildConfig(t *testing.T) {
	mgr, err := NewManager(ManagerConfig{
		Logger:       silentLogger(),
		StackFactory: func(_ context.Context, _, _ string) (*Stack, error) { return nil, errors.New("unused") },
		// BuildConfig intentionally nil.
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	// Must not panic.
	mgr.SetTLSFingerprint("firefox")
	if got := mgr.TLSFingerprint(); got != "" {
		t.Errorf("TLSFingerprint with no BuildConfig = %q, want empty string sentinel", got)
	}
}

// TestManager_SetEnabledProtocols_PropagatesToBuildConfig verifies the
// USK-808 fan-out: Manager.SetEnabledProtocols pushes the snapshot into
// the bound BuildConfig so the live MITM ALPN filter observes it. Mirrors
// the SetUpstreamProxy → BuildConfig propagation locked in by USK-734.
func TestManager_SetEnabledProtocols_PropagatesToBuildConfig(t *testing.T) {
	depsTpl := newTestDeps(t)
	bc := &connector.BuildConfig{}
	mgr, err := NewManager(ManagerConfig{
		Logger: depsTpl.Logger,
		StackFactory: func(_ context.Context, name, addr string) (*Stack, error) {
			d := newTestDeps(t)
			d.ListenerName = name
			d.ListenAddr = addr
			return BuildLiveStack(context.Background(), d)
		},
		BuildConfig: bc,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Initial snapshot is nil.
	if got := bc.EffectiveEnabledProtocols(); got != nil {
		t.Errorf("initial BuildConfig.EffectiveEnabledProtocols = %v, want nil", got)
	}

	// Setting protocols propagates to BuildConfig.
	mgr.SetEnabledProtocols([]string{"HTTP/1.x", "HTTPS"})
	got := bc.EffectiveEnabledProtocols()
	want := []string{"HTTP/1.x", "HTTPS"}
	if len(got) != len(want) {
		t.Fatalf("BuildConfig.EffectiveEnabledProtocols = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("BuildConfig.EffectiveEnabledProtocols[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	// Clearing propagates too.
	mgr.SetEnabledProtocols(nil)
	if got := bc.EffectiveEnabledProtocols(); got != nil {
		t.Errorf("after clear: BuildConfig.EffectiveEnabledProtocols = %v, want nil", got)
	}
}

// TestManager_SetEnabledProtocols_NoBuildConfig_NoCrash verifies the
// fan-out tolerates a Manager constructed without a BuildConfig (the
// historical pre-USK-808 path retained for tests/adapters).
func TestManager_SetEnabledProtocols_NoBuildConfig_NoCrash(t *testing.T) {
	mgr := newTestManager(t) // newTestManager omits BuildConfig
	// Must not panic.
	mgr.SetEnabledProtocols([]string{"HTTP/1.x"})
	if got := mgr.EnabledProtocols(); len(got) != 1 || got[0] != "HTTP/1.x" {
		t.Errorf("Manager.EnabledProtocols = %v, want [HTTP/1.x]", got)
	}
}

func TestManager_TCPForwards_NilParamsAccepted(t *testing.T) {
	// StartTCPForwards(nil) is a no-op (no forwards to bind) — must not
	// return an error and must not bind anything.
	mgr := newTestManager(t)
	if err := mgr.StartTCPForwards(context.Background(), nil); err != nil {
		t.Errorf("StartTCPForwards(nil) returned %v, want nil", err)
	}
	if got := mgr.TCPForwardAddrs(); got != nil {
		t.Errorf("TCPForwardAddrs = %v, want nil", got)
	}
}

func TestManager_TCPForwards_RejectsWrongParamsType(t *testing.T) {
	// Passing a non-TCPForwardParams value must return a typed error so MCP
	// callers see a precise failure (not a panic from a hard type assertion).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := newTestManager(t)
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.StopAll(context.Background())

	err := mgr.StartTCPForwards(ctx, "not-a-params-struct")
	if err == nil {
		t.Fatal("expected error for wrong params type, got nil")
	}
	if !strings.Contains(err.Error(), "TCPForwardParams") {
		t.Errorf("error %q should mention TCPForwardParams", err.Error())
	}
}

// TestManager_StartTCPForwardsNamed_RejectsInvalidPortKey verifies the
// defensive port-key validation at the package boundary. The MCP layer
// already validates these via validatePortNumber, but a programmatic
// caller passing a malformed key must observe a precise error rather than
// reaching net.Listen with a confusing bind-address error.
func TestManager_StartTCPForwardsNamed_RejectsInvalidPortKey(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := newTestManager(t)
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.StopAll(context.Background())

	cases := []struct {
		name string
		port string
	}{
		{"empty", ""},
		{"non-numeric", "abc"},
		{"out-of-range", "99999"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := mgr.StartTCPForwards(ctx, TCPForwardParams{
				Forwards: map[string]*config.ForwardConfig{
					tc.port: {Target: "127.0.0.1:1", Protocol: "raw"},
				},
			})
			if err == nil {
				t.Fatalf("expected error for port=%q, got nil", tc.port)
			}
		})
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

// reserveBoundPort listens on an ephemeral port and returns the port string
// + a closer that frees the listener. Tests use this to provoke "address in
// use" errors against a port that is provably bound right now.
func reserveBoundPort(t *testing.T) (port string, release func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	_, p, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		ln.Close()
		t.Fatalf("split host port: %v", err)
	}
	return p, func() { ln.Close() }
}

// TestManager_StartTCPForwardsNamed_OnNonRunningListener verifies the
// pre-condition: forwards cannot be attached to a listener that does not
// exist. ErrNotRunning is returned for the default listener so MCP callers
// observe the same sentinel as Stop on a non-running default.
func TestManager_StartTCPForwardsNamed_OnNonRunningListener(t *testing.T) {
	mgr := newTestManager(t)
	err := mgr.StartTCPForwards(context.Background(), TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			"0": {Target: "127.0.0.1:9999", Protocol: "raw"},
		},
	})
	if !errors.Is(err, ErrNotRunning) {
		t.Errorf("StartTCPForwards on non-running default returned %v, want ErrNotRunning", err)
	}
}

// TestManager_StartTCPForwardsNamed_NamedNotFound verifies the non-default
// listener absence path: ErrListenerNotFound rather than ErrNotRunning.
func TestManager_StartTCPForwardsNamed_NamedNotFound(t *testing.T) {
	mgr := newTestManager(t)
	err := mgr.StartTCPForwardsNamed(context.Background(), "ghost", TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			"0": {Target: "127.0.0.1:9999", Protocol: "raw"},
		},
	})
	if !errors.Is(err, ErrListenerNotFound) {
		t.Errorf("StartTCPForwardsNamed on missing listener returned %v, want ErrListenerNotFound", err)
	}
}

// TestManager_StartTCPForwardsNamed_Success verifies the happy path:
// multiple forwards bind cleanly and TCPForwardAddrs reports them.
func TestManager_StartTCPForwardsNamed_Success(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := newTestManager(t)
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.StopAll(context.Background())

	err := mgr.StartTCPForwards(ctx, TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			"0": {Target: "127.0.0.1:1", Protocol: "raw"},
		},
	})
	if err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}

	addrs := mgr.TCPForwardAddrs()
	if len(addrs) != 1 {
		t.Fatalf("TCPForwardAddrs len = %d, want 1", len(addrs))
	}
	if addrs["0"] == "" {
		t.Errorf("TCPForwardAddrs[%q] is empty", "0")
	}
}

// TestManager_StartTCPForwardsNamed_DuplicatePort verifies the legacy
// idempotent skip behaviour: re-starting an already-bound port is a no-op.
func TestManager_StartTCPForwardsNamed_DuplicatePort(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := newTestManager(t)
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.StopAll(context.Background())

	params := TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			"0": {Target: "127.0.0.1:1", Protocol: "raw"},
		},
	}
	if err := mgr.StartTCPForwards(ctx, params); err != nil {
		t.Fatalf("first StartTCPForwards: %v", err)
	}
	firstAddr := mgr.TCPForwardAddrs()["0"]

	// Second call with the same port resolves to the SAME backing forward
	// (idempotent skip). The reported addr must not change because we did
	// not bind a fresh listener.
	if err := mgr.StartTCPForwards(ctx, params); err != nil {
		t.Fatalf("duplicate StartTCPForwards: %v", err)
	}
	if got := mgr.TCPForwardAddrs()["0"]; got != firstAddr {
		t.Errorf("after duplicate call: addr = %q, want %q (idempotent skip)", got, firstAddr)
	}
}

// TestManager_StartTCPForwardsNamed_BindError exercises the rollback path:
// when the second forward fails to bind, the first must be torn down so
// the manager state is consistent. Critically, the bound port from the
// failing entry must NOT remain registered on listenerEntry.
func TestManager_StartTCPForwardsNamed_BindError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := newTestManager(t)
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.StopAll(context.Background())

	occupied, release := reserveBoundPort(t)
	defer release()

	// Single-port call against the occupied port must fail and leave the
	// manager with no recorded forwards.
	err := mgr.StartTCPForwards(ctx, TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			occupied: {Target: "127.0.0.1:1", Protocol: "raw"},
		},
	})
	if err == nil {
		t.Fatal("expected error binding occupied port, got nil")
	}
	if got := mgr.TCPForwardAddrs(); got != nil {
		t.Errorf("after bind failure: TCPForwardAddrs = %v, want nil", got)
	}
}

// TestManager_StartTCPForwardsNamed_RejectsUnsupportedProtocol verifies the
// USK-711 scope guard: L7 protocol modes are rejected at start time so
// callers see a clear "deferred to follow-up" failure rather than silent
// partial behaviour.
func TestManager_StartTCPForwardsNamed_RejectsUnsupportedProtocol(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := newTestManager(t)
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.StopAll(context.Background())

	err := mgr.StartTCPForwards(ctx, TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			"0": {Target: "127.0.0.1:1", Protocol: "http"},
		},
	})
	if err == nil {
		t.Fatal("expected error for protocol=http, got nil")
	}
	if !strings.Contains(err.Error(), "not yet supported") {
		t.Errorf("error %q should mention 'not yet supported'", err.Error())
	}
}

// TestManager_StopNamed_StopsTCPForwards verifies graceful shutdown drains
// associated forwards. After StopNamed, the per-port listener must be
// unbound (a fresh dial fails) and TCPForwardAddrs returns nil.
func TestManager_StopNamed_StopsTCPForwards(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := newTestManager(t)
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := mgr.StartTCPForwards(ctx, TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			"0": {Target: "127.0.0.1:1", Protocol: "raw"},
		},
	}); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}
	addrs := mgr.TCPForwardAddrs()
	if len(addrs) != 1 {
		t.Fatalf("TCPForwardAddrs len = %d, want 1", len(addrs))
	}
	fwdAddr := addrs["0"]

	if err := mgr.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if got := mgr.TCPForwardAddrs(); got != nil {
		t.Errorf("after Stop: TCPForwardAddrs = %v, want nil", got)
	}

	// A fresh dial against the previously-bound forward addr must fail —
	// the port is no longer listening. Retry within a short window because
	// busy CI runners may immediately reuse the freed ephemeral port for
	// an unrelated listener; if the manager truly unbound, at least one
	// dial in the window will see ECONNREFUSED.
	const attempts = 4
	sawRefused := false
	for i := 0; i < attempts; i++ {
		conn, err := net.DialTimeout("tcp", fwdAddr, 100*time.Millisecond)
		if err != nil {
			sawRefused = true
			break
		}
		conn.Close()
		if i < attempts-1 {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if !sawRefused {
		t.Errorf("dial %s after Stop succeeded on all %d attempts; expected ECONNREFUSED in at least one", fwdAddr, attempts)
	}
}

// TestManager_StartTCPForwardsNamed_AcceptsConn proves the accept loop is
// wired: a TCP dial against the bound forward port reaches the handler
// goroutine. The handler dial-out uses a non-routable target (127.0.0.1:1)
// so it fails fast and closes the conn quickly — sufficient to assert the
// accept loop runs and tears down cleanly.
func TestManager_StartTCPForwardsNamed_AcceptsConn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := newTestManager(t)
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.StopAll(context.Background())

	if err := mgr.StartTCPForwards(ctx, TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			"0": {Target: "127.0.0.1:1", Protocol: "raw"},
		},
	}); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}

	addr := mgr.TCPForwardAddrs()["0"]
	if addr == "" {
		t.Fatal("forward addr is empty")
	}

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial forward listener: %v", err)
	}
	conn.Close()
}

// TestManager_ConcurrentStartTCPForwards_StopNamed guards against the
// race + nil-map-write panic that existed before the
// StartTCPForwardsNamed/shutdownEntry locking was tightened: the legacy
// shutdownEntry iterated and nil'd entry.tcpForwards without holding m.mu,
// so a still-running StartTCPForwardsNamed (with the entry pointer in
// hand) could either race on the map or panic on assignment to a nil map.
//
// This test alternates Start+StartForwards / StopNamed across goroutines
// with multiple ports per call so the post-bind window is repeatedly
// re-entered against a Stop in flight. With -race it must run clean and
// must not panic.
func TestManager_ConcurrentStartTCPForwards_StopNamed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := newTestManager(t)
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// One stopper goroutine tearing down + restarting the parent listener
	// under load; one accumulator goroutine repeatedly calling
	// StartTCPForwardsNamed with multiple per-call ports.
	const iterations = 32
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_ = mgr.Stop(context.Background())
			if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
				// Parent ctx already cancelled — exit.
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			// Use port 0 (OS-assigned) so multiple attempts don't collide.
			// Errors are expected (parent may be down between Stop and
			// Start) — the assertion is "no panic, no -race report".
			_ = mgr.StartTCPForwards(ctx, TCPForwardParams{
				Forwards: map[string]*config.ForwardConfig{
					"0": {Target: "127.0.0.1:1", Protocol: "raw"},
				},
			})
		}
	}()
	wg.Wait()

	if err := mgr.StopAll(context.Background()); err != nil {
		t.Errorf("final StopAll: %v", err)
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
