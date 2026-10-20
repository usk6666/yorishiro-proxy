package proxybuild

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/config"
)

// captureHandler is a slog.Handler that retains every record it receives so
// tests can assert on manager-level log output.
type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

// warnsWithListenAddr returns the listen_addr attribute of every Warn
// record that carries one.
func (h *captureHandler) warnsWithListenAddr() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for _, r := range h.records {
		if r.Level != slog.LevelWarn {
			continue
		}
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "listen_addr" {
				out = append(out, a.Value.String())
				return false
			}
			return true
		})
	}
	return out
}

// newCapturingTestManager mirrors newTestManager but routes the Manager's
// own logger into a captureHandler.
func newCapturingTestManager(t *testing.T) (*Manager, *captureHandler) {
	t.Helper()
	h := &captureHandler{}
	mgr, err := NewManager(ManagerConfig{
		Logger: slog.New(h),
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
	return mgr, h
}

// skipIfWildcardBindDenied skips when the environment refuses a wildcard
// bind (sandboxed CI runners occasionally do).
func skipIfWildcardBindDenied(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skipf("cannot bind 0.0.0.0 in this environment: %v", err)
	}
	_ = ln.Close()
}

func addrHost(t *testing.T, hostport string) string {
	t.Helper()
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", hostport, err)
	}
	return host
}

func addrPort(t *testing.T, hostport string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", hostport, err)
	}
	return port
}

// TestManager_StartNamed_NonLoopbackWarnsOnce verifies the one-shot operator
// warning: a listener bound to a non-loopback address emits exactly one Warn
// carrying the bound listen_addr; loopback binds (including the literal
// "localhost") emit none.
func TestManager_StartNamed_NonLoopbackWarnsOnce(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		wantWarn int
	}{
		{name: "all interfaces", addr: "0.0.0.0:0", wantWarn: 1},
		{name: "IPv4 loopback", addr: "127.0.0.1:0", wantWarn: 0},
		{name: "localhost", addr: "localhost:0", wantWarn: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantWarn > 0 {
				skipIfWildcardBindDenied(t)
			}
			mgr, logs := newCapturingTestManager(t)
			if err := mgr.StartNamed(context.Background(), "l", tt.addr); err != nil {
				t.Fatalf("StartNamed(%q): %v", tt.addr, err)
			}
			t.Cleanup(func() { _ = mgr.StopAll(context.Background()) })

			warns := logs.warnsWithListenAddr()
			if len(warns) != tt.wantWarn {
				t.Fatalf("Warn records with listen_addr = %v (len %d), want %d", warns, len(warns), tt.wantWarn)
			}
			if tt.wantWarn > 0 {
				statuses := mgr.ListenerStatuses()
				if len(statuses) != 1 {
					t.Fatalf("ListenerStatuses len = %d, want 1", len(statuses))
				}
				if warns[0] != statuses[0].ListenAddr {
					t.Errorf("Warn listen_addr = %q, want bound address %q", warns[0], statuses[0].ListenAddr)
				}
			}
		})
	}
}

// TestManager_TCPForwards_InheritParentHost verifies that forward listeners
// bind on the parent listener's bound host instead of a hard-coded
// 127.0.0.1.
func TestManager_TCPForwards_InheritParentHost(t *testing.T) {
	tests := []struct {
		name     string
		parent   string
		wantHost string
	}{
		{name: "parent on all interfaces", parent: "0.0.0.0:0", wantHost: "0.0.0.0"},
		{name: "parent on loopback", parent: "127.0.0.1:0", wantHost: "127.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantHost == "0.0.0.0" {
				skipIfWildcardBindDenied(t)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			mgr := newTestManager(t)
			if err := mgr.Start(ctx, tt.parent); err != nil {
				t.Fatalf("Start(%q): %v", tt.parent, err)
			}
			defer mgr.StopAll(context.Background())

			if err := mgr.StartTCPForwards(ctx, TCPForwardParams{
				Forwards: map[string]*config.ForwardConfig{
					"0": {Target: "127.0.0.1:1", Protocol: "raw"},
				},
			}); err != nil {
				t.Fatalf("StartTCPForwards: %v", err)
			}
			got := mgr.TCPForwardAddrs()["0"]
			if host := addrHost(t, got); host != tt.wantHost {
				t.Errorf("forward bound on %q (host %q), want host %q", got, host, tt.wantHost)
			}
		})
	}
}

// TestManager_BindConflict_WildcardVsLoopback verifies the cross-listener
// pre-bind check: once a listener holds 0.0.0.0:P, neither a forward nor a
// parent listener may claim 127.0.0.1:P. The failure is the typed
// ErrBindConflict (not a platform-dependent EADDRINUSE) and leaves nothing
// registered.
func TestManager_BindConflict_WildcardVsLoopback(t *testing.T) {
	skipIfWildcardBindDenied(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := newTestManager(t)
	if err := mgr.StartNamed(ctx, "wild", "0.0.0.0:0"); err != nil {
		t.Fatalf("StartNamed(wild): %v", err)
	}
	defer mgr.StopAll(context.Background())
	var wildAddr string
	for _, st := range mgr.ListenerStatuses() {
		if st.Name == "wild" {
			wildAddr = st.ListenAddr
		}
	}
	port := addrPort(t, wildAddr)

	t.Run("forward on same port", func(t *testing.T) {
		if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
			t.Fatalf("Start(default): %v", err)
		}
		defer mgr.Stop(context.Background())

		err := mgr.StartTCPForwards(ctx, TCPForwardParams{
			Forwards: map[string]*config.ForwardConfig{
				port: {Target: "127.0.0.1:1", Protocol: "raw"},
			},
		})
		if !errors.Is(err, ErrBindConflict) {
			t.Fatalf("StartTCPForwards(port %s) = %v, want ErrBindConflict", port, err)
		}
		if got := mgr.TCPForwardAddrs(); got != nil {
			t.Errorf("TCPForwardAddrs after conflict = %v, want nil", got)
		}
	})

	t.Run("parent on same port", func(t *testing.T) {
		err := mgr.StartNamed(ctx, "loop", net.JoinHostPort("127.0.0.1", port))
		if !errors.Is(err, ErrBindConflict) {
			t.Fatalf("StartNamed(loop, 127.0.0.1:%s) = %v, want ErrBindConflict", port, err)
		}
		for _, st := range mgr.ListenerStatuses() {
			if st.Name == "loop" {
				t.Errorf("listener %q registered after conflict: %+v", st.Name, st)
			}
		}
	})
}

// TestManager_BindConflict_ForwardVsForward verifies a forward port already
// held by another listener's forward (same host) is rejected with
// ErrBindConflict before the bind.
func TestManager_BindConflict_ForwardVsForward(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mgr := newTestManager(t)
	if err := mgr.StartNamed(ctx, "a", "127.0.0.1:0"); err != nil {
		t.Fatalf("StartNamed(a): %v", err)
	}
	defer mgr.StopAll(context.Background())
	if err := mgr.StartTCPForwardsNamed(ctx, "a", TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			"0": {Target: "127.0.0.1:1", Protocol: "raw"},
		},
	}); err != nil {
		t.Fatalf("StartTCPForwardsNamed(a): %v", err)
	}
	// The ephemeral forward on "a" is keyed "0"; read its bound port from
	// the entry (TCPForwardAddrs only reports the default listener).
	mgr.mu.Lock()
	fwdAddr := mgr.listeners["a"].tcpForwards["0"].addr
	mgr.mu.Unlock()
	port := addrPort(t, fwdAddr)

	if err := mgr.StartNamed(ctx, "b", "127.0.0.1:0"); err != nil {
		t.Fatalf("StartNamed(b): %v", err)
	}
	err := mgr.StartTCPForwardsNamed(ctx, "b", TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			port: {Target: "127.0.0.1:1", Protocol: "raw"},
		},
	})
	if !errors.Is(err, ErrBindConflict) {
		t.Fatalf("StartTCPForwardsNamed(b, port %s) = %v, want ErrBindConflict", port, err)
	}
}

func TestBindAddrsOverlap(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"0.0.0.0:8080", "127.0.0.1:8080", true},
		{"127.0.0.1:8080", "0.0.0.0:8080", true},
		{"[::]:8080", "127.0.0.1:8080", true},
		{"0.0.0.0:8080", "[::1]:8080", true}, // accepted false positive
		{"127.0.0.1:8080", "127.0.0.1:8080", true},
		{"localhost:8080", "127.0.0.1:8080", true},
		{"localhost:8080", "[::1]:8080", true},
		{"127.0.0.1:8080", "127.0.0.1:8081", false},
		{"127.0.0.1:8080", "10.0.0.5:8080", false},
		{"0.0.0.0:0", "127.0.0.1:0", false},
		{"0.0.0.0:0", "0.0.0.0:0", false},
		{"[::1]:8080", "127.0.0.1:8080", false},
		// IPv4-mapped spellings are the IPv4 address they map.
		{"[::ffff:0.0.0.0]:8080", "127.0.0.1:8080", true},
		{"127.0.0.1:8080", "[0:0:0:0:0:ffff:0:0]:8080", true},
		{"[::ffff:0.0.0.0]:8080", "10.0.0.5:8080", true},
		{"[::ffff:127.0.0.1]:8080", "127.0.0.1:8080", true},
		{"[::ffff:127.0.0.1]:8080", "10.0.0.5:8080", false},
	}
	for _, tt := range tests {
		if got := bindAddrsOverlap(tt.a, tt.b); got != tt.want {
			t.Errorf("bindAddrsOverlap(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}
