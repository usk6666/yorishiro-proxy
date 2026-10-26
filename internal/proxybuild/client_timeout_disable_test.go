package proxybuild

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// USK-1185: Manager surface for request_timeout_ms: 0 (disabled) and
// client_idle_timeout_ms.

func newClientTimeoutTestManager(t *testing.T, bc *connector.BuildConfig) *Manager {
	t.Helper()
	depsTpl := newTestDeps(t)
	mgr, err := NewManager(ManagerConfig{
		Logger: depsTpl.Logger,
		StackFactory: func(_ context.Context, name, addr string) (*Stack, error) {
			d := newTestDeps(t)
			d.ListenerName = name
			d.ListenAddr = addr
			if bc != nil {
				d.BuildConfig = bc
			}
			return BuildLiveStack(context.Background(), d)
		},
		BuildConfig: bc,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return mgr
}

func TestManager_DisableRequestTimeout_FanOut(t *testing.T) {
	bc := newTestDeps(t).BuildConfig
	bc.RequestHeaderTimeout = 3 * time.Second
	mgr := newClientTimeoutTestManager(t, bc)
	if err := mgr.Start(context.Background(), "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.StopAll(context.Background())

	mgr.SetRequestTimeout(200 * time.Millisecond)
	mgr.DisableRequestTimeout()
	if !mgr.RequestTimeoutDisabled() {
		t.Error("Manager.RequestTimeoutDisabled = false after DisableRequestTimeout")
	}
	if !mgr.Listener(DefaultListenerName).RequestTimeoutDisabled() {
		t.Error("listener RequestTimeoutDisabled = false after Manager.DisableRequestTimeout")
	}
	if _, ok := bc.ClientRequestHeadDeadline(); ok {
		t.Error("BuildConfig request-head bound still enabled after Manager.DisableRequestTimeout")
	}

	// A positive value re-enables everywhere.
	mgr.SetRequestTimeout(250 * time.Millisecond)
	if mgr.RequestTimeoutDisabled() || mgr.Listener(DefaultListenerName).RequestTimeoutDisabled() {
		t.Error("SetRequestTimeout(250ms) did not clear the disabled state")
	}
	if d, ok := bc.ClientRequestHeadDeadline(); !ok || d != 250*time.Millisecond {
		t.Errorf("BuildConfig ClientRequestHeadDeadline = (%v, %v), want (250ms, true)", d, ok)
	}
}

// The disabled state set before a listener exists reaches it at Start.
func TestManager_DisableRequestTimeout_BeforeStart_AppliesToNewListener(t *testing.T) {
	mgr := newClientTimeoutTestManager(t, nil)
	mgr.DisableRequestTimeout()
	if err := mgr.Start(context.Background(), "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer mgr.StopAll(context.Background())
	if !mgr.Listener(DefaultListenerName).RequestTimeoutDisabled() {
		t.Error("listener started after DisableRequestTimeout is not disabled")
	}
}

func TestManager_ClientIdleTimeout(t *testing.T) {
	t.Run("bound BuildConfig", func(t *testing.T) {
		bc := &connector.BuildConfig{}
		mgr := newClientTimeoutTestManager(t, bc)
		if got := mgr.ClientIdleTimeout(); got != connector.DefaultClientIdleTimeout || mgr.ClientIdleTimeoutDisabled() {
			t.Errorf("default ClientIdleTimeout = %v (disabled=%v), want %v", got, mgr.ClientIdleTimeoutDisabled(), connector.DefaultClientIdleTimeout)
		}
		mgr.SetClientIdleTimeout(5 * time.Second)
		if d, ok := bc.ClientIdleDeadline(); !ok || d != 5*time.Second {
			t.Errorf("BuildConfig ClientIdleDeadline = (%v, %v), want (5s, true)", d, ok)
		}
		if got := mgr.ClientIdleTimeout(); got != 5*time.Second {
			t.Errorf("ClientIdleTimeout = %v, want 5s", got)
		}
		mgr.DisableClientIdleTimeout()
		if _, ok := bc.ClientIdleDeadline(); ok {
			t.Error("BuildConfig idle bound still enabled after DisableClientIdleTimeout")
		}
		if !mgr.ClientIdleTimeoutDisabled() {
			t.Error("ClientIdleTimeoutDisabled = false after DisableClientIdleTimeout")
		}
	})
	t.Run("no BuildConfig", func(t *testing.T) {
		mgr, err := NewManager(ManagerConfig{
			Logger:       silentLogger(),
			StackFactory: func(context.Context, string, string) (*Stack, error) { return nil, errors.New("unused") },
		})
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		mgr.SetClientIdleTimeout(7 * time.Second)
		if got := mgr.ClientIdleTimeout(); got != 7*time.Second {
			t.Errorf("ClientIdleTimeout = %v, want 7s", got)
		}
		mgr.DisableClientIdleTimeout()
		if !mgr.ClientIdleTimeoutDisabled() {
			t.Error("ClientIdleTimeoutDisabled = false after DisableClientIdleTimeout")
		}
	})
}
