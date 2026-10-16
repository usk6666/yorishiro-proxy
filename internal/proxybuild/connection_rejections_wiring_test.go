package proxybuild

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestManager_ConnectionRejections_WiredThroughBuildLiveStack (USK-1142):
// the aggregator passed in Deps reaches the FullListener's OnReject, and
// the Manager's status accessor reports the same instance. Driven by a
// real over-cap dial against a Manager-started listener.
func TestManager_ConnectionRejections_WiredThroughBuildLiveStack(t *testing.T) {
	rej := NewConnectionRejections(ConnectionRejectionsConfig{Logger: silentLogger()})
	t.Cleanup(rej.Close)

	factory := func(ctx context.Context, name, addr string) (*Stack, error) {
		deps := newTestDeps(t)
		deps.ListenerName = name
		deps.ListenAddr = addr
		deps.MaxConnections = 1
		// A silent first connection holds the only slot for PeekTimeout.
		deps.PeekTimeout = 10 * time.Second
		deps.ConnectionRejections = rej
		return BuildLiveStack(ctx, deps)
	}
	mgr, err := NewManager(ManagerConfig{
		Logger:               silentLogger(),
		StackFactory:         factory,
		ConnectionRejections: rej,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	mgr.SetMaxConnections(1)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := mgr.StartNamed(ctx, DefaultListenerName, "127.0.0.1:0"); err != nil {
		t.Fatalf("StartNamed: %v", err)
	}
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer scancel()
		_ = mgr.StopAll(sctx)
	})
	_, addr := mgr.Status()

	holder, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial holder: %v", err)
	}
	defer holder.Close()
	deadline := time.Now().Add(3 * time.Second)
	for mgr.ActiveConnections() < 1 {
		if time.Now().After(deadline) {
			t.Fatalf("holder connection never became active")
		}
		time.Sleep(10 * time.Millisecond)
	}

	over, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial over-cap: %v", err)
	}
	defer over.Close()
	if _, err := over.Write([]byte("CONNECT wired.example:443 HTTP/1.1\r\nHost: wired.example:443\r\n\r\n")); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	deadline = time.Now().Add(3 * time.Second)
	for {
		snap := mgr.ConnectionRejections()
		if snap.Total >= 1 {
			if snap.ByKind.Connect != 1 {
				t.Errorf("ByKind.Connect = %d, want 1", snap.ByKind.Connect)
			}
			if len(snap.Recent) == 0 {
				t.Fatalf("Total = %d but Recent is empty", snap.Total)
			}
			if got := snap.Recent[0].Target; got != "wired.example:443" {
				t.Errorf("Recent[0].Target = %q, want wired.example:443", got)
			}
			if got := snap.Recent[0].Listener; got != DefaultListenerName {
				t.Errorf("Recent[0].Listener = %q, want %q", got, DefaultListenerName)
			}
			if rej.Snapshot().Total != snap.Total {
				t.Errorf("Manager accessor and Deps aggregator disagree: %d vs %d", snap.Total, rej.Snapshot().Total)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Manager.ConnectionRejections().Total = 0 after an over-cap CONNECT; OnReject not wired")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestNewManager_ConnectionRejectionsFallback: omitting the aggregator
// still yields a working (empty) status accessor.
func TestNewManager_ConnectionRejectionsFallback(t *testing.T) {
	mgr, err := NewManager(ManagerConfig{
		Logger: silentLogger(),
		StackFactory: func(context.Context, string, string) (*Stack, error) {
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	snap := mgr.ConnectionRejections()
	if snap.Total != 0 || snap.Recent == nil {
		t.Errorf("fallback snapshot = %+v, want zero total and non-nil Recent (JSON [] not null)", snap)
	}
}
