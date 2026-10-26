package proxybuild

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// newRateLimitedTestManager is newTestManager with a rate limiter, a
// live-connection registry and a recording flow store wired into every
// Stack it builds, started on an ephemeral port.
func newRateLimitedTestManager(t *testing.T, rl *connector.RateLimiter, live *connector.LiveConns, store *recordingFlowStore) *Manager {
	t.Helper()
	depsTpl := newTestDeps(t)
	mgr, err := NewManager(ManagerConfig{
		Logger: depsTpl.Logger,
		StackFactory: func(_ context.Context, name, addr string) (*Stack, error) {
			d := newTestDeps(t)
			d.ListenerName = name
			d.ListenAddr = addr
			d.RateLimiter = rl
			d.LiveConns = live
			d.FlowStore = store
			return BuildLiveStack(context.Background(), d)
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := mgr.Start(context.Background(), "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.StopAll(context.Background()) })
	return mgr
}

// TestBuildLiveStack_RateLimiterOnStack: the Deps rate limiter is carried
// on the Stack, where the tcp_forwards accept gate reads it.
func TestBuildLiveStack_RateLimiterOnStack(t *testing.T) {
	rl := connector.NewRateLimiter()
	d := newTestDeps(t)
	d.RateLimiter = rl
	stack, err := BuildLiveStack(context.Background(), d)
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	if stack.RateLimiter != rl {
		t.Errorf("Stack.RateLimiter = %p, want the Deps limiter %p", stack.RateLimiter, rl)
	}
}

// TestAdmitTCPForwardConn_RateLimitRefusesOverLimit is test-plan 8/9: with
// a burst-1 limit the second admission is refused, nothing is registered
// in the live-connection registry for it, a plaintext http forward answers
// the CONNECT gate's exact 429, and one rate_limit Stream is recorded.
func TestAdmitTCPForwardConn_RateLimitRefusesOverLimit(t *testing.T) {
	rl := connector.NewRateLimiter()
	rl.SetPolicyLimits(connector.RateLimitConfig{MaxRequestsPerSecond: 0.001})
	live := connector.NewLiveConns(silentLogger())
	store := &recordingFlowStore{}
	mgr := newRateLimitedTestManager(t, rl, live, store)

	entry := &tcpForwardEntry{port: "1", target: "127.0.0.1:4444", fc: &config.ForwardConfig{Target: "127.0.0.1:4444", Protocol: "http"}}

	c1, s1 := net.Pipe()
	defer c1.Close()
	defer s1.Close()
	_, release, ok := mgr.admitTCPForwardConn(context.Background(), DefaultListenerName, entry, s1)
	if !ok {
		t.Fatal("first admission refused under a burst-1 limit")
	}
	defer release()
	if n := live.Len(); n != 1 {
		t.Fatalf("live connections after first admission = %d, want 1", n)
	}

	c2, s2 := net.Pipe()
	defer c2.Close()
	type result struct{ ok bool }
	done := make(chan result, 1)
	go func() {
		_, rel, ok := mgr.admitTCPForwardConn(context.Background(), DefaultListenerName, entry, s2)
		if ok {
			rel()
		}
		done <- result{ok: ok}
	}()

	want := connector.RateLimitRefusalResponse()
	_ = c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(want)+64)
	n, _ := io.ReadAtLeast(c2, got, max(len(want), 1))
	_ = c2.Close()
	if len(want) == 0 || !bytes.Equal(got[:n], want) {
		t.Errorf("over-limit http forward wrote %q, want the CONNECT gate's 429 %q", got[:n], want)
	}

	select {
	case r := <-done:
		if r.ok {
			t.Fatal("second admission ok=true under a burst-1 limit, want refused")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second admission did not return")
	}
	if n := live.Len(); n != 1 {
		t.Errorf("live connections after the refusal = %d, want 1 (the refused conn must not register)", n)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.saved) != 1 {
		t.Fatalf("saved %d Streams, want 1 rate_limit Stream", len(store.saved))
	}
	st := store.saved[0]
	if st.State != "error" || st.BlockedBy != pipeline.BlockedByRateLimit {
		t.Errorf("Stream State=%q BlockedBy=%q, want error / %q", st.State, st.BlockedBy, pipeline.BlockedByRateLimit)
	}
	if st.Tags["rate_limit_type"] != "global" || st.Tags["rate_limit_effective_rps"] == "" {
		t.Errorf("Stream Tags = %v, want rate_limit_type=global and rate_limit_effective_rps", st.Tags)
	}
}

// TestAdmitTCPForwardConn_ZeroLimitAdmitsAll: a rate limiter with no
// limits configured admits every connection (test-plan 4, unit seam).
func TestAdmitTCPForwardConn_ZeroLimitAdmitsAll(t *testing.T) {
	live := connector.NewLiveConns(silentLogger())
	store := &recordingFlowStore{}
	mgr := newRateLimitedTestManager(t, connector.NewRateLimiter(), live, store)
	entry := &tcpForwardEntry{port: "1", target: "127.0.0.1:4444", fc: &config.ForwardConfig{Target: "127.0.0.1:4444", Protocol: "raw"}}
	for i := 0; i < 5; i++ {
		c, s := net.Pipe()
		_, release, ok := mgr.admitTCPForwardConn(context.Background(), DefaultListenerName, entry, s)
		if !ok {
			t.Fatalf("admission %d refused with no limits configured", i)
		}
		release()
		_ = c.Close()
		_ = s.Close()
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.saved) != 0 {
		t.Errorf("saved %d Streams with no limits, want 0", len(store.saved))
	}
}
