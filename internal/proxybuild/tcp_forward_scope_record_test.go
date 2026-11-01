package proxybuild

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// USK-1403: a tcp_forwards connection the accept-time scope gate refuses —
// at the gate or in LiveConns.Register's re-check — keeps its refusal bytes
// and leaves one State="error", BlockedBy="target_scope" Stream.

// newScopeRecordingTestManager is newRateLimitedTestManager with a TargetScope and
// no rate limiter.
func newScopeRecordingTestManager(t *testing.T, scope *connector.TargetScope, live *connector.LiveConns, store *recordingFlowStore) *Manager {
	t.Helper()
	depsTpl := newTestDeps(t)
	mgr, err := NewManager(ManagerConfig{
		Logger: depsTpl.Logger,
		StackFactory: func(_ context.Context, name, addr string) (*Stack, error) {
			d := newTestDeps(t)
			d.ListenerName = name
			d.ListenAddr = addr
			d.Scope = scope
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

// admitRefused runs admitTCPForwardConn on a net.Pipe with ctx, requires
// a refusal, and returns every byte the client side read.
func admitRefused(t *testing.T, mgr *Manager, ctx context.Context, entry *tcpForwardEntry) []byte {
	t.Helper()
	c, s := net.Pipe()
	defer c.Close()
	done := make(chan bool, 1)
	go func() {
		_, rel, ok := mgr.admitTCPForwardConn(ctx, DefaultListenerName, entry, s)
		if ok {
			rel()
			_ = s.Close()
		}
		done <- ok
	}()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, _ := io.ReadAll(c)
	select {
	case ok := <-done:
		if ok {
			t.Fatal("admission ok=true for a denied target, want refused")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("admission did not return")
	}
	return got
}

// checkTCPForwardScopeStream requires exactly one target_scope Stream with
// the tcp_forwards refusal shape.
func checkTCPForwardScopeStream(t *testing.T, store *recordingFlowStore, protocol, scheme, target, port, fwdProto, reason string) {
	t.Helper()
	store.mu.Lock()
	saved := append([]*flow.Stream(nil), store.saved...)
	store.mu.Unlock()
	if len(saved) != 1 {
		t.Fatalf("saved %d Streams, want 1 target_scope Stream", len(saved))
	}
	st := saved[0]
	if st.State != "error" || st.BlockedBy != pipeline.BlockedByTargetScope || st.FailureReason != pipeline.BlockedByTargetScope {
		t.Errorf("Stream State=%q BlockedBy=%q FailureReason=%q, want error / target_scope / target_scope", st.State, st.BlockedBy, st.FailureReason)
	}
	if st.Protocol != protocol || st.Scheme != scheme {
		t.Errorf("Stream Protocol=%q Scheme=%q, want %q / %q", st.Protocol, st.Scheme, protocol, scheme)
	}
	if st.ConnID == "" {
		t.Error("Stream ConnID is empty")
	}
	if st.ListenerName != DefaultListenerName {
		t.Errorf("Stream ListenerName = %q, want %q", st.ListenerName, DefaultListenerName)
	}
	if st.ConnInfo == nil || st.ConnInfo.ClientAddr == "" || st.ConnInfo.ServerAddr != "" {
		t.Errorf("Stream ConnInfo = %+v, want a ClientAddr and no ServerAddr", st.ConnInfo)
	}
	want := map[string]string{
		"via":              "tcp-forward",
		"target":           target,
		"forward_port":     port,
		"forward_protocol": fwdProto,
		"reason":           reason,
	}
	for k, v := range want {
		if st.Tags[k] != v {
			t.Errorf("Tags[%s] = %q, want %q (tags %v)", k, st.Tags[k], v, st.Tags)
		}
	}
}

// TestAdmitTCPForwardConn_ScopeRefusalRecorded is T9.
func TestAdmitTCPForwardConn_ScopeRefusalRecorded(t *testing.T) {
	const target = "127.0.0.1:4444"
	tests := []struct {
		name      string
		fc        *config.ForwardConfig
		wantBytes []byte
		protocol  string
		scheme    string
		fwdProto  string
	}{
		{"http arm answers the canned 403", &config.ForwardConfig{Target: target, Protocol: "http"}, tcpForwardDenyResponse, "http", "http", "http"},
		{"raw arm closes with no byte", &config.ForwardConfig{Target: target, Protocol: "raw"}, nil, "raw", "http", "raw"},
		{"auto tls arm closes with no byte", &config.ForwardConfig{Target: target, TLS: true}, nil, "raw", "https", "auto"},
		{"grpc arm closes with no byte", &config.ForwardConfig{Target: target, Protocol: "grpc"}, nil, "grpc", "http", "grpc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope := connector.NewTargetScope()
			scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: "127.0.0.1"}})
			live := connector.NewLiveConns(silentLogger())
			store := &recordingFlowStore{}
			mgr := newScopeRecordingTestManager(t, scope, live, store)
			entry := &tcpForwardEntry{port: "7", target: target, fc: tt.fc}

			got := admitRefused(t, mgr, context.Background(), entry)
			if !bytes.Equal(got, tt.wantBytes) {
				t.Errorf("client read %q, want %q", got, tt.wantBytes)
			}
			if n := live.Len(); n != 0 {
				t.Errorf("live connections = %d, want 0", n)
			}
			checkTCPForwardScopeStream(t, store, tt.protocol, tt.scheme, target, "7", tt.fwdProto, "blocked by policy deny rule")
		})
	}
}

// flipOnDoneCtx flips the scope the first time Done is called on it.
// admitTCPForwardConn's first Done call is LiveConns.Register's
// context.WithCancelCause, after the gate's own check admitted the target
// — exactly the admission window Register's re-check exists to close.
type flipOnDoneCtx struct {
	context.Context
	once sync.Once
	flip func()
}

func (c *flipOnDoneCtx) Done() <-chan struct{} {
	c.once.Do(c.flip)
	return c.Context.Done()
}

// TestAdmitTCPForwardConn_ScopeRefusalAdmissionRaceRecorded is T10.
func TestAdmitTCPForwardConn_ScopeRefusalAdmissionRaceRecorded(t *testing.T) {
	const target = "127.0.0.1:4444"
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{{Hostname: "127.0.0.1"}}, nil)
	live := connector.NewLiveConns(silentLogger())
	store := &recordingFlowStore{}
	mgr := newScopeRecordingTestManager(t, scope, live, store)
	entry := &tcpForwardEntry{port: "7", target: target, fc: &config.ForwardConfig{Target: target, Protocol: "http"}}

	var flipped bool
	ctx := &flipOnDoneCtx{Context: context.Background(), flip: func() {
		scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: "127.0.0.1"}})
		flipped = true
	}}
	got := admitRefused(t, mgr, ctx, entry)
	if !flipped {
		t.Fatal("scope flip never ran; fix the test seam")
	}
	if !bytes.Equal(got, tcpForwardDenyResponse) {
		t.Errorf("client read %q, want the canned 403 %q", got, tcpForwardDenyResponse)
	}
	if n := live.Len(); n != 0 {
		t.Errorf("live connections = %d, want 0", n)
	}
	checkTCPForwardScopeStream(t, store, "http", "http", target, "7", "http", "policy changed during admission: blocked by policy deny rule")
}
