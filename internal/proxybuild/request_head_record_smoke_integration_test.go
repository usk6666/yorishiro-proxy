//go:build e2e

package proxybuild_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// usk1181Store is a concurrency-safe flow.Writer capture for the USK-1181
// request-head recording tests.
type usk1181Store struct {
	mu      sync.Mutex
	streams []*flow.Stream
	updates map[string][]flow.StreamUpdate
	flows   []*flow.Flow
}

func (s *usk1181Store) SaveStream(_ context.Context, st *flow.Stream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *st
	s.streams = append(s.streams, &cp)
	return nil
}

func (s *usk1181Store) UpdateStream(_ context.Context, id string, upd flow.StreamUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.updates == nil {
		s.updates = make(map[string][]flow.StreamUpdate)
	}
	s.updates[id] = append(s.updates[id], upd)
	return nil
}

func (s *usk1181Store) SaveFlow(_ context.Context, f *flow.Flow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *f
	s.flows = append(s.flows, &cp)
	return nil
}

// errorStream returns the first stream saved with State="error" and the
// given FailureReason, or nil.
func (s *usk1181Store) errorStream(reason string) *flow.Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.streams {
		if st.State == "error" && st.FailureReason == reason {
			return st
		}
	}
	return nil
}

func (s *usk1181Store) flowsOf(streamID string) []*flow.Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*flow.Flow
	for _, f := range s.flows {
		if f.StreamID == streamID {
			out = append(out, f)
		}
	}
	return out
}

func (s *usk1181Store) allStreams() []*flow.Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*flow.Stream(nil), s.streams...)
}

// awaitErrorStream polls until an error stream with reason exists AND its
// flows reached wantFlows, failing after guard.
func awaitErrorStream(t *testing.T, s *usk1181Store, reason string, wantFlows int, guard time.Duration) (*flow.Stream, []*flow.Flow) {
	t.Helper()
	deadline := time.Now().Add(guard)
	for {
		if st := s.errorStream(reason); st != nil {
			if fl := s.flowsOf(st.ID); len(fl) >= wantFlows {
				return st, fl
			}
		}
		if time.Now().After(deadline) {
			var got []string
			for _, st := range s.allStreams() {
				got = append(got, st.State+"/"+st.FailureReason)
			}
			t.Fatalf("no state=error failure_reason=%q stream with %d flows within %v; streams=%v", reason, wantFlows, guard, got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestProxybuild_PlainHTTP_RequestHeadTimeoutRecorded_Smoke is the USK-1181
// merge-gate repro: a plain-forward client that sends part of its request
// head and stalls is closed by request_timeout_ms, and the close is
// recorded as a state=error stream carrying the received bytes and the
// proxy-closed reason.
func TestProxybuild_PlainHTTP_RequestHeadTimeoutRecorded_Smoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	defer upLn.Close()
	go func() {
		for {
			c, err := upLn.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	upstream := upLn.Addr().String()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
	}
	store := &usk1181Store{}
	logger := testutil.DiscardLogger()
	mgr, err := proxybuild.NewManager(proxybuild.ManagerConfig{
		Logger: logger,
		StackFactory: func(ctx context.Context, name, addr string) (*proxybuild.Stack, error) {
			return proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
				Logger:       logger,
				ListenerName: name,
				ListenAddr:   addr,
				FlowStore:    store,
				BuildConfig:  buildCfg,
			})
		},
		BuildConfig: buildCfg,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer func() { _ = mgr.StopAll(context.Background()) }()
	mgr.SetRequestTimeout(300 * time.Millisecond)
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	_, proxyAddr := mgr.Status()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// > 4100 bytes so the request passes the forward handler's 4000-byte
	// target peek and reaches the HTTP/1 Layer.
	head := "GET http://" + upstream + "/stall HTTP/1.1\r\nHost: " + upstream + "\r\nX-Pad: " + strings.Repeat("a", 4100)
	if _, err := conn.Write([]byte(head)); err != nil {
		t.Fatalf("write head: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			t.Errorf("proxy replied to a stalled request head: %q", buf[:n])
		}
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatal("proxy still holds the stalled connection open after 3s")
			}
			break
		}
	}

	st, flows := awaitErrorStream(t, store, "request_head_timeout", 1, 5*time.Second)
	if st.Protocol != "http" || st.Scheme != "http" {
		t.Errorf("stream protocol/scheme = %q/%q, want http/http", st.Protocol, st.Scheme)
	}
	if st.Tags["closed_by"] != "proxy" {
		t.Errorf("Tags[closed_by] = %q, want proxy", st.Tags["closed_by"])
	}
	if st.Tags["request_timeout_ms"] != "300" {
		t.Errorf("Tags[request_timeout_ms] = %q, want 300", st.Tags["request_timeout_ms"])
	}
	if st.ConnID == "" {
		t.Error("stream ConnID is empty")
	}
	if len(flows) != 1 || flows[0].Direction != "send" || flows[0].Sequence != 0 {
		t.Fatalf("flows = %d (first dir %q), want one send flow", len(flows), flows[0].Direction)
	}
	if string(flows[0].RawBytes) != head {
		t.Errorf("send RawBytes = %d bytes (prefix ok=%v), want the %d bytes sent",
			len(flows[0].RawBytes), strings.HasPrefix(head, string(flows[0].RawBytes)), len(head))
	}
}
