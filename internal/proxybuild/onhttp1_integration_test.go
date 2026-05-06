//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"context"
	"fmt"
	"io"
	gohttp "net/http"
	"net/http/httptest"
	"net/url"
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

// flowStoreCapture is a flow.Writer test double that captures Streams,
// StreamUpdates, and Flows under a mutex so the assertions can read them
// without races.
type flowStoreCapture struct {
	mu      sync.Mutex
	streams []*flow.Stream
	updates map[string][]flow.StreamUpdate
	flows   []*flow.Flow
}

func (s *flowStoreCapture) SaveStream(_ context.Context, st *flow.Stream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streams = append(s.streams, st)
	return nil
}

func (s *flowStoreCapture) UpdateStream(_ context.Context, streamID string, upd flow.StreamUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.updates == nil {
		s.updates = make(map[string][]flow.StreamUpdate)
	}
	s.updates[streamID] = append(s.updates[streamID], upd)
	return nil
}

func (s *flowStoreCapture) SaveFlow(_ context.Context, f *flow.Flow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flows = append(s.flows, f)
	return nil
}

func (s *flowStoreCapture) Streams() []*flow.Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*flow.Stream, len(s.streams))
	copy(out, s.streams)
	return out
}

// StreamUpdates returns a snapshot of the StreamUpdates captured for the
// given streamID. Returns nil when no updates were recorded for that ID.
func (s *flowStoreCapture) StreamUpdates(streamID string) []flow.StreamUpdate {
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.updates[streamID]
	if len(src) == 0 {
		return nil
	}
	out := make([]flow.StreamUpdate, len(src))
	copy(out, src)
	return out
}

func (s *flowStoreCapture) Flows() []*flow.Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*flow.Flow, len(s.flows))
	copy(out, s.flows)
	return out
}

// TestProxybuild_PlainHTTP_ForwardProxy_ReachesUpstream is the end-to-end
// proof for USK-710: a plain-HTTP proxy client (curl-style absolute URI)
// must reach the upstream server through the proxy and the response body
// must propagate back to the client. This is the production scenario that
// pre-USK-710 produced ERR_EMPTY_RESPONSE because OnHTTP1 was unwired.
//
// Verifies (subsystem checklist):
//   - Communication success (request -> response with expected body)
//   - Stream recording with Protocol="http", Scheme="http"
//   - Flow recording: send + receive directions both saved
//   - Raw bytes recording on each Flow (L4-capable principle)
func TestProxybuild_PlainHTTP_ForwardProxy_ReachesUpstream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Spin up an upstream HTTP test server.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("X-Echo-Path", r.URL.Path)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "hello from upstream: %s", r.URL.Path)
	}))
	defer upstream.Close()

	// 2. Build the proxy stack via BuildLiveStack.
	store := &flowStoreCapture{}
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}

	deps := proxybuild.Deps{
		Logger:       testutil.DiscardLogger(),
		ListenerName: "usk-710-test",
		ListenAddr:   "127.0.0.1:0",
		FlowStore:    store,
		BuildConfig: &connector.BuildConfig{
			ProxyConfig:        &config.ProxyConfig{},
			Issuer:             cert.NewIssuer(ca),
			InsecureSkipVerify: true,
		},
	}

	stack, err := proxybuild.BuildLiveStack(ctx, deps)
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}

	// 3. Start the listener and wait until it is ready.
	go func() { _ = stack.Listener.Start(ctx) }()

	select {
	case <-stack.Listener.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("listener not ready in 5s")
	}
	// Listener shutdown is driven by ctx cancellation (defer cancel above):
	// connector.FullListener has no Close() method — Start(ctx) returns once
	// ctx is done. No teardown call needed here.

	proxyAddr := stack.Listener.Addr()
	if proxyAddr == "" {
		t.Fatal("listener has no addr")
	}

	// 4. Send a plain-HTTP request through the proxy. The Go http transport
	// will issue absolute-form Request-URI when configured with a proxy.
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &gohttp.Client{
		Transport: &gohttp.Transport{
			Proxy:             gohttp.ProxyURL(proxyURL),
			DisableKeepAlives: true, // first iteration: one request per conn (USK-710 limitation)
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(upstream.URL + "/usk710")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("response status = %d, want 200", resp.StatusCode)
	}
	if got := string(body); !strings.Contains(got, "hello from upstream: /usk710") {
		t.Fatalf("response body = %q, want to contain hello from upstream: /usk710", got)
	}

	client.CloseIdleConnections()

	// Allow asynchronous Stream/Flow recording to complete.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(store.Streams()) >= 1 && len(store.Flows()) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// 5. Stream recording — Protocol="http", Scheme="http" (RFC-001 §3.4).
	streams := store.Streams()
	if len(streams) < 1 {
		t.Fatalf("expected at least 1 stream recorded, got %d", len(streams))
	}
	st := streams[0]
	if st.Protocol != "http" {
		t.Errorf("stream Protocol = %q, want %q", st.Protocol, "http")
	}
	if st.Scheme != "http" {
		t.Errorf("stream Scheme = %q, want %q (plain HTTP forward proxy must record http, not https)", st.Scheme, "http")
	}

	// 6. Flow recording — both directions saved with raw bytes.
	flows := store.Flows()
	if len(flows) < 2 {
		t.Fatalf("expected at least 2 flows (send + receive), got %d", len(flows))
	}

	var sendFlow, recvFlow *flow.Flow
	for _, f := range flows {
		switch f.Direction {
		case "send":
			if sendFlow == nil {
				sendFlow = f
			}
		case "receive":
			if recvFlow == nil {
				recvFlow = f
			}
		}
	}
	if sendFlow == nil {
		t.Fatal("no send-direction flow recorded")
	}
	if recvFlow == nil {
		t.Fatal("no receive-direction flow recorded")
	}
	if len(sendFlow.RawBytes) == 0 {
		t.Error("send flow RawBytes is empty (L4-capable principle violated)")
	}
	if len(recvFlow.RawBytes) == 0 {
		t.Error("receive flow RawBytes is empty (L4-capable principle violated)")
	}
	// Send flow raw bytes should contain the absolute-form Request-URI or
	// at least the HTTP method.
	if !strings.Contains(string(sendFlow.RawBytes), "GET ") {
		t.Errorf("send flow RawBytes missing GET request line: %q", string(sendFlow.RawBytes))
	}
}

// TestProxybuild_PlainHTTP_ScopeBlocks verifies the plain-HTTP forward
// proxy honors TargetScope deny rules: a denied target produces a 403
// response (the proxy's own response, not the upstream's) and no Stream
// is recorded.
func TestProxybuild_PlainHTTP_ScopeBlocks(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, _ *gohttp.Request) {
		fmt.Fprint(w, "should not reach")
	}))
	defer upstream.Close()

	upstreamURL, _ := url.Parse(upstream.URL)
	scope := connector.NewTargetScope()
	scope.SetPolicyRules(nil, []connector.TargetRule{
		{Hostname: upstreamURL.Hostname()},
	})

	store := &flowStoreCapture{}
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}

	deps := proxybuild.Deps{
		Logger:       testutil.DiscardLogger(),
		ListenerName: "usk-710-scope",
		ListenAddr:   "127.0.0.1:0",
		FlowStore:    store,
		Scope:        scope,
		BuildConfig: &connector.BuildConfig{
			ProxyConfig:        &config.ProxyConfig{},
			Issuer:             cert.NewIssuer(ca),
			InsecureSkipVerify: true,
		},
	}

	stack, err := proxybuild.BuildLiveStack(ctx, deps)
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	go func() { _ = stack.Listener.Start(ctx) }()
	select {
	case <-stack.Listener.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("listener not ready")
	}

	proxyAddr := stack.Listener.Addr()
	proxyURL, _ := url.Parse("http://" + proxyAddr)
	client := &gohttp.Client{
		Transport: &gohttp.Transport{
			Proxy:             gohttp.ProxyURL(proxyURL),
			DisableKeepAlives: true,
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(upstream.URL + "/blocked")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != gohttp.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
	if got := resp.Header.Get("Server"); got != "yorishiro-proxy" {
		t.Errorf("Server header = %q, want yorishiro-proxy", got)
	}

	// No Stream should be recorded — scope denial happens before stack build.
	time.Sleep(200 * time.Millisecond)
	if n := len(store.Streams()); n != 0 {
		t.Errorf("expected 0 streams (scope denied), got %d", n)
	}
}
