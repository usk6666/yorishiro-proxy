//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"context"
	"io"
	"net"
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

// echoTCPServer accepts a single TCP connection, echoes whatever bytes the
// client sends, and exits. Returns (addr, stop) where stop closes the
// listener. The accept goroutine returns once stop is invoked.
func echoTCPServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, accErr := ln.Accept()
			if accErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, rerr := c.Read(buf)
					if n > 0 {
						_, _ = c.Write(buf[:n])
					}
					if rerr != nil {
						return
					}
				}
			}(c)
		}
	}()

	stop = func() {
		ln.Close()
		wg.Wait()
	}
	return ln.Addr().String(), stop
}

// newForwardTestManager constructs a *proxybuild.Manager whose StackFactory
// builds a Stack that records to the given store. Mirrors the live data
// path wiring used elsewhere in the package.
func newForwardTestManager(t *testing.T, store flow.Writer) *proxybuild.Manager {
	t.Helper()

	logger := testutil.DiscardLogger()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
	}
	factory := func(ctx context.Context, name, addr string) (*proxybuild.Stack, error) {
		return proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
			Logger:       logger,
			ListenerName: name,
			ListenAddr:   addr,
			FlowStore:    store,
			BuildConfig:  buildCfg,
		})
	}
	mgr, err := proxybuild.NewManager(proxybuild.ManagerConfig{
		Logger:       logger,
		StackFactory: factory,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.StopAll(context.Background()) })
	return mgr
}

// TestProxybuild_TCPForward_RawBytesFlowRecording is the AC-level e2e for
// USK-711: a client dials the TCP forward listener, the proxy forwards
// bytes to an upstream echo server, and the round-trip is recorded as raw
// bytes in the parent listener's FlowStore.
//
// Subsystem checklist (CLAUDE.md):
//   - Communication success: bytes sent → received unchanged at upstream
//   - Stream recording: Protocol="raw", State transitions to "complete"
//   - Flow recording: at least one Send and one Receive flow
//   - Raw bytes recording (Envelope.Raw): wire-observed bytes preserved
func TestProxybuild_TCPForward_RawBytesFlowRecording(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, stopUpstream := echoTCPServer(t)
	defer stopUpstream()

	store := &flowStoreCapture{}
	mgr := newForwardTestManager(t, store)

	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}

	if err := mgr.StartTCPForwards(ctx, proxybuild.TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			"0": {Target: upstreamAddr, Protocol: "raw"},
		},
	}); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}

	addrs := mgr.TCPForwardAddrs()
	fwdAddr := addrs["0"]
	if fwdAddr == "" {
		t.Fatalf("TCPForwardAddrs missing port 0: %v", addrs)
	}

	// Round-trip a unique payload through the forward so we can assert it
	// shows up in the recorded flows.
	payload := []byte("hello-usk-711-tcp-forward")
	conn, err := net.DialTimeout("tcp", fwdAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}

	if _, err := conn.Write(payload); err != nil {
		conn.Close()
		t.Fatalf("write payload: %v", err)
	}

	// Read the echoed bytes back. The echo server may return them in one or
	// more reads; loop until we have the full payload or timeout.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var got []byte
	buf := make([]byte, len(payload))
	for len(got) < len(payload) {
		n, rerr := conn.Read(buf[len(got):])
		got = append(got, buf[len(got):len(got)+n]...)
		if rerr != nil {
			break
		}
	}
	if string(got) != string(payload) {
		t.Errorf("echo round-trip got %q, want %q", got, payload)
	}

	// Close the client side so the proxy session terminates cleanly.
	conn.Close()

	// Stop the listener to drive Stream state transitions to "complete".
	if err := mgr.Stop(context.Background()); err != nil {
		t.Errorf("manager.Stop: %v", err)
	}

	// Allow async recording to settle.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(store.Streams()) >= 1 && len(store.Flows()) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	streams := store.Streams()
	if len(streams) < 1 {
		t.Fatalf("expected at least 1 stream recorded, got %d", len(streams))
	}
	// At least one Stream must carry Protocol="raw" — the bytechunk Layer
	// Channel produces RawMessage envelopes (Protocol=raw). Capture its
	// StreamID so we can assert the State transition below.
	var rawStreamID string
	for _, st := range streams {
		if st.Protocol == "raw" {
			rawStreamID = st.ID
			break
		}
	}
	if rawStreamID == "" {
		t.Errorf("expected at least one stream with Protocol=raw, got streams: %+v", streams)
	} else {
		// State transition assertion: session.OnComplete (wired by
		// proxybuild.tcpForwardSessionOpts) must have called UpdateStream
		// with State="complete" once the round-trip finished. Without this
		// hook every Stream recorded via the forward path stays at "active".
		// (tcp_forward.go's OnComplete treats context.Canceled — the result
		// of mgr.Stop cancelling the connCtx mid-session — as a graceful
		// end-of-life for raw TCP, so this assertion holds whether the
		// session ended on natural EOF or on listener shutdown.)
		var sawComplete bool
		for _, upd := range store.StreamUpdates(rawStreamID) {
			if upd.State == "complete" {
				sawComplete = true
				break
			}
		}
		if !sawComplete {
			t.Errorf("expected StreamUpdate with State=\"complete\" for stream %q, got updates: %+v",
				rawStreamID, store.StreamUpdates(rawStreamID))
		}
	}

	flows := store.Flows()
	if len(flows) < 2 {
		t.Fatalf("expected at least 2 flows (send + receive), got %d", len(flows))
	}

	var sendFlow, recvFlow *flow.Flow
	for _, f := range flows {
		switch f.Direction {
		case "send":
			if sendFlow == nil || len(f.RawBytes) > len(sendFlow.RawBytes) {
				sendFlow = f
			}
		case "receive":
			if recvFlow == nil || len(f.RawBytes) > len(recvFlow.RawBytes) {
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

	// L4-capable principle: raw bytes must be present and contain the payload.
	if len(sendFlow.RawBytes) == 0 {
		t.Error("send flow RawBytes is empty (L4-capable principle violated)")
	}
	if len(recvFlow.RawBytes) == 0 {
		t.Error("receive flow RawBytes is empty (L4-capable principle violated)")
	}
	if !contains(sendFlow.RawBytes, payload) {
		t.Errorf("send flow RawBytes does not contain payload (got %q, want substring %q)", sendFlow.RawBytes, payload)
	}
	if !contains(recvFlow.RawBytes, payload) {
		t.Errorf("receive flow RawBytes does not contain echoed payload (got %q, want substring %q)", recvFlow.RawBytes, payload)
	}
}

// contains reports whether haystack contains needle (byte-wise).
// Standalone so the e2e file does not import bytes for one call.
func contains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// _ keeps io as a referenced import for the future when the test grows a
// streaming-body assertion. The current shape uses time/net/io transitively
// via the testing harness only.
var _ = io.EOF
