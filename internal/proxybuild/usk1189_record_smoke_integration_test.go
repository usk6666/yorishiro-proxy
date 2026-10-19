//go:build e2e

// USK-1189 merge-gate coverage: the second half of USK-1181. A CONNECT
// request the proxy cuts off at request_timeout_ms, a plain-forward request
// whose target peek is cut off, and a client TLS MITM handshake the proxy
// abandons at the same deadline must each leave a distinguishable record.
package proxybuild_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

type usk1189Fixture struct {
	mgr       *proxybuild.Manager
	store     *usk1181Store
	buildCfg  *connector.BuildConfig
	proxyAddr string
}

// startUSK1189Proxy starts a Manager-backed live stack recording into a
// usk1181Store. requestTimeout <= 0 leaves request_timeout_ms unset.
func startUSK1189Proxy(t *testing.T, ctx context.Context, pcfg *config.ProxyConfig, mutate func(*connector.BuildConfig), requestTimeout time.Duration) *usk1189Fixture {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	if pcfg == nil {
		pcfg = &config.ProxyConfig{}
	}
	buildCfg := &connector.BuildConfig{
		ProxyConfig:        pcfg,
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
	}
	if mutate != nil {
		mutate(buildCfg)
	}
	store := &usk1181Store{}
	logger := testutil.DiscardLogger()
	mgr, err := proxybuild.NewManager(proxybuild.ManagerConfig{
		Logger: logger,
		StackFactory: func(_ context.Context, name, addr string) (*proxybuild.Stack, error) {
			return proxybuild.BuildLiveStack(context.Background(), proxybuild.Deps{
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
	t.Cleanup(func() { _ = mgr.StopAll(context.Background()) })
	if requestTimeout > 0 {
		mgr.SetRequestTimeout(requestTimeout)
	}
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	_, proxyAddr := mgr.Status()
	return &usk1189Fixture{mgr: mgr, store: store, buildCfg: buildCfg, proxyAddr: proxyAddr}
}

// usk1189SendAndAwaitClose writes payload, then reads until the proxy
// closes the connection, failing if it is still open after guard. Returns
// every byte read.
func usk1189SendAndAwaitClose(t *testing.T, addr, payload string, guard time.Duration) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(guard))
	got, err := io.ReadAll(conn)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("proxy still holds the connection open after %v", guard)
	}
	return got
}

// assertOnlySendFlow re-reads the stream's flows after a settle window and
// fails if anything other than the single send flow was recorded.
func assertOnlySendFlow(t *testing.T, store *usk1181Store, st *flow.Stream) *flow.Flow {
	t.Helper()
	time.Sleep(200 * time.Millisecond)
	flows := store.flowsOf(st.ID)
	if len(flows) != 1 || flows[0].Direction != "send" || flows[0].Sequence != 0 {
		var got []string
		for _, f := range flows {
			got = append(got, fmt.Sprintf("%s/%d", f.Direction, f.Sequence))
		}
		t.Fatalf("flows = %v, want exactly one send flow at sequence 0", got)
	}
	return flows[0]
}

// TestProxybuild_CONNECT_RequestTimeoutRecorded_Smoke (T1): a CONNECT
// request cut off by request_timeout_ms after bytes arrived is recorded as
// connect_request_timeout with the bytes received.
func TestProxybuild_CONNECT_RequestTimeoutRecorded_Smoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fix := startUSK1189Proxy(t, ctx, nil, nil, 300*time.Millisecond)

	payload := "CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\nX-Pa"
	if got := usk1189SendAndAwaitClose(t, fix.proxyAddr, payload, 3*time.Second); len(got) != 0 {
		t.Errorf("proxy replied to a stalled CONNECT: %q", got)
	}

	st, _ := awaitErrorStream(t, fix.store, "connect_request_timeout", 1, 5*time.Second)
	if st.Protocol != "http" {
		t.Errorf("Protocol = %q, want http", st.Protocol)
	}
	if st.ConnID == "" {
		t.Error("ConnID is empty")
	}
	for k, v := range map[string]string{
		"closed_by":          "proxy",
		"phase":              "connect_request",
		"request_timeout_ms": "300",
		"target":             "127.0.0.1:1",
	} {
		if st.Tags[k] != v {
			t.Errorf("Tags[%q] = %q, want %q", k, st.Tags[k], v)
		}
	}
	if st.Tags["listener"] == "" {
		t.Error("Tags[listener] is empty")
	}
	if _, ok := st.Tags["wrote_response"]; ok {
		t.Errorf("Tags[wrote_response] = %q, want absent (no response is sent)", st.Tags["wrote_response"])
	}
	send := assertOnlySendFlow(t, fix.store, st)
	if string(send.RawBytes) != payload {
		t.Errorf("send RawBytes = %q, want %q", send.RawBytes, payload)
	}
	if send.Method != "CONNECT" {
		t.Errorf("send Method = %q, want CONNECT", send.Method)
	}
}

// TestProxybuild_PlainForward_PeekTimeoutRecorded_Smoke (T3): a
// plain-forward request head under the 4000-byte target peek that stalls is
// still answered 400, and both the bytes received and the 400 are recorded.
func TestProxybuild_PlainForward_PeekTimeoutRecorded_Smoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fix := startUSK1189Proxy(t, ctx, nil, nil, 300*time.Millisecond)

	payload := "GET http://127.0.0.1:9/x HTTP/1.1\r\nHo"
	got := usk1189SendAndAwaitClose(t, fix.proxyAddr, payload, 3*time.Second)
	if !strings.HasPrefix(string(got), "HTTP/1.1 400 Bad Request\r\n") {
		t.Fatalf("client read %q, want the 400", got)
	}

	st, flows := awaitErrorStream(t, fix.store, "request_head_timeout", 2, 5*time.Second)
	if st.Protocol != "http" || st.Scheme != "http" {
		t.Errorf("Protocol/Scheme = %q/%q, want http/http", st.Protocol, st.Scheme)
	}
	for k, v := range map[string]string{
		"closed_by":          "proxy",
		"phase":              "headers",
		"request_timeout_ms": "300",
		"wrote_response":     "true",
	} {
		if st.Tags[k] != v {
			t.Errorf("Tags[%q] = %q, want %q", k, st.Tags[k], v)
		}
	}
	var send, recv *flow.Flow
	for _, f := range flows {
		switch f.Direction {
		case "send":
			send = f
		case "receive":
			recv = f
		}
	}
	if send == nil || recv == nil {
		t.Fatalf("flows missing send or receive: %d flows", len(flows))
	}
	if send.Sequence != 0 || string(send.RawBytes) != payload {
		t.Errorf("send seq/RawBytes = %d/%q, want 0/%q", send.Sequence, send.RawBytes, payload)
	}
	if send.Method != "GET" {
		t.Errorf("send Method = %q, want GET", send.Method)
	}
	if recv.Sequence != 1 || recv.StatusCode != 400 {
		t.Errorf("receive seq/status = %d/%d, want 1/400", recv.Sequence, recv.StatusCode)
	}
	if string(recv.RawBytes) != string(got) {
		t.Errorf("receive RawBytes = %q, want the bytes the client read %q", recv.RawBytes, got)
	}
	if recv.Metadata["proxy_generated"] != "true" {
		t.Errorf("receive Metadata[proxy_generated] = %q, want true", recv.Metadata["proxy_generated"])
	}
}

// usk1189FirstWriteOnlyConn forwards only the first Write (the
// ClientHello) so the client's handshake runs locally to completion while
// the proxy never receives the client Finished.
type usk1189FirstWriteOnlyConn struct {
	net.Conn
	once    sync.Once
	written atomic.Bool
}

func (c *usk1189FirstWriteOnlyConn) Write(b []byte) (int, error) {
	if c.written.Load() {
		return len(b), nil
	}
	n, err := c.Conn.Write(b)
	c.once.Do(func() { c.written.Store(true) })
	return n, err
}

// usk1189StallTLSHandshake runs a client TLS handshake over conn whose
// Finished never reaches the proxy, then waits for the proxy to close.
func usk1189StallTLSHandshake(t *testing.T, conn net.Conn) {
	t.Helper()
	tc := tls.Client(&usk1189FirstWriteOnlyConn{Conn: conn}, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS13}) //nolint:gosec // test
	hsDone := make(chan struct{})
	go func() {
		defer close(hsDone)
		_ = tc.Handshake()
	}()
	select {
	case <-hsDone:
	case <-time.After(5 * time.Second):
		t.Fatal("client half of the TLS handshake did not finish")
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := io.Copy(io.Discard, conn)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("proxy still holds the stalled TLS handshake open after 3s")
	}
}

var usk1189TLSTimeoutTagKeys = []string{"phase", "closed_by", "timeout", "request_timeout_ms"}

// TestProxybuild_CONNECT_TLSHandshakeTimeoutTagged_Smoke (T5): a client
// TLS MITM handshake the proxy abandons at request_timeout_ms keeps
// FailureReason=client_tls_error and gains the timeout tags.
func TestProxybuild_CONNECT_TLSHandshakeTimeoutTagged_Smoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	target := "127.0.0.1:1"
	fix := startUSK1189Proxy(t, ctx, &config.ProxyConfig{RawPassthroughHosts: []string{target}}, nil, 300*time.Millisecond)

	conn, err := net.DialTimeout("tcp", fix.proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	buf := make([]byte, 256)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), "200") {
		t.Fatalf("CONNECT response = %q, err = %v", buf[:n], err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	usk1189StallTLSHandshake(t, conn)

	st, _ := awaitErrorStream(t, fix.store, "client_tls_error", 0, 5*time.Second)
	for k, v := range map[string]string{
		"phase":              "tls_handshake",
		"closed_by":          "proxy",
		"timeout":            "request_timeout",
		"request_timeout_ms": "300",
		"target":             target,
	} {
		if st.Tags[k] != v {
			t.Errorf("Tags[%q] = %q, want %q", k, st.Tags[k], v)
		}
	}
	if st.Tags["error"] == "" {
		t.Error("Tags[error] is empty")
	}
}

// TestProxybuild_CONNECT_TLSCertRejection_NotTimeoutTagged_Smoke (T6): the
// reverse direction — a client that rejects the MITM certificate is still
// client_tls_error, without any of the timeout tags.
func TestProxybuild_CONNECT_TLSCertRejection_NotTimeoutTagged_Smoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	target := "127.0.0.1:1"
	fix := startUSK1189Proxy(t, ctx, &config.ProxyConfig{RawPassthroughHosts: []string{target}}, nil, 5*time.Second)

	if err := connectAndAttemptHandshakeWithEmptyRoots(t, fix.proxyAddr, target); err == nil {
		t.Fatal("client TLS handshake unexpectedly succeeded")
	}
	st, _ := awaitErrorStream(t, fix.store, "client_tls_error", 0, 5*time.Second)
	for _, k := range usk1189TLSTimeoutTagKeys {
		if v, ok := st.Tags[k]; ok {
			t.Errorf("Tags[%q] = %q, want absent on a certificate rejection (error=%q)", k, v, st.Tags["error"])
		}
	}
}
