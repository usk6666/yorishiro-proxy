//go:build e2e

// Shared test helpers for proxybuild h2-pool integration tests.
//
// These helpers stage a TLS h2 upstream + a CONNECT-tunnel client + a
// BuildLiveStack-assembled proxy with HTTP2Pool wired in. They are used
// by both the smoke tier (USK-993 OpenStream-retry coverage —
// h2_openstream_retry_integration_test.go) and the full tier (USK-816
// h2-pool intercept coverage — h2_pool_intercept_integration_test.go).
// Putting them under //go:build e2e (no `!e2e_smoke` exclusion) lets the
// merge-gate smoke run pick them up.
package proxybuild_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	gohttp "net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	h2pool "github.com/usk6666/yorishiro-proxy/internal/layer/http2/pool"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// startH2TLSUpstreamForPoolTest spins up a TLS upstream that serves HTTP/2 via
// golang.org/x/net/http2.Server. Returns the listener addr, an accept counter
// (used to verify pool reuse), and a shutdown closure.
func startH2TLSUpstreamForPoolTest(t *testing.T, cn string, handler gohttp.Handler) (addr string, acceptCount func() int64, shutdown func()) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{cn, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
		}},
		NextProtos: []string{"h2"},
	}

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepts atomic.Int64
	h2s := &http2.Server{}

	var wg sync.WaitGroup
	go func() {
		for {
			c, aerr := tcpLn.Accept()
			if aerr != nil {
				return
			}
			accepts.Add(1)
			tlsConn := tls.Server(c, tlsCfg)
			wg.Add(1)
			go func(tc *tls.Conn) {
				defer wg.Done()
				defer tc.Close()
				if herr := tc.Handshake(); herr != nil {
					return
				}
				h2s.ServeConn(tc, &http2.ServeConnOpts{Handler: handler})
			}(tlsConn)
		}
	}()

	return tcpLn.Addr().String(), func() int64 { return accepts.Load() }, func() {
		_ = tcpLn.Close()
		doneCh := make(chan struct{})
		go func() { wg.Wait(); close(doneCh) }()
		select {
		case <-doneCh:
		case <-time.After(2 * time.Second):
		}
	}
}

// connectTunnelDialerForPoolTest opens a CONNECT tunnel to proxyAddr for the
// given target.
func connectTunnelDialerForPoolTest(proxyAddr, target string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, werr := c.Write([]byte(req)); werr != nil {
		c.Close()
		return nil, werr
	}
	br := bytes.NewBuffer(nil)
	buf := make([]byte, 1)
	for {
		n, rerr := c.Read(buf)
		if rerr != nil {
			c.Close()
			return nil, rerr
		}
		if n == 0 {
			continue
		}
		br.Write(buf[:n])
		text := br.String()
		if (len(text) >= 4 && text[len(text)-4:] == "\r\n\r\n") || (len(text) >= 2 && text[len(text)-2:] == "\n\n") {
			break
		}
		if br.Len() > 4096 {
			c.Close()
			return nil, fmt.Errorf("CONNECT response too large")
		}
	}
	if !bytes.Contains(br.Bytes(), []byte(" 200")) {
		c.Close()
		return nil, fmt.Errorf("CONNECT failed: %s", br.String())
	}
	return c, nil
}

// newH2ClientThroughProxyForPoolTest wires an http.Client that funnels every
// request through proxyAddr using CONNECT + TLS h2.
func newH2ClientThroughProxyForPoolTest(proxyAddr, target string) *gohttp.Client {
	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test
			NextProtos:         []string{"h2"},
		},
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			raw, err := connectTunnelDialerForPoolTest(proxyAddr, target)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(raw, cfg)
			if err := tlsConn.Handshake(); err != nil {
				raw.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}
	return &gohttp.Client{Transport: tr, Timeout: 30 * time.Second}
}

// startProxyForH2PoolInterceptTest builds a live Stack via BuildLiveStack and
// starts its listener. The stack is wired with a non-nil HTTP2Pool to mirror
// production wiring (mcpserver/init.go:467).
func startProxyForH2PoolInterceptTest(
	t *testing.T,
	ctx context.Context,
	store flow.Writer,
	intercept *httprules.InterceptEngine,
	holdQueue *common.HoldQueue,
	pool *h2pool.Pool,
) (proxyAddr string) {
	t.Helper()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}

	logger := testutil.DiscardLogger()
	if testing.Verbose() && os.Getenv("USK816_DEBUG") != "" {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	deps := proxybuild.Deps{
		Logger:       logger,
		ListenerName: "usk-pool-test",
		ListenAddr:   "127.0.0.1:0",
		FlowStore:    store,
		BuildConfig: &connector.BuildConfig{
			ProxyConfig:        &config.ProxyConfig{},
			Issuer:             cert.NewIssuer(ca),
			InsecureSkipVerify: true,
			HTTP2Pool:          pool,
		},
		HTTPInterceptEngine: intercept,
		HoldQueue:           holdQueue,
	}

	stack, err := proxybuild.BuildLiveStack(ctx, deps)
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	go func() { _ = stack.Listener.Start(ctx) }()

	select {
	case <-stack.Listener.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("listener not ready in 5s")
	}
	addr := stack.Listener.Addr()
	if addr == "" {
		t.Fatal("listener has no addr")
	}
	return addr
}

// flowStoreForH2Pool is a flow.Writer that records every Stream/Flow under a
// mutex so test goroutines can inspect them safely.
type flowStoreForH2Pool struct {
	mu      sync.Mutex
	streams []*flow.Stream
	updates map[string][]flow.StreamUpdate
	flows   []*flow.Flow
}

func (s *flowStoreForH2Pool) SaveStream(_ context.Context, st *flow.Stream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *st
	s.streams = append(s.streams, &cp)
	return nil
}

func (s *flowStoreForH2Pool) UpdateStream(_ context.Context, id string, upd flow.StreamUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.updates == nil {
		s.updates = make(map[string][]flow.StreamUpdate)
	}
	s.updates[id] = append(s.updates[id], upd)
	for _, st := range s.streams {
		if st.ID == id {
			if upd.State != "" {
				st.State = upd.State
			}
			if upd.FailureReason != "" {
				st.FailureReason = upd.FailureReason
			}
		}
	}
	return nil
}

func (s *flowStoreForH2Pool) SaveFlow(_ context.Context, f *flow.Flow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *f
	s.flows = append(s.flows, &cp)
	return nil
}

func (s *flowStoreForH2Pool) Streams() []*flow.Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*flow.Stream, len(s.streams))
	copy(out, s.streams)
	return out
}

func (s *flowStoreForH2Pool) Flows() []*flow.Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*flow.Flow, len(s.flows))
	copy(out, s.flows)
	return out
}

// releaseFirstHeldEntry waits up to timeout for the queue to receive a held
// entry and then releases it with the given action. Returns the released
// entry so the caller can mutate it for modify_and_forward.
func releaseFirstHeldEntry(t *testing.T, q *common.HoldQueue, timeout time.Duration, build func(held *common.HeldEntry) *common.HoldAction) *common.HeldEntry {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if q.Len() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	entries := q.List()
	if len(entries) == 0 {
		t.Fatal("no held entry observed within timeout")
	}
	held := entries[0]
	if err := q.Release(held.ID, build(held)); err != nil {
		t.Fatalf("HoldQueue.Release: %v", err)
	}
	return held
}
