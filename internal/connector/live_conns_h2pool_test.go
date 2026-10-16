package connector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/pool"
)

// startH2Upstream runs a TLS listener that advertises ALPN h2 and keeps a
// ServerRole *http2.Layer open on every accepted connection until the test
// ends.
func startH2Upstream(t *testing.T) string {
	t.Helper()
	serverCfg, err := newSelfSignedTLSConfig("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	serverCfg.NextProtos = []string{"h2"}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				srv, err := http2.New(c, "test-upstream", http2.ServerRole, http2.WithScheme("https"))
				if err != nil {
					_ = c.Close()
					return
				}
				t.Cleanup(func() { _ = srv.Close() })
			}(c)
		}
	}()
	return ln.Addr().String()
}

// S-1 (USK-1160 review): when a MITM'd h2 CONNECT is cut because its target
// was revoked, the upstream h2 Layer must not go back to HTTP2Pool as an
// idle entry — the pool only prunes idle entries on a later Get for the
// same key, so a socket to the denied host would otherwise stay open
// indefinitely.
func TestCONNECTHandler_LiveConns_H2CutRetiresPooledUpstream(t *testing.T) {
	target := startH2Upstream(t)

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	h2Pool := pool.New(pool.PoolOptions{})
	t.Cleanup(func() { _ = h2Pool.Close() })

	scope := NewTargetScope()
	reg := NewLiveConns(newTestLogger())

	type h2Started struct {
		upstream *http2.Layer
		key      pool.PoolKey
	}
	startedCh := make(chan h2Started, 1)

	client, done := serveOneConn(t, NewCONNECTHandler(CONNECTHandlerConfig{
		Negotiator: NewCONNECTNegotiator(newTestLogger()),
		BuildCfg: &BuildConfig{
			ProxyConfig:        &config.ProxyConfig{},
			Issuer:             cert.NewIssuer(ca),
			InsecureSkipVerify: true,
			HTTP2Pool:          h2Pool,
		},
		Scope:            scope,
		LiveConns:        reg,
		InnerPeekTimeout: 2 * time.Second,
		OnHTTP2Stack: func(ctx context.Context, stack *ConnectionStack, upstreamH2 *http2.Layer, _, _ *envelope.TLSSnapshot, _ string) {
			startedCh <- h2Started{upstream: upstreamH2, key: stack.PoolKey()}
			<-ctx.Done()
		},
		Logger: newTestLogger(),
	}))
	connectThrough(t, client, target)

	host, _, _ := net.SplitHostPort(target)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate())
	clientTLS := tls.Client(client, &tls.Config{
		ServerName:         host,
		RootCAs:            roots,
		NextProtos:         []string{"h2"},
		InsecureSkipVerify: true, //nolint:gosec // test: MITM cert for an IP
	})
	_ = clientTLS.SetDeadline(time.Now().Add(5 * time.Second))
	if err := clientTLS.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	_ = clientTLS.SetDeadline(time.Time{})
	clientH2, err := http2.New(clientTLS, "test-client", http2.ClientRole, http2.WithScheme("https"))
	if err != nil {
		t.Fatalf("client http2.New: %v", err)
	}
	t.Cleanup(func() { _ = clientH2.Close() })

	var started h2Started
	select {
	case started = <-startedCh:
	case <-time.After(5 * time.Second):
		t.Fatal("h2 stack never reached OnHTTP2Stack")
	}

	denyHost(scope, "127.0.0.1")
	if n := reg.Reconcile("test"); n != 1 {
		t.Fatalf("Reconcile closed %d, want 1", n)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("CONNECT handler did not return after the cut")
	}

	if l, err := h2Pool.Get(started.key); err != nil || l != nil {
		if l != nil {
			h2Pool.Put(started.key, l)
		}
		t.Fatalf("pool still holds the revoked target's upstream Layer (got %p, err %v)", l, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !started.upstream.IsShutdown() {
		if time.Now().After(deadline) {
			t.Fatal("revoked target's upstream h2 Layer still open after the cut")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
