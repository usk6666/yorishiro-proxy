//go:build e2e && !e2e_smoke

// USK-1161 exhaustive tier: the TCP forward accept-time TargetScope gate
// and live-connection registration, driven through a real Manager and
// forward listener. The gate runs before client TLS termination and before
// the upstream dial, so a denied target is never contacted on any arm —
// including the L7 ones, whose dial / upstream ClientHello (SNI) / h2
// preface reach the target before any envelope exists for HostScopeStep.
package proxybuild_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// scopeForwardFixture is a running Manager whose Stack carries scope and
// liveConns, with one forward listener.
type scopeForwardFixture struct {
	scope     *connector.TargetScope
	liveConns *connector.LiveConns
	logs      *testutil.CaptureLogger
	store     *flowStoreCapture
	fwdAddr   string
	mgr       *proxybuild.Manager
}

// startScopeForward starts the fixture; opts adjust the parent listener's
// Deps (e.g. withRateLimiter).
func startScopeForward(t *testing.T, fc *config.ForwardConfig, opts ...func(*proxybuild.Deps)) *scopeForwardFixture {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	logs, logger := testutil.NewCaptureLogger()
	scope := connector.NewTargetScope()
	liveConns := connector.NewLiveConns(logger)
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
	}
	store := &flowStoreCapture{}
	mgr, err := proxybuild.NewManager(proxybuild.ManagerConfig{
		Logger:      logger,
		BuildConfig: buildCfg,
		StackFactory: func(ctx context.Context, name, addr string) (*proxybuild.Stack, error) {
			d := proxybuild.Deps{
				Logger:       logger,
				ListenerName: name,
				ListenAddr:   addr,
				FlowStore:    store,
				BuildConfig:  buildCfg,
				Scope:        scope,
				LiveConns:    liveConns,
			}
			for _, o := range opts {
				o(&d)
			}
			return proxybuild.BuildLiveStack(ctx, d)
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.StopAll(context.Background()) })
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	if err := mgr.StartTCPForwards(ctx, proxybuild.TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{"0": fc},
	}); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}
	fwdAddr := mgr.TCPForwardAddrs()["0"]
	if fwdAddr == "" {
		t.Fatal("forward listener not bound")
	}
	return &scopeForwardFixture{scope: scope, liveConns: liveConns, logs: logs, store: store, fwdAddr: fwdAddr, mgr: mgr}
}

// deny installs a Policy deny on the target's host:port, optionally only
// for the given schemes.
func (f *scopeForwardFixture) deny(t *testing.T, target string, schemes ...string) {
	t.Helper()
	host, p, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("split %q: %v", target, err)
	}
	port, _ := strconv.Atoi(p)
	f.scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: host, Ports: []int{port}, Schemes: schemes}})
}

// acceptCountingUpstream accepts TCP connections, counts them, and closes
// each at once.
func acceptCountingUpstream(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var accepts atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			_ = c.Close()
		}
	}()
	return ln.Addr().String(), &accepts
}

// settleAccepts waits until accepts reaches want or d elapses, and
// returns the final count.
func settleAccepts(accepts *atomic.Int64, want int64, d time.Duration) int64 {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if accepts.Load() >= want && want > 0 {
			return accepts.Load()
		}
		time.Sleep(10 * time.Millisecond)
	}
	return accepts.Load()
}

// readClosedNoBytes reads until the proxy closes c and fails if any byte
// arrives or the connection stays open past d.
func readClosedNoBytes(t *testing.T, c net.Conn, d time.Duration) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if n > 0 {
		t.Fatalf("read %d bytes (%q) from a denied forward, want none", n, buf[:n])
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("denied forward connection still open after %v", d)
	}
}

var h2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// TestProxybuild_TCPForwardScope_AcceptGateAllArms is test-plan 4: a deny
// added after the forward started is enforced at accept on every protocol
// arm and TLS combination, before client TLS termination and before the
// upstream dial: the upstream sees no connection, plaintext
// http / websocket / sse clients read a 403, every other client sees the
// connection closed (a tls=true client's handshake fails).
func TestProxybuild_TCPForwardScope_AcceptGateAllArms(t *testing.T) {
	protocols := []string{"raw", "auto", "http", "websocket", "sse", "http2", "grpc"}
	for _, proto := range protocols {
		for _, tlsCombo := range []struct{ tls, upstreamTLS bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
			name := fmt.Sprintf("%s/tls=%v/upstream_tls=%v", proto, tlsCombo.tls, tlsCombo.upstreamTLS)
			t.Run(name, func(t *testing.T) {
				target, accepts := acceptCountingUpstream(t)
				f := startScopeForward(t, &config.ForwardConfig{
					Target: target, Protocol: proto, TLS: tlsCombo.tls, UpstreamTLS: tlsCombo.upstreamTLS,
				})
				f.deny(t, target)

				switch {
				case tlsCombo.tls:
					nextProtos := []string{"http/1.1"}
					if proto == "http2" || proto == "grpc" {
						nextProtos = []string{"h2"}
					}
					tc, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", f.fwdAddr, &tls.Config{
						InsecureSkipVerify: true, //nolint:gosec // proxy's ephemeral MITM CA
						ServerName:         "127.0.0.1",
						NextProtos:         nextProtos,
					})
					if err == nil {
						_ = tc.Close()
						t.Errorf("client TLS handshake succeeded on a denied forward; want the gate to close before termination")
					}
				case proto == "http" || proto == "websocket" || proto == "sse":
					c := dialScopeForward(t, f.fwdAddr)
					_, _ = io.WriteString(c, "GET /usk1161 HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
					_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
					line, err := bufio.NewReader(c).ReadString('\n')
					if !strings.HasPrefix(line, "HTTP/1.1 403") {
						t.Errorf("status line = %q (err %v), want HTTP/1.1 403", line, err)
					}
				default:
					c := dialScopeForward(t, f.fwdAddr)
					probe := []byte{0x00, 0x01, 'u', 's', 'k', '1', '1', '6', '1'}
					if proto == "http2" || proto == "grpc" {
						probe = h2Preface
					}
					_, _ = c.Write(probe)
					readClosedNoBytes(t, c, 5*time.Second)
				}

				if got := settleAccepts(accepts, 0, 300*time.Millisecond); got != 0 {
					t.Errorf("denied upstream accepted %d connections, want 0", got)
				}
			})
		}
	}
}

func dialScopeForward(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestProxybuild_TCPForwardScope_SchemeIsDialLeg is test-plan 5 (user
// decision U1): the gate checks the upstream (dial) leg's scheme.
func TestProxybuild_TCPForwardScope_SchemeIsDialLeg(t *testing.T) {
	dialTLS := func(addr string) (*tls.Conn, error) {
		return tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // proxy's ephemeral MITM CA
			ServerName:         "127.0.0.1",
		})
	}

	t.Run("deny http, tls client, plaintext dial: denied", func(t *testing.T) {
		target, accepts := acceptCountingUpstream(t)
		f := startScopeForward(t, &config.ForwardConfig{Target: target, Protocol: "raw", TLS: true})
		f.deny(t, target, "http")
		if tc, err := dialTLS(f.fwdAddr); err == nil {
			_ = tc.Close()
			t.Errorf("client TLS handshake succeeded; want the gate to deny the plaintext egress")
		}
		if got := settleAccepts(accepts, 0, 300*time.Millisecond); got != 0 {
			t.Errorf("upstream accepted %d connections, want 0", got)
		}
	})

	t.Run("deny http, plaintext client, tls dial: admitted", func(t *testing.T) {
		target, accepts := acceptCountingUpstream(t)
		f := startScopeForward(t, &config.ForwardConfig{Target: target, Protocol: "raw", UpstreamTLS: true})
		f.deny(t, target, "http")
		c := dialScopeForward(t, f.fwdAddr)
		_, _ = c.Write([]byte{0x00, 0x01})
		if got := settleAccepts(accepts, 1, 5*time.Second); got != 1 {
			t.Errorf("upstream accepted %d connections, want 1 (the gate admits an https dial)", got)
		}
	})

	t.Run("deny https, tls client, plaintext dial: admitted at the gate", func(t *testing.T) {
		target, accepts := acceptCountingUpstream(t)
		f := startScopeForward(t, &config.ForwardConfig{Target: target, Protocol: "raw", TLS: true})
		f.deny(t, target, "https")
		tc, err := dialTLS(f.fwdAddr)
		if err != nil {
			t.Fatalf("client TLS handshake failed: %v; want the gate to admit (dial leg is http)", err)
		}
		defer tc.Close()
		if got := settleAccepts(accepts, 1, 5*time.Second); got != 1 {
			t.Errorf("upstream accepted %d connections, want 1", got)
		}
	})
}

// waitLiveConnsLen polls until the registry holds want entries.
func waitLiveConnsLen(t *testing.T, r *connector.LiveConns, want int, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for r.Len() != want {
		if time.Now().After(deadline) {
			t.Fatalf("live connections = %d after %v, want %d", r.Len(), d, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestProxybuild_TCPForwardScope_ReconcileCutsLiveConn is test-plan 6/7 at
// the Manager seam: an admitted forward connection is registered (via
// tcp-forward), an unchanged-scope Reconcile keeps it, and a Reconcile
// after a deny closes it and unwinds its handler.
func TestProxybuild_TCPForwardScope_ReconcileCutsLiveConn(t *testing.T) {
	t.Run("raw", func(t *testing.T) {
		target, stop := echoTCPServer(t)
		defer stop()
		f := startScopeForward(t, &config.ForwardConfig{Target: target, Protocol: "raw"})
		c := dialScopeForward(t, f.fwdAddr)
		msg := []byte("usk1161-raw")
		_, _ = c.Write(msg)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(c, got); err != nil {
			t.Fatalf("echo: %v", err)
		}
		waitLiveConnsLen(t, f.liveConns, 1, 5*time.Second)
		if n := f.liveConns.Reconcile("test-unchanged"); n != 0 {
			t.Fatalf("unchanged Reconcile revoked %d, want 0", n)
		}

		f.deny(t, target)
		if n := f.liveConns.Reconcile("test-deny"); n != 1 {
			t.Fatalf("Reconcile after deny revoked %d, want 1", n)
		}
		readClosedNoBytes(t, c, 5*time.Second)
		waitLiveConnsLen(t, f.liveConns, 0, 5*time.Second)
		if out := f.logs.Output(); !strings.Contains(out, "live connection closed") || !strings.Contains(out, "via=tcp-forward") {
			t.Errorf("missing Info 'live connection closed' with via=tcp-forward; logs:\n%s", out)
		}
	})

	t.Run("http keep-alive", func(t *testing.T) {
		var hits atomic.Int64
		up := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, _ *gohttp.Request) {
			hits.Add(1)
			_, _ = io.WriteString(w, "ok")
		}))
		defer up.Close()
		target := up.Listener.Addr().String()
		f := startScopeForward(t, &config.ForwardConfig{Target: target, Protocol: "http"})
		c := dialScopeForward(t, f.fwdAddr)
		br := bufio.NewReader(c)
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(c, "GET /1 HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
		resp, err := gohttp.ReadResponse(br, nil)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("GET /1 = %v, %v; want 200", resp, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		_ = c.SetDeadline(time.Time{})

		f.deny(t, target)
		if n := f.liveConns.Reconcile("test-deny"); n != 1 {
			t.Fatalf("Reconcile after deny revoked %d, want 1", n)
		}
		readClosedNoBytes(t, c, 5*time.Second)
		waitLiveConnsLen(t, f.liveConns, 0, 5*time.Second)
		if got := hits.Load(); got != 1 {
			t.Errorf("upstream hits = %d, want 1", got)
		}
	})

	t.Run("http2", func(t *testing.T) {
		target, shutdown := h2cEchoUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, _ *gohttp.Request) {
			_, _ = io.WriteString(w, "h2-ok")
		}))
		defer shutdown()
		f := startScopeForward(t, &config.ForwardConfig{Target: target, Protocol: "http2"})
		raw := dialScopeForward(t, f.fwdAddr)
		cc, err := (&http2.Transport{AllowHTTP: true}).NewClientConn(raw)
		if err != nil {
			t.Fatalf("NewClientConn: %v", err)
		}
		defer cc.Close()
		req, _ := gohttp.NewRequest(gohttp.MethodGet, "http://"+target+"/h2", nil)
		resp, err := cc.RoundTrip(req)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("h2 GET = %v, %v; want 200", resp, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		f.deny(t, target)
		if n := f.liveConns.Reconcile("test-deny"); n != 1 {
			t.Fatalf("Reconcile after deny revoked %d, want 1", n)
		}
		deadline := time.Now().Add(5 * time.Second)
		for !cc.State().Closed {
			if time.Now().After(deadline) {
				t.Fatalf("h2 forward connection still open 5s after the cut (state %+v)", cc.State())
			}
			time.Sleep(20 * time.Millisecond)
		}
		waitLiveConnsLen(t, f.liveConns, 0, 5*time.Second)
	})
}
