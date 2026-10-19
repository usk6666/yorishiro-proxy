//go:build e2e && !e2e_smoke

// USK-1250 exhaustive tier: a TargetScope deny must hold against every
// spelling of the denied host that the proxy would still dial to it —
// IPv4-mapped IPv6, an IPv6 zone, a single trailing dot — on every
// data-path gate (CONNECT, SOCKS5, plain-HTTP forward, tcp_forwards), driven
// through a real Manager + BuildLiveStack and an accept-counting upstream on
// 127.0.0.1. Every deny case has a positive control proving the same alias
// does reach the upstream when the deny does not cover its port, so a zero
// accept count is not vacuous.
package proxybuild_test

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// aliasProxyFixture is a running Manager whose main listener carries scope.
type aliasProxyFixture struct {
	scope     *connector.TargetScope
	mgr       *proxybuild.Manager
	store     *flowStoreCapture
	proxyAddr string
	ctx       context.Context
}

func startAliasProxy(t *testing.T) *aliasProxyFixture {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	_, logger := testutil.NewCaptureLogger()
	scope := connector.NewTargetScope()
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
			return proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
				Logger:       logger,
				ListenerName: name,
				ListenAddr:   addr,
				FlowStore:    store,
				BuildConfig:  buildCfg,
				Scope:        scope,
				LiveConns:    connector.NewLiveConns(logger),
			})
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.StopAll(context.Background()) })
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	_, addr := mgr.Status()
	if addr == "" {
		t.Fatal("main listener not bound")
	}
	return &aliasProxyFixture{scope: scope, mgr: mgr, store: store, proxyAddr: addr, ctx: ctx}
}

// denyPort installs a Policy deny on host restricted to port.
func (f *aliasProxyFixture) denyPort(host string, port int) {
	f.scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: host, Ports: []int{port}}})
}

func portOf(t *testing.T, addr string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("port %q: %v", p, err)
	}
	return n
}

// requireLocalhostDot skips when the resolver cannot resolve "localhost."
// (the alias is only a bypass where it resolves).
func requireLocalhostDot(t *testing.T) {
	t.Helper()
	if _, err := net.LookupHost("localhost."); err != nil {
		t.Skipf("resolver does not resolve %q here: %v", "localhost.", err)
	}
}

// aliasCase is one alias spelling of a denied host.
type aliasCase struct {
	name     string
	denyHost string // the rule as an operator writes it
	alias    string // host as the client spells it (bracketed IPv6 as in an authority)
	dotHost  bool   // alias relies on resolving "localhost."
}

var aliasCases = []aliasCase{
	{"ipv4-mapped", "127.0.0.1", "[::ffff:127.0.0.1]", false},
	{"ipv4-mapped hex", "127.0.0.1", "[::ffff:7f00:1]", false},
	{"ipv4-mapped with zone", "127.0.0.1", "[::ffff:127.0.0.1%bogus]", false},
	{"trailing dot", "localhost", "localhost.", true},
}

// connectStatus sends "CONNECT authority" and returns the status line, or
// "" when the proxy closes without answering.
func connectStatus(t *testing.T, proxyAddr, authority string) (net.Conn, *bufio.Reader, string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, "CONNECT "+authority+" HTTP/1.1\r\nHost: "+authority+"\r\n\r\n")
	br := bufio.NewReader(c)
	line, _ := br.ReadString('\n')
	return c, br, line
}

// TestProxybuild_ScopeHostAlias_CONNECT is test-plan 1/2: CONNECT to an
// alias of a denied host is refused before any upstream dial.
func TestProxybuild_ScopeHostAlias_CONNECT(t *testing.T) {
	for _, tc := range aliasCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.dotHost {
				requireLocalhostDot(t)
			}
			denied, deniedAccepts := acceptCountingUpstream(t)
			control, controlAccepts := acceptCountingUpstream(t)
			f := startAliasProxy(t)
			f.denyPort(tc.denyHost, portOf(t, denied))

			// Positive control: the same alias on a port the deny does not
			// cover is tunnelled and dialled.
			c, _, line := connectStatus(t, f.proxyAddr, tc.alias+":"+strconv.Itoa(portOf(t, control)))
			if !strings.Contains(line, " 200") {
				t.Fatalf("control CONNECT status = %q, want 200", line)
			}
			_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: control\r\n\r\n")
			if got := settleAccepts(controlAccepts, 1, 5*time.Second); got < 1 {
				t.Fatalf("control upstream accepted %d connections, want >= 1 (alias must dial loopback)", got)
			}

			c2, _, line := connectStatus(t, f.proxyAddr, tc.alias+":"+strconv.Itoa(portOf(t, denied)))
			if strings.Contains(line, " 200") {
				_, _ = io.WriteString(c2, "GET / HTTP/1.1\r\nHost: denied\r\n\r\n")
				t.Errorf("CONNECT %s to a host denied as %q = %q, want refused", tc.alias, tc.denyHost, line)
			}
			if got := settleAccepts(deniedAccepts, 0, 500*time.Millisecond); got != 0 {
				t.Errorf("denied upstream accepted %d connections via alias %s, want 0", got, tc.alias)
			}
		})
	}
}

// socks5Connect runs a no-auth SOCKS5 CONNECT with ATYP=domain and returns
// the reply REP byte (0xff when no reply arrived).
func socks5Connect(t *testing.T, proxyAddr, domain string, port int) (net.Conn, byte) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("socks5 greeting: %v", err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(c, method); err != nil {
		t.Fatalf("socks5 method selection: %v", err)
	}
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(domain))}
	req = append(req, domain...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := c.Write(req); err != nil {
		t.Fatalf("socks5 connect: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(c, reply); err != nil {
		return c, 0xff
	}
	return c, reply[1]
}

// TestProxybuild_ScopeHostAlias_SOCKS5 is test-plan 3: an ATYP=domain
// alias of a denied host is refused with REP=0x02.
func TestProxybuild_ScopeHostAlias_SOCKS5(t *testing.T) {
	cases := []aliasCase{
		{"ipv4-mapped", "127.0.0.1", "::ffff:127.0.0.1", false},
		{"ipv4-mapped with zone", "127.0.0.1", "::ffff:127.0.0.1%bogus", false},
		{"trailing dot", "localhost", "localhost.", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.dotHost {
				requireLocalhostDot(t)
			}
			denied, deniedAccepts := acceptCountingUpstream(t)
			control, controlAccepts := acceptCountingUpstream(t)
			f := startAliasProxy(t)
			f.denyPort(tc.denyHost, portOf(t, denied))

			c, rep := socks5Connect(t, f.proxyAddr, tc.alias, portOf(t, control))
			if rep != 0x00 {
				t.Fatalf("control SOCKS5 REP = %#x, want 0x00", rep)
			}
			_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: control\r\n\r\n")
			if got := settleAccepts(controlAccepts, 1, 5*time.Second); got < 1 {
				t.Fatalf("control upstream accepted %d connections, want >= 1", got)
			}

			c2, rep := socks5Connect(t, f.proxyAddr, tc.alias, portOf(t, denied))
			if rep != 0x02 {
				_, _ = io.WriteString(c2, "GET / HTTP/1.1\r\nHost: denied\r\n\r\n")
				t.Errorf("SOCKS5 %s to a host denied as %q: REP = %#x, want 0x02", tc.alias, tc.denyHost, rep)
			}
			if got := settleAccepts(deniedAccepts, 0, 500*time.Millisecond); got != 0 {
				t.Errorf("denied upstream accepted %d connections via alias %s, want 0", got, tc.alias)
			}
		})
	}
}

// forwardStatus sends one plain-HTTP forward request and returns the
// status line.
func forwardStatus(t *testing.T, proxyAddr, requestTarget, hostHeader string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, "GET "+requestTarget+" HTTP/1.1\r\nHost: "+hostHeader+"\r\nConnection: close\r\n\r\n")
	line, _ := bufio.NewReader(c).ReadString('\n')
	return line
}

// TestProxybuild_ScopeHostAlias_PlainForward is test-plan 4: absolute-form
// and origin-form plain-HTTP forward requests naming an alias of a denied
// host get a 403 and no upstream connection.
func TestProxybuild_ScopeHostAlias_PlainForward(t *testing.T) {
	for _, tc := range aliasCases {
		for _, form := range []string{"absolute-form", "origin-form"} {
			if form == "absolute-form" && strings.Contains(tc.alias, "%") {
				// An unescaped zone ("%bogus") is not a valid URL host, so the
				// absolute-form parser rejects the request before any gate
				// or dial; the control would never reach the upstream.
				continue
			}
			t.Run(tc.name+"/"+form, func(t *testing.T) {
				if tc.dotHost {
					requireLocalhostDot(t)
				}
				denied, deniedAccepts := acceptCountingUpstream(t)
				control, controlAccepts := acceptCountingUpstream(t)
				f := startAliasProxy(t)
				f.denyPort(tc.denyHost, portOf(t, denied))

				send := func(port int) string {
					authority := tc.alias + ":" + strconv.Itoa(port)
					target := "/usk1250"
					if form == "absolute-form" {
						target = "http://" + authority + "/usk1250"
					}
					return forwardStatus(t, f.proxyAddr, target, authority)
				}

				// Positive control: the alias is forwarded to the upstream
				// (which closes at once, so the status is a 502-class error).
				_ = send(portOf(t, control))
				if got := settleAccepts(controlAccepts, 1, 5*time.Second); got < 1 {
					t.Fatalf("control upstream accepted %d connections, want >= 1", got)
				}

				if line := send(portOf(t, denied)); !strings.HasPrefix(line, "HTTP/1.1 403") {
					t.Errorf("forward to %s denied as %q: status = %q, want HTTP/1.1 403", tc.alias, tc.denyHost, line)
				}
				if got := settleAccepts(deniedAccepts, 0, 500*time.Millisecond); got != 0 {
					t.Errorf("denied upstream accepted %d connections via alias %s, want 0", got, tc.alias)
				}
			})
		}
	}
}

// TestProxybuild_ScopeHostAlias_TCPForward is test-plan 5: a tcp_forwards
// target spelled as an alias of a denied host is refused at start, and an
// already-running alias forward is refused at accept once the deny lands.
func TestProxybuild_ScopeHostAlias_TCPForward(t *testing.T) {
	for _, tc := range aliasCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.dotHost {
				requireLocalhostDot(t)
			}

			t.Run("start", func(t *testing.T) {
				upstream, accepts := acceptCountingUpstream(t)
				f := startAliasProxy(t)
				f.denyPort(tc.denyHost, portOf(t, upstream))
				err := f.mgr.StartTCPForwards(f.ctx, proxybuild.TCPForwardParams{
					Forwards: map[string]*config.ForwardConfig{
						"0": {Target: tc.alias + ":" + strconv.Itoa(portOf(t, upstream)), Protocol: "raw"},
					},
				})
				if !errors.Is(err, proxybuild.ErrTCPForwardTargetBlocked) {
					t.Errorf("StartTCPForwards(%s) error = %v, want ErrTCPForwardTargetBlocked", tc.alias, err)
				}
				if got := settleAccepts(accepts, 0, 300*time.Millisecond); got != 0 {
					t.Errorf("denied upstream accepted %d connections, want 0", got)
				}
			})

			t.Run("accept", func(t *testing.T) {
				upstream, accepts := acceptCountingUpstream(t)
				f := startScopeForward(t, &config.ForwardConfig{
					Target: tc.alias + ":" + strconv.Itoa(portOf(t, upstream)), Protocol: "raw",
				})
				// Positive control: before the deny, the alias forward dials
				// the upstream.
				c := dialScopeForward(t, f.fwdAddr)
				_, _ = c.Write([]byte("usk1250"))
				if got := settleAccepts(accepts, 1, 5*time.Second); got != 1 {
					t.Fatalf("control: upstream accepted %d connections, want 1", got)
				}

				f.scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: tc.denyHost, Ports: []int{portOf(t, upstream)}}})
				c2 := dialScopeForward(t, f.fwdAddr)
				_, _ = c2.Write([]byte("usk1250"))
				readClosedNoBytes(t, c2, 5*time.Second)
				if got := settleAccepts(accepts, 2, 500*time.Millisecond); got != 1 {
					t.Errorf("upstream accepted %d connections after the deny, want 1 (the control only)", got)
				}
			})
		})
	}
}

// recordingUpstream is an HTTP/1.1 upstream that captures each request head
// verbatim and answers 200.
func recordingUpstream(t *testing.T) (addr string, heads func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var mu sync.Mutex
	var got []string
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				var head strings.Builder
				for {
					line, err := br.ReadString('\n')
					head.WriteString(line)
					if err != nil || line == "\r\n" {
						break
					}
				}
				mu.Lock()
				got = append(got, head.String())
				mu.Unlock()
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			}(c)
		}
	}()
	return ln.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), got...)
	}
}

// TestProxybuild_ScopeHostAlias_AllowedAliasStaysVerbatim is test-plan 10:
// folding is comparison-only. Under a Policy allow written as "localhost"
// / "127.0.0.1", an alias-spelled request is admitted, and the upstream
// receives and the flow records the alias spelling — never the folded one.
func TestProxybuild_ScopeHostAlias_AllowedAliasStaysVerbatim(t *testing.T) {
	cases := []aliasCase{
		{"ipv4-mapped", "127.0.0.1", "[::ffff:127.0.0.1]", false},
		{"trailing dot", "localhost", "localhost.", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.dotHost {
				requireLocalhostDot(t)
			}
			upstream, heads := recordingUpstream(t)
			f := startAliasProxy(t)
			f.scope.SetPolicyRules([]connector.TargetRule{{Hostname: tc.denyHost}}, nil)

			authority := tc.alias + ":" + strconv.Itoa(portOf(t, upstream))
			line := forwardStatus(t, f.proxyAddr, "http://"+authority+"/usk1250", authority)
			if !strings.HasPrefix(line, "HTTP/1.1 200") {
				t.Fatalf("allowed alias forward status = %q, want HTTP/1.1 200", line)
			}

			var seen []string
			deadline := time.Now().Add(5 * time.Second)
			for len(seen) == 0 && time.Now().Before(deadline) {
				seen = heads()
				time.Sleep(10 * time.Millisecond)
			}
			if len(seen) != 1 {
				t.Fatalf("upstream saw %d requests, want 1", len(seen))
			}
			if !strings.Contains(seen[0], "\r\nHost: "+authority+"\r\n") {
				t.Errorf("upstream request head lost the verbatim Host %q:\n%s", authority, seen[0])
			}

			wantHost := strings.TrimSuffix(strings.TrimPrefix(tc.alias, "["), "]")
			var recorded bool
			deadline = time.Now().Add(5 * time.Second)
			for !recorded && time.Now().Before(deadline) {
				for _, fl := range f.store.Flows() {
					if fl.Direction == "send" && fl.URL != nil {
						recorded = true
						if fl.URL.Hostname() != wantHost {
							t.Errorf("recorded flow URL host = %q, want verbatim %q", fl.URL.Hostname(), wantHost)
						}
					}
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !recorded {
				t.Fatal("no send flow with a URL was recorded")
			}
		})
	}
}
