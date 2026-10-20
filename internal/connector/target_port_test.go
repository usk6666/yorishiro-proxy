package connector

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-1249: the plain-HTTP forward target port must be what the dialer
// connects to. net.Dial resolves service names ("postgresql" → 5432) and,
// in Go's parsePort, wraps a 10-digit decimal modulo 2^32
// ("4294967376" → 80), while TargetScope checked strconv.Atoi's result
// (0 on a service name, the unwrapped value on the 10-digit form). Either
// discrepancy slipped past a port-scoped deny.

func TestSplitTargetHostPort(t *testing.T) {
	cases := []struct {
		target   string
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{target: "h:80", wantHost: "h", wantPort: 80},
		{target: "h:05432", wantHost: "h", wantPort: 5432},
		{target: "[::1]:443", wantHost: "::1", wantPort: 443},
		{target: "h:65535", wantHost: "h", wantPort: 65535},
		{target: "h:1", wantHost: "h", wantPort: 1},
		{target: "h:postgresql", wantErr: true},
		{target: "h:http", wantErr: true},
		{target: "h:+5432", wantErr: true},
		{target: "h:-1", wantErr: true},
		{target: "h: 80", wantErr: true},
		{target: "h:80 ", wantErr: true},
		{target: "h:", wantErr: true},
		{target: "h:0", wantErr: true},
		{target: "h:65536", wantErr: true},
		{target: "h:4294967376", wantErr: true},
		{target: "h:99999999999999999999999", wantErr: true},
		{target: "h:١٢", wantErr: true},
		{target: "h", wantErr: true},
		{target: "[::1]", wantErr: true},
		{target: "", wantErr: true},
		// USK-1264 U2: bracket content must be an IPv6 literal.
		{target: "[fe80::1%eth0]:80", wantHost: "fe80::1%eth0", wantPort: 80},
		{target: "[::ffff:1.2.3.4]:80", wantHost: "::ffff:1.2.3.4", wantPort: 80},
		{target: "[db.internal:5432]:80", wantErr: true},
		{target: "[db.internal]:80", wantErr: true},
		{target: "[localhost:1]:80", wantErr: true},
		{target: "[1.2.3.4]:80", wantErr: true},
		{target: "[]:80", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.target, func(t *testing.T) {
			host, port, err := SplitTargetHostPort(c.target)
			if c.wantErr {
				if err == nil {
					t.Fatalf("SplitTargetHostPort(%q) = (%q, %d, nil), want error", c.target, host, port)
				}
				return
			}
			if err != nil {
				t.Fatalf("SplitTargetHostPort(%q) error: %v", c.target, err)
			}
			if host != c.wantHost || port != c.wantPort {
				t.Errorf("SplitTargetHostPort(%q) = (%q, %d), want (%q, %d)", c.target, host, port, c.wantHost, c.wantPort)
			}
		})
	}
}

// peekTargetOf feeds raw to peekForwardTarget over a net.Pipe.
func peekTargetOf(t *testing.T, raw string) (string, error) {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() { _, _ = a.Write([]byte(raw)) }()
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	return peekForwardTarget(NewPeekConn(b))
}

func TestPeekForwardTarget_RejectsNonDecimalPort(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "origin service name", raw: "GET / HTTP/1.1\r\nHost: x:postgresql\r\n\r\n", wantErr: true},
		{name: "origin leading space port", raw: "GET / HTTP/1.1\r\nHost: x: 80\r\n\r\n", wantErr: true},
		{name: "origin empty port", raw: "GET / HTTP/1.1\r\nHost: x:\r\n\r\n", wantErr: true},
		{name: "origin out of range", raw: "GET / HTTP/1.1\r\nHost: x:70000\r\n\r\n", wantErr: true},
		{name: "origin uint32 wrap", raw: "GET / HTTP/1.1\r\nHost: x:4294967376\r\n\r\n", wantErr: true},
		{name: "absolute empty port", raw: "GET http://x:/ HTTP/1.1\r\nHost: x\r\n\r\n", wantErr: true},
		{name: "absolute uint32 wrap", raw: "GET http://x:4294967376/ HTTP/1.1\r\nHost: x\r\n\r\n", wantErr: true},
		{name: "absolute out of range", raw: "GET http://x:70000/ HTTP/1.1\r\nHost: x\r\n\r\n", wantErr: true},
		{name: "origin no port", raw: "GET / HTTP/1.1\r\nHost: x\r\n\r\n", want: "x:80"},
		{name: "origin numeric port", raw: "GET / HTTP/1.1\r\nHost: x:8080\r\n\r\n", want: "x:8080"},
		{name: "origin leading zero", raw: "GET / HTTP/1.1\r\nHost: x:05432\r\n\r\n", want: "x:05432"},
		{name: "origin ipv6", raw: "GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n", want: "[::1]:8080"},
		{name: "absolute no port", raw: "GET http://x/ HTTP/1.1\r\nHost: x\r\n\r\n", want: "x:80"},
		{name: "absolute numeric port", raw: "GET http://x:8080/ HTTP/1.1\r\nHost: x\r\n\r\n", want: "x:8080"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := peekTargetOf(t, c.raw)
			if c.wantErr {
				if err == nil {
					t.Fatalf("peekForwardTarget = %q, nil; want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("peekForwardTarget error: %v", err)
			}
			if got != c.want {
				t.Errorf("peekForwardTarget = %q, want %q (target must not be rewritten)", got, c.want)
			}
		})
	}
}

func TestScopeChecks_UnparseablePortFailsClosed(t *testing.T) {
	ruled := NewTargetScope()
	ruled.SetPolicyRules(nil, []TargetRule{{Hostname: "other.example", Ports: []int{1}}})
	open := NewTargetScope()

	type checkFn func(scope *TargetScope, target string) bool
	forward := func(s *TargetScope, tg string) bool { ok, _, _ := forwardScopeCheck(s, tg); return ok }
	connect := func(s *TargetScope, tg string) bool { ok, _, _ := connectScopeCheck(s, tg, false); return ok }
	socks := func(s *TargetScope, tg string) bool { ok, _ := socks5ScopeCheck(s, tg, false); return ok }

	cases := []struct {
		name   string
		check  checkFn
		target string
	}{
		{name: "connect plus sign", check: connect, target: "h:+443"},
		{name: "connect service name", check: connect, target: "h:x"},
		{name: "socks5 port zero", check: socks, target: "h:0"},
		{name: "socks5 service name", check: socks, target: "h:x"},
		{name: "forward service name", check: forward, target: "h:x"},
		{name: "forward uint32 wrap", check: forward, target: "h:4294967376"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.check(ruled, c.target) {
				t.Errorf("with rules: %q allowed, want denied (fail closed)", c.target)
			}
			if !c.check(open, c.target) {
				t.Errorf("without rules: %q denied, want allowed (open mode unchanged)", c.target)
			}
			if !c.check(nil, c.target) {
				t.Errorf("nil scope: %q denied, want allowed", c.target)
			}
		})
	}

	// Positive controls: a well-formed port still reaches CheckTarget.
	if ok, _, err := forwardScopeCheck(ruled, "h:80"); !ok || err != nil {
		t.Errorf("forwardScopeCheck(h:80) = %v, %v; want allowed", ok, err)
	}
	if ok, _, err := connectScopeCheck(ruled, "h:443", false); !ok || err != nil {
		t.Errorf("connectScopeCheck(h:443) = %v, %v; want allowed", ok, err)
	}
	if ok, _ := socks5ScopeCheck(ruled, "h:1080", false); !ok {
		t.Error("socks5ScopeCheck(h:1080) denied, want allowed")
	}
	if ok, _, _ := forwardScopeCheck(ruled, "other.example:1"); ok {
		t.Error("forwardScopeCheck(other.example:1) allowed, want denied by rule")
	}
}

// countingListener accepts TCP connections on loopback, counts them and
// closes each at once.
func countingListener(t *testing.T) (port int, accepts *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepts = new(atomic.Int64)
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
	return ln.Addr().(*net.TCPAddr).Port, accepts
}

// runForwardHandler drives one request through the real plain-HTTP
// forward handler and returns the client-visible response bytes.
func runForwardHandler(t *testing.T, cfg HTTP1ForwardHandlerConfig, raw string) []byte {
	t.Helper()
	cfg.OnStack = func(_ context.Context, stack *ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
		_ = stack.Close()
	}
	handler := NewHTTP1ForwardHandler(cfg)

	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	var resp []byte
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = clientA.Write([]byte(raw))
		resp = drainAndCapture(t, clientA)
	}()

	ctx, cancel := context.WithTimeout(ContextWithConnID(context.Background(), "usk-1249"), 5*time.Second)
	defer cancel()
	if err := handler(ctx, NewPeekConn(clientB)); err != nil {
		t.Errorf("handler returned error: %v", err)
	}
	_ = clientB.Close()
	wg.Wait()
	return resp
}

// waitAccepts waits up to d for accepts to reach want (want > 0), or the
// full d when want == 0, and returns the count.
func waitAccepts(accepts *atomic.Int64, want int64, d time.Duration) int64 {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if want > 0 && accepts.Load() >= want {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return accepts.Load()
}

// TestNewHTTP1ForwardHandler_WrappedPortNeverDialed is the USK-1249
// reproducer through the real handler and a real loopback dial. The
// target port is p + 2^32, which strconv.Atoi reads as a value no deny
// rule names while Go's net.parsePort wraps it back to p. If Go ever
// stops wrapping, the bypass rows stop being red reproducers but stay
// valid assertions of the fixed behaviour.
func TestNewHTTP1ForwardHandler_WrappedPortNeverDialed(t *testing.T) {
	const (
		scopeDeny      = "port deny"
		scopeUnrelated = "unrelated deny"
		scopeNone      = "no scope"
	)
	// %s in raw is replaced with the target port: the wrapped one when
	// wrap is set, the numeric one otherwise.
	cases := []struct {
		name        string
		scope       string
		raw         string
		wrap        bool
		wantStatus  string // "" means no proxy error response is asserted
		wantAccepts int64
	}{
		{
			name:       "origin-form wrapped port vs port deny",
			scope:      scopeDeny,
			raw:        "GET / HTTP/1.1\r\nHost: 127.0.0.1:%s\r\n\r\n",
			wrap:       true,
			wantStatus: "400",
		},
		{
			name:       "absolute-form wrapped port vs port deny",
			scope:      scopeDeny,
			raw:        "GET http://127.0.0.1:%s/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
			wrap:       true,
			wantStatus: "400",
		},
		{
			name:       "origin-form wrapped port without rules",
			scope:      scopeNone,
			raw:        "GET / HTTP/1.1\r\nHost: 127.0.0.1:%s\r\n\r\n",
			wrap:       true,
			wantStatus: "400",
		},
		{
			name:       "numeric port vs port deny",
			scope:      scopeDeny,
			raw:        "GET / HTTP/1.1\r\nHost: 127.0.0.1:%s\r\n\r\n",
			wantStatus: "403",
		},
		{
			// Positive control: the counter does observe a dial, so the
			// zero-accept rows above are not vacuous.
			name:        "origin-form numeric port allowed",
			scope:       scopeUnrelated,
			raw:         "GET / HTTP/1.1\r\nHost: 127.0.0.1:%s\r\n\r\n",
			wantAccepts: 1,
		},
		{
			name:        "absolute-form numeric port allowed",
			scope:       scopeUnrelated,
			raw:         "GET http://127.0.0.1:%s/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
			wantAccepts: 1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, accepts := countingListener(t)
			var scope *TargetScope
			switch c.scope {
			case scopeDeny:
				scope = NewTargetScope()
				scope.SetPolicyRules(nil, []TargetRule{{Hostname: "127.0.0.1", Ports: []int{p}}})
			case scopeUnrelated:
				scope = NewTargetScope()
				scope.SetPolicyRules(nil, []TargetRule{{Hostname: "denied.invalid"}})
			}
			port := strconv.Itoa(p)
			if c.wrap {
				port = strconv.Itoa(p + 1<<32)
			}
			resp := runForwardHandler(t, HTTP1ForwardHandlerConfig{Scope: scope}, fmt.Sprintf(c.raw, port))
			if c.wantStatus != "" {
				if !bytes.HasPrefix(resp, []byte("HTTP/1.1 "+c.wantStatus+" ")) {
					t.Errorf("response = %q, want status %s", resp, c.wantStatus)
				}
				if !bytes.Contains(resp, []byte("Server: yorishiro-proxy")) {
					t.Errorf("response = %q, want the proxy's own Server header", resp)
				}
			}
			if got := waitAccepts(accepts, c.wantAccepts, 300*time.Millisecond); got != c.wantAccepts {
				t.Errorf("upstream accepts = %d, want %d", got, c.wantAccepts)
			}
		})
	}
}

// recordingConnectProxy is a fake HTTP upstream proxy that records the
// request line of every CONNECT it receives and answers 502.
func recordingConnectProxy(t *testing.T) (*url.URL, func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var mu sync.Mutex
	var lines []string
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				line, _ := bufio.NewReader(c).ReadString('\n')
				mu.Lock()
				lines = append(lines, strings.TrimRight(line, "\r\n"))
				mu.Unlock()
				_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
			}(c)
		}
	}()
	u, _ := url.Parse("http://" + ln.Addr().String())
	return u, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), lines...)
	}
}

// TestNewHTTP1ForwardHandler_ServiceNamePortNeverForwarded covers the
// literal service-name vector hermetically: with an HTTP upstream proxy
// the target is sent verbatim in the CONNECT line, so the next hop would
// resolve "postgresql" → 5432 behind the port-scoped deny.
func TestNewHTTP1ForwardHandler_ServiceNamePortNeverForwarded(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules(nil, []TargetRule{{Hostname: "db.internal", Ports: []int{5432, 80}}})

	cases := []struct {
		name     string
		raw      string
		wantLine string // "" means the proxy must receive nothing
		status   string
	}{
		{name: "postgresql", raw: "GET / HTTP/1.1\r\nHost: db.internal:postgresql\r\n\r\n", status: "400"},
		{name: "http", raw: "GET / HTTP/1.1\r\nHost: db.internal:http\r\n\r\n", status: "400"},
		{
			// Positive control: an allowed numeric target does reach the
			// recording proxy, so the empty-recording rows are not vacuous.
			name:     "allowed numeric",
			raw:      "GET / HTTP/1.1\r\nHost: allowed.internal:8080\r\n\r\n",
			wantLine: "CONNECT allowed.internal:8080 HTTP/1.1",
			status:   "502",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			proxyURL, recorded := recordingConnectProxy(t)
			resp := runForwardHandler(t, HTTP1ForwardHandlerConfig{
				Scope:    scope,
				BuildCfg: &BuildConfig{UpstreamProxy: proxyURL},
			}, c.raw)
			if !bytes.HasPrefix(resp, []byte("HTTP/1.1 "+c.status+" ")) {
				t.Errorf("response = %q, want status %s", resp, c.status)
			}
			var lines []string
			deadline := time.Now().Add(300 * time.Millisecond)
			for time.Now().Before(deadline) {
				if lines = recorded(); c.wantLine != "" && len(lines) > 0 {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if c.wantLine == "" {
				if len(lines) != 0 {
					t.Errorf("upstream proxy received %q, want nothing", lines)
				}
				return
			}
			if len(lines) != 1 || lines[0] != c.wantLine {
				t.Errorf("upstream proxy received %q, want [%q]", lines, c.wantLine)
			}
		})
	}
}
