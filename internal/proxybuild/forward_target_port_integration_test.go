//go:build e2e && !e2e_smoke

// USK-1249 exhaustive tier: the plain-HTTP forward gate validates the
// target port it peeked (origin-form Host header or absolute-form URI)
// as a decimal 1..65535 before the scope check and the dial, through the
// production BuildLiveStack wiring. A target port the scope would read
// differently from the dialer (service name, uint32 wrap) is answered
// 400 and never dialed.
package proxybuild_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// startForwardPortProxy builds and starts a live stack with scope and
// returns its listen address and flow store.
func startForwardPortProxy(t *testing.T, ctx context.Context, scope *connector.TargetScope) (string, *flowStoreCapture) {
	t.Helper()
	store := &flowStoreCapture{}
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	stack, err := proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
		Logger:       testutil.DiscardLogger(),
		ListenerName: "usk-1249",
		ListenAddr:   "127.0.0.1:0",
		FlowStore:    store,
		Scope:        scope,
		BuildConfig: &connector.BuildConfig{
			ProxyConfig:        &config.ProxyConfig{},
			Issuer:             cert.NewIssuer(ca),
			InsecureSkipVerify: true,
		},
	})
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	go func() { _ = stack.Listener.Start(ctx) }()
	select {
	case <-stack.Listener.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("listener not ready")
	}
	return stack.Listener.Addr(), store
}

// rawForwardRequest writes raw to the proxy and returns the parsed
// response and its body. A connection the proxy closes without a
// response is returned as an error.
func rawForwardRequest(t *testing.T, proxyAddr, raw string) (*gohttp.Response, string, error) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := gohttp.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		return nil, "", fmt.Errorf("read response: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body), nil
}

// TestProxybuild_PlainHTTP_WrappedPortNeverReachesUpstream: the target
// port is p + 2^32, which strconv.Atoi reads as a value the deny rule
// does not name while Go's net.parsePort wraps it back to p. Before
// USK-1249 the request was admitted and dialed p. If Go ever stops
// wrapping, this stops being a red reproducer but stays a valid
// assertion of the fixed behaviour.
func TestProxybuild_PlainHTTP_WrappedPortNeverReachesUpstream(t *testing.T) {
	cases := []struct {
		name string
		raw  string // %s is replaced with the wrapped port
	}{
		{name: "origin-form", raw: "GET / HTTP/1.1\r\nHost: 127.0.0.1:%s\r\nConnection: close\r\n\r\n"},
		{name: "absolute-form", raw: "GET http://127.0.0.1:%s/ HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			upAddr, accepts := acceptCountingUpstream(t)
			_, portStr, _ := net.SplitHostPort(upAddr)
			p, _ := strconv.Atoi(portStr)
			scope := connector.NewTargetScope()
			scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: "127.0.0.1", Ports: []int{p}}})
			proxyAddr, store := startForwardPortProxy(t, ctx, scope)

			resp, _, err := rawForwardRequest(t, proxyAddr, fmt.Sprintf(c.raw, strconv.Itoa(p+1<<32)))
			switch {
			case err != nil:
				t.Errorf("no proxy response (%v), want 400", err)
			case resp.StatusCode != gohttp.StatusBadRequest:
				t.Errorf("status = %d, want 400", resp.StatusCode)
			case resp.Header.Get("Server") != "yorishiro-proxy":
				t.Errorf("Server header = %q, want yorishiro-proxy (the proxy's own answer)", resp.Header.Get("Server"))
			}
			if n := settleAccepts(accepts, 0, 300*time.Millisecond); n != 0 {
				t.Errorf("upstream accepts = %d, want 0", n)
			}
			if n := len(store.Streams()); n != 0 {
				t.Errorf("streams recorded = %d, want 0 (rejected before the stack is built)", n)
			}

			// Positive control on the same listener and proxy: an
			// un-denied numeric port on the counter's host is dialed, so
			// the zero above is not vacuous.
			scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: "denied.invalid"}})
			numeric := strings.Replace(c.raw, "%s", portStr, 1)
			base := accepts.Load()
			c2, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			_, _ = io.WriteString(c2, numeric)
			if n := settleAccepts(accepts, base+1, 3*time.Second) - base; n < 1 {
				t.Errorf("positive control: upstream accepts = %d, want >= 1", n)
			}
			_ = c2.Close()
		})
	}
}

// TestProxybuild_PlainHTTP_NumericPortStillForwarded guards that
// well-formed numeric targets keep working in both forms and that a
// port deny still answers 403.
func TestProxybuild_PlainHTTP_NumericPortStillForwarded(t *testing.T) {
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, _ *gohttp.Request) {
		fmt.Fprint(w, "usk-1249 upstream")
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	p, _ := strconv.Atoi(u.Port())

	cases := []struct {
		name       string
		raw        string
		deny       bool
		wantStatus int
	}{
		{name: "origin-form", raw: "GET / HTTP/1.1\r\nHost: " + u.Host + "\r\nConnection: close\r\n\r\n", wantStatus: 200},
		{name: "absolute-form", raw: "GET " + upstream.URL + "/ HTTP/1.1\r\nHost: " + u.Host + "\r\nConnection: close\r\n\r\n", wantStatus: 200},
		{name: "origin-form port deny", raw: "GET / HTTP/1.1\r\nHost: " + u.Host + "\r\nConnection: close\r\n\r\n", deny: true, wantStatus: 403},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			scope := connector.NewTargetScope()
			if c.deny {
				scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: u.Hostname(), Ports: []int{p}}})
			}
			proxyAddr, store := startForwardPortProxy(t, ctx, scope)

			resp, body, err := rawForwardRequest(t, proxyAddr, c.raw)
			if err != nil {
				t.Fatalf("request through proxy: %v", err)
			}
			if resp.StatusCode != c.wantStatus {
				t.Fatalf("status = %d (body %q), want %d", resp.StatusCode, body, c.wantStatus)
			}
			if c.wantStatus != 200 {
				return
			}
			if body != "usk-1249 upstream" {
				t.Errorf("body = %q, want the upstream's", body)
			}
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) && len(store.Streams()) < 1 {
				time.Sleep(20 * time.Millisecond)
			}
			if n := len(store.Streams()); n != 1 {
				t.Errorf("streams recorded = %d, want 1", n)
			}
		})
	}
}
