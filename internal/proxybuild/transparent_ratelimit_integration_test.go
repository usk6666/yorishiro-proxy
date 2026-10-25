//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
)

// USK-1374: the Policy / Agent rate limits apply to every transparent
// route, per connection, at admission. Helpers live in
// transparent_smoke_integration_test.go and transparent_integration_test.go.

// burstOneLimiter returns a limiter whose global (or per-host) bucket
// admits exactly one connection: rate 0.001 rps → burst 1, and the next
// token is ~17 minutes away.
func burstOneLimiter(perHost bool) *connector.RateLimiter {
	rl := connector.NewRateLimiter()
	cfg := connector.RateLimitConfig{MaxRequestsPerSecond: 0.001}
	if perHost {
		cfg = connector.RateLimitConfig{MaxRequestsPerHostPerSecond: 0.001}
	}
	rl.SetPolicyLimits(cfg)
	return rl
}

func withRateLimiter(rl *connector.RateLimiter) func(*proxybuild.Deps) {
	return func(d *proxybuild.Deps) { d.RateLimiter = rl }
}

// rateLimitedStream waits for the transparent rate-limit refusal Stream.
func rateLimitedStream(t *testing.T, p *transparentProxy) *flow.Stream {
	t.Helper()
	st, _ := waitStream(t, p.store, 0, func(st *flow.Stream) bool {
		return st.BlockedBy == "rate_limit" && st.Tags["via"] == "transparent"
	})
	return st
}

// countStreams counts the recorded Streams matching match.
func countStreams(p *transparentProxy, match func(*flow.Stream) bool) int {
	n := 0
	for _, st := range p.store.allStreams() {
		if match(st) {
			n++
		}
	}
	return n
}

// expectAccepts waits a moment for stray dials and asserts the upstream
// saw exactly want connections.
func expectAccepts(t *testing.T, accepts *atomic.Int32, want int32) {
	t.Helper()
	time.Sleep(100 * time.Millisecond)
	if n := accepts.Load(); n != want {
		t.Errorf("upstream accepted %d connections, want %d", n, want)
	}
}

// T1: on the plain-HTTP route the connection over the limit gets the
// CONNECT / forward gate's 429 before any dial, and a rate_limit audit
// Stream is recorded.
func TestTransparent_RateLimit_PlainHTTP(t *testing.T) {
	ctx := transparentCtx(t)
	up := newRawHTTPUpstream(t)
	p := startTransparentProxy(t, ctx, up.addr(), withRateLimiter(burstOneLimiter(false)))

	resp, _, _ := transparentExchange(t, p.addr, "GET /first HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n")
	if resp.StatusCode != 200 {
		t.Fatalf("first connection status %d, want 200", resp.StatusCode)
	}
	resp, body, clientAddr := transparentExchange(t, p.addr, "GET /second HTTP/1.1\r\nHost: a.example\r\n\r\n")
	if resp.StatusCode != 429 || resp.Status != "429 Too Many Requests" {
		t.Errorf("second connection status %q, want 429 Too Many Requests", resp.Status)
	}
	if body != "yorishiro-proxy: target blocked by rate limit\r\n" {
		t.Errorf("second connection body %q", body)
	}
	expectAccepts(t, &up.accepts, 1)

	st := rateLimitedStream(t, p)
	if st.State != "error" || st.FailureReason != "rate_limit" || st.Protocol != "http" {
		t.Errorf("audit Stream = %+v, want State error, FailureReason rate_limit, Protocol http", st)
	}
	want := map[string]string{
		"via":             "transparent",
		"route":           "http",
		"target":          up.addr().String(),
		"rate_limit_type": "global",
	}
	for k, v := range want {
		if st.Tags[k] != v {
			t.Errorf("Tags[%s] = %q, want %q (tags %v)", k, st.Tags[k], v, st.Tags)
		}
	}
	if st.Tags["rate_limit_effective_rps"] == "" {
		t.Errorf("Tags = %v, want rate_limit_effective_rps", st.Tags)
	}
	if st.ConnInfo == nil || st.ConnInfo.ClientAddr != clientAddr || st.ConnInfo.ServerAddr != "" {
		t.Errorf("ConnInfo = %+v, want ClientAddr %s, ServerAddr empty", st.ConnInfo, clientAddr)
	}
	if n := countStreams(p, func(s *flow.Stream) bool { return s.BlockedBy == "rate_limit" }); n != 1 {
		t.Errorf("%d rate_limit Streams, want 1; streams=%s", n, describeStreams(p.store))
	}
	if !p.logs.Contains("transparent target blocked by rate limit") {
		t.Errorf("no Info log for the rate-limit block; log:\n%s", p.logs.Output())
	}
}

// T2: a TLS connection the MITM would take (ALPN h2, http/1.1, or none)
// is reset before any TLS byte once over the limit; the upstream is not
// contacted and a tls-handshake rate_limit Stream carries the SNI and the
// client fingerprints.
func TestTransparent_RateLimit_TLSMITM(t *testing.T) {
	tests := []struct {
		name string
		alpn []string
	}{
		{name: "ALPN h2", alpn: []string{"h2"}},
		{name: "ALPN http/1.1", alpn: []string{"http/1.1"}},
		{name: "no ALPN", alpn: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := transparentCtx(t)
			up := newCapturingTLSUpstream(t, []string{"h2", "http/1.1"}, serveHTTPS)
			p := startTransparentProxy(t, ctx, up.addr(), withRateLimiter(burstOneLimiter(false)))

			if len(tc.alpn) == 1 && tc.alpn[0] == "h2" {
				_, body := h2Get(t, p, "first.example", tc.alpn, "/first")
				if body == "" {
					t.Fatal("first connection: empty h2 body")
				}
			} else {
				first := mitmTLS(t, p, "first.example", tc.alpn)
				resp, _ := httpsGet(t, first, bufio.NewReader(first), "/first", "first.example", true)
				if resp.StatusCode != 200 {
					t.Fatalf("first connection status %d, want 200", resp.StatusCode)
				}
			}
			expectAccepts(t, &up.accepts, 1)

			c := p.dial(t)
			sc := tls.Client(c, &tls.Config{ServerName: "second.example", NextProtos: tc.alpn, RootCAs: p.roots()})
			if err := sc.Handshake(); err == nil {
				t.Error("second TLS handshake succeeded, want the connection reset")
			}
			expectAccepts(t, &up.accepts, 1)

			st := rateLimitedStream(t, p)
			if st.Protocol != "tls-handshake" || st.FailureReason != "rate_limit" || st.State != "error" {
				t.Errorf("audit Stream = %+v, want tls-handshake / rate_limit / error", st)
			}
			if st.Tags["name"] != "second.example" || st.Tags["route"] != "tls" {
				t.Errorf("Tags = %v, want name second.example, route tls", st.Tags)
			}
			if st.ConnInfo == nil || st.ConnInfo.TLSClientJA3 == "" || st.ConnInfo.TLSClientJA4 == "" {
				t.Errorf("ConnInfo = %+v, want the client JA3 / JA4", st.ConnInfo)
			}
		})
	}
}

// T3: the passthrough routes (server-first, TLS passthrough class,
// opaque client-first) are reset with no byte once over the limit; no
// passthrough Stream is started for the refused connection.
func TestTransparent_RateLimit_Passthrough(t *testing.T) {
	isPassthrough := func(s *flow.Stream) bool { return s.Tags["transparent"] == "passthrough" }

	t.Run("server-first", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newBannerUpstream(t, "hi\r\n")
		p := startTransparentProxy(t, ctx, up.addr(), withRateLimiter(burstOneLimiter(false)))

		c := p.dial(t)
		br := bufio.NewReader(c)
		if line, err := br.ReadString('\n'); err != nil || line != "hi\r\n" {
			t.Fatalf("first connection banner %q, %v", line, err)
		}
		_, _ = io.WriteString(c, "QUIT\r\n")
		_, _ = br.ReadString('\n')
		_ = c.Close()

		expectClosedNoBytes(t, p.dial(t))
		expectAccepts(t, &up.accepts, 1)
		st := rateLimitedStream(t, p)
		if st.Tags["route"] != "server_first" || st.Protocol != "raw" || st.FailureReason != "rate_limit" {
			t.Errorf("audit Stream = %+v, want route server_first, raw, rate_limit", st)
		}
		waitPassthroughDone(t, p.store, "server_first")
		if n := countStreams(p, isPassthrough); n != 1 {
			t.Errorf("%d passthrough Streams, want 1 (the admitted connection only)", n)
		}
	})

	t.Run("TLS passthrough class", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newCapturingTLSUpstream(t, []string{"imap"}, func(tc *tls.Conn) {
			_, _ = bufio.NewReader(tc).ReadString('\n')
		})
		p := startTransparentProxy(t, ctx, up.addr(), withRateLimiter(burstOneLimiter(false)))

		first := tls.Client(p.dial(t), &tls.Config{ServerName: "imap.example", NextProtos: []string{"imap"}, InsecureSkipVerify: true}) //nolint:gosec // test
		if err := first.Handshake(); err != nil {
			t.Fatalf("first TLS passthrough handshake: %v", err)
		}
		_ = first.Close()

		second := tls.Client(p.dial(t), &tls.Config{ServerName: "imap2.example", NextProtos: []string{"imap"}, InsecureSkipVerify: true}) //nolint:gosec // test
		if err := second.Handshake(); err == nil {
			t.Error("second TLS passthrough handshake succeeded, want the connection reset")
		}
		expectAccepts(t, &up.accepts, 1)
		st := rateLimitedStream(t, p)
		if st.Tags["route"] != "tls" || st.Protocol != "tls-handshake" || st.Tags["name"] != "imap2.example" {
			t.Errorf("audit Stream = %+v, want route tls, tls-handshake, name imap2.example", st)
		}
		waitPassthroughDone(t, p.store, "tls")
		if n := countStreams(p, isPassthrough); n != 1 {
			t.Errorf("%d passthrough Streams, want 1 (the admitted connection only)", n)
		}
	})

	t.Run("opaque client-first", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newEchoUpstream(t)
		p := startTransparentProxy(t, ctx, up.addr(), withRateLimiter(burstOneLimiter(false)))

		c := p.dial(t)
		_, _ = io.WriteString(c, "SSH-2.0-test\r\n")
		_ = c.(*net.TCPConn).CloseWrite()
		if got, err := io.ReadAll(c); err != nil || string(got) != "SSH-2.0-test\r\n" {
			t.Fatalf("first connection echoed %q, %v", got, err)
		}
		_ = c.Close()

		second := p.dial(t)
		_, _ = io.WriteString(second, "SSH-2.0-test\r\n")
		expectClosedNoBytes(t, second)
		expectAccepts(t, &up.accepts, 1)
		st := rateLimitedStream(t, p)
		if st.Tags["route"] != "opaque" || st.Protocol != "raw" {
			t.Errorf("audit Stream = %+v, want route opaque, raw", st)
		}
		waitPassthroughDone(t, p.store, "opaque")
		if n := countStreams(p, isPassthrough); n != 1 {
			t.Errorf("%d passthrough Streams, want 1 (the admitted connection only)", n)
		}
	})
}

// switchableDst is an OriginalDstResolver whose answer the test changes
// between connections.
type switchableDst struct{ v atomic.Value }

func newSwitchableDst(dst netip.AddrPort) *switchableDst {
	s := &switchableDst{}
	s.v.Store(dst)
	return s
}

func (s *switchableDst) set(dst netip.AddrPort) { s.v.Store(dst) }

func (s *switchableDst) resolver() connector.OriginalDstResolver {
	return connector.OriginalDstFunc(func(net.Conn) (netip.AddrPort, error) {
		return s.v.Load().(netip.AddrPort), nil
	})
}

// T4: the per-host bucket is keyed by the original-destination IP: a
// second connection to the same IP is refused whatever its Host says,
// a connection to another IP is admitted.
func TestTransparent_RateLimit_PerHostKeyIsOriginalDstIP(t *testing.T) {
	ctx := transparentCtx(t)
	upA := newRawHTTPUpstream(t)
	upB := newRawHTTPUpstreamOn(t, "tcp4", "127.0.0.2:0")
	dst := newSwitchableDst(upA.addr())
	p := startTransparentProxy(t, ctx, upA.addr(), func(d *proxybuild.Deps) {
		d.RateLimiter = burstOneLimiter(true)
		d.OriginalDstResolver = dst.resolver()
	})

	resp, _, _ := transparentExchange(t, p.addr, "GET / HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n")
	if resp.StatusCode != 200 {
		t.Fatalf("first connection to A status %d, want 200", resp.StatusCode)
	}
	resp, _, _ = transparentExchange(t, p.addr, "GET / HTTP/1.1\r\nHost: other.example\r\nConnection: close\r\n\r\n")
	if resp.StatusCode != 429 {
		t.Errorf("second connection to A (different Host) status %d, want 429", resp.StatusCode)
	}
	dst.set(upB.addr())
	resp, _, _ = transparentExchange(t, p.addr, "GET / HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n")
	if resp.StatusCode != 200 {
		t.Errorf("connection to B status %d, want 200 (separate per-host bucket)", resp.StatusCode)
	}
	expectAccepts(t, &upA.accepts, 1)
	expectAccepts(t, &upB.accepts, 1)
	st := rateLimitedStream(t, p)
	if st.Tags["rate_limit_type"] != "per_host" || st.Tags["target"] != upA.addr().String() {
		t.Errorf("Tags = %v, want rate_limit_type per_host, target %s", st.Tags, upA.addr())
	}
}

// T5: the scope verdict runs first, so a scope-denied connection
// consumes no rate-limit token.
func TestTransparent_RateLimit_ScopeRefusalConsumesNoToken(t *testing.T) {
	ctx := transparentCtx(t)
	upA := newRawHTTPUpstream(t)
	upB := newRawHTTPUpstream(t)
	dst := newSwitchableDst(upA.addr())
	scope := policyScope(nil, []connector.TargetRule{{Hostname: "127.0.0.1", Ports: []int{int(upA.addr().Port())}}})
	p := startTransparentProxy(t, ctx, upA.addr(), func(d *proxybuild.Deps) {
		d.Scope = scope
		d.RateLimiter = burstOneLimiter(false)
		d.OriginalDstResolver = dst.resolver()
	})

	resp, _, _ := transparentExchange(t, p.addr, "GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")
	if resp.StatusCode != 403 {
		t.Fatalf("scope-denied connection status %d, want 403", resp.StatusCode)
	}
	blockedStream(t, p)
	dst.set(upB.addr())
	resp, _, _ = transparentExchange(t, p.addr, "GET / HTTP/1.1\r\nHost: b.example\r\nConnection: close\r\n\r\n")
	if resp.StatusCode != 200 {
		t.Errorf("first admitted connection status %d, want 200 (the scope refusal must not consume the token)", resp.StatusCode)
	}
	resp, _, _ = transparentExchange(t, p.addr, "GET / HTTP/1.1\r\nHost: b.example\r\n\r\n")
	if resp.StatusCode != 429 {
		t.Errorf("second admitted connection status %d, want 429", resp.StatusCode)
	}
	expectAccepts(t, &upA.accepts, 0)
	expectAccepts(t, &upB.accepts, 1)
	if n := countStreams(p, func(s *flow.Stream) bool { return s.BlockedBy == "rate_limit" }); n != 1 {
		t.Errorf("%d rate_limit Streams, want 1; streams=%s", n, describeStreams(p.store))
	}
}

// T6: with no limit configured (a nil limiter, or one with a zero
// config) a burst of connections on every route kind is relayed and no
// rate_limit Stream is recorded.
func TestTransparent_RateLimit_NoLimitsUnchanged(t *testing.T) {
	const burst = 5
	limiters := []struct {
		name string
		rl   *connector.RateLimiter
	}{
		{name: "nil limiter", rl: nil},
		{name: "zero config", rl: connector.NewRateLimiter()},
	}
	noRateLimitStream := func(t *testing.T, p *transparentProxy) {
		t.Helper()
		time.Sleep(100 * time.Millisecond)
		if n := countStreams(p, func(s *flow.Stream) bool { return s.BlockedBy == "rate_limit" }); n != 0 {
			t.Errorf("%d rate_limit Streams, want 0; streams=%s", n, describeStreams(p.store))
		}
	}
	for _, lim := range limiters {
		t.Run(lim.name+"/http", func(t *testing.T) {
			ctx := transparentCtx(t)
			up := newRawHTTPUpstream(t)
			p := startTransparentProxy(t, ctx, up.addr(), withRateLimiter(lim.rl))
			for i := 0; i < burst; i++ {
				resp, _, _ := transparentExchange(t, p.addr, "GET / HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n")
				if resp.StatusCode != 200 {
					t.Fatalf("connection %d status %d, want 200", i, resp.StatusCode)
				}
			}
			expectAccepts(t, &up.accepts, burst)
			noRateLimitStream(t, p)
		})
		t.Run(lim.name+"/tls-mitm", func(t *testing.T) {
			ctx := transparentCtx(t)
			up := newCapturingTLSUpstream(t, []string{"http/1.1"}, serveHTTPS)
			p := startTransparentProxy(t, ctx, up.addr(), withRateLimiter(lim.rl))
			for i := 0; i < burst; i++ {
				tc := mitmTLS(t, p, "a.example", []string{"http/1.1"})
				resp, _ := httpsGet(t, tc, bufio.NewReader(tc), "/", "a.example", true)
				if resp.StatusCode != 200 {
					t.Fatalf("connection %d status %d, want 200", i, resp.StatusCode)
				}
				_ = tc.Close()
			}
			expectAccepts(t, &up.accepts, burst)
			noRateLimitStream(t, p)
		})
		t.Run(lim.name+"/server-first", func(t *testing.T) {
			ctx := transparentCtx(t)
			up := newBannerUpstream(t, "hi\r\n")
			p := startTransparentProxy(t, ctx, up.addr(), withRateLimiter(lim.rl))
			for i := 0; i < burst; i++ {
				c := p.dial(t)
				if line, err := bufio.NewReader(c).ReadString('\n'); err != nil || line != "hi\r\n" {
					t.Fatalf("connection %d banner %q, %v", i, line, err)
				}
				_ = c.Close()
			}
			expectAccepts(t, &up.accepts, burst)
			noRateLimitStream(t, p)
		})
	}
}

// T9: a Policy reload that lowers the rate takes effect on the next
// transparent connection.
func TestTransparent_RateLimit_PolicyReload(t *testing.T) {
	ctx := transparentCtx(t)
	up := newRawHTTPUpstream(t)
	rl := connector.NewRateLimiter()
	rl.SetPolicyLimits(connector.RateLimitConfig{MaxRequestsPerSecond: 1000})
	p := startTransparentProxy(t, ctx, up.addr(), withRateLimiter(rl))
	req := "GET / HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n"
	for i := 0; i < 2; i++ {
		if resp, _, _ := transparentExchange(t, p.addr, req); resp.StatusCode != 200 {
			t.Fatalf("connection %d under 1000 rps status %d, want 200", i, resp.StatusCode)
		}
	}
	rl.SetPolicyLimits(connector.RateLimitConfig{MaxRequestsPerSecond: 0.001})
	if resp, _, _ := transparentExchange(t, p.addr, req); resp.StatusCode != 200 {
		t.Fatalf("first connection after the reload status %d, want 200 (burst 1)", resp.StatusCode)
	}
	if resp, _, _ := transparentExchange(t, p.addr, req); resp.StatusCode != 429 {
		t.Errorf("second connection after the reload status %d, want 429", resp.StatusCode)
	}
	rateLimitedStream(t, p)
}
