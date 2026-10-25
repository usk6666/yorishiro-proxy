//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
)

// USK-1316 exhaustive tier. Helpers live in
// transparent_smoke_integration_test.go.

func transparentCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func withScope(scope *connector.TargetScope) func(*proxybuild.Deps) {
	return func(d *proxybuild.Deps) { d.Scope = scope }
}

func policyScope(allows, denies []connector.TargetRule) *connector.TargetScope {
	s := connector.NewTargetScope()
	s.SetPolicyRules(allows, denies)
	return s
}

// readHTTPResponse reads one response from br.
func readHTTPResponse(t *testing.T, br *bufio.Reader) (*gohttp.Response, string) {
	t.Helper()
	resp, err := gohttp.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(body)
}

// expectNoUpstreamContact waits a moment for stray dials and asserts the
// upstream saw none.
func expectNoUpstreamContact(t *testing.T, s *tcpTestServer) {
	t.Helper()
	time.Sleep(100 * time.Millisecond)
	if n := s.accepts.Load(); n != 0 {
		t.Errorf("upstream accepted %d connections, want 0", n)
	}
}

// expectClosedNoBytes asserts the proxy closes c without writing a byte.
func expectClosedNoBytes(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, err := io.ReadAll(c)
	if len(b) != 0 {
		t.Fatalf("read %q from a refused connection, want none", b)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("refused connection not closed within 5s")
	}
}

// blockedStream waits for the transparent refusal audit Stream.
func blockedStream(t *testing.T, p *transparentProxy) *flow.Stream {
	t.Helper()
	st, _ := waitStream(t, p.store, 0, func(st *flow.Stream) bool {
		return st.BlockedBy == "target_scope" && st.Tags["via"] == "transparent"
	})
	return st
}

// sendClientHello starts a TLS handshake toward the proxy and returns
// once the proxy closed (or answered) the connection.
func tlsHandshakeVia(c net.Conn, sni string) error {
	tc := tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: true}) //nolint:gosec // test
	return tc.Handshake()
}

// T6: plain HTTP is relayed to the original destination whatever the
// Host header says, and the Stream records what the wire showed.
func TestTransparent_PlainHTTP_RelayedToOriginalDst(t *testing.T) {
	ctx := transparentCtx(t)
	up := newRawHTTPUpstream(t)
	p := startTransparentProxy(t, ctx, up.addr(), nil)

	const req = "GET /t6 HTTP/1.1\r\nHost: elsewhere.invalid\r\nConnection: close\r\n\r\n"
	resp, body, clientAddr := transparentExchange(t, p.addr, req)
	if resp.StatusCode != 200 || body != "GET /t6 HTTP/1.1" {
		t.Fatalf("response %d %q, want 200 from the original destination", resp.StatusCode, body)
	}
	if heads := up.seenHeads(); len(heads) != 1 || heads[0] != req {
		t.Errorf("upstream saw %q, want the client bytes verbatim", heads)
	}

	st, flows := waitStream(t, p.store, 2, isHTTPStream)
	if st.Scheme != "http" || st.State != "active" {
		t.Errorf("Stream = %s/%s, want http/active", st.Scheme, st.State)
	}
	if st.ListenerName != transparentListenerName {
		t.Errorf("ListenerName = %q", st.ListenerName)
	}
	if st.ConnInfo == nil || st.ConnInfo.ClientAddr != clientAddr {
		t.Errorf("ConnInfo = %+v, want ClientAddr %s", st.ConnInfo, clientAddr)
	}
	waitUpdate(t, p.store, st.ID, "State=complete", func(u flow.StreamUpdate) bool { return u.State == "complete" })
	waitUpdate(t, p.store, st.ID, "ServerAddr="+up.addr().String(), func(u flow.StreamUpdate) bool {
		return u.ServerAddr == up.addr().String()
	})
	send, recv := flowByDirection(flows, "send"), flowByDirection(flows, "receive")
	if send == nil || recv == nil {
		t.Fatalf("flows = %d, want a send and a receive flow", len(flows))
	}
	if send.URL == nil || send.URL.Host != "elsewhere.invalid" {
		t.Errorf("send Flow URL = %v, want host elsewhere.invalid (the Host header)", send.URL)
	}
	if string(send.RawBytes) != req {
		t.Errorf("send RawBytes = %q, want %q", send.RawBytes, req)
	}
	if !strings.HasPrefix(string(recv.RawBytes), "HTTP/1.1 200 OK\r\n") {
		t.Errorf("receive RawBytes = %q", recv.RawBytes)
	}
}

// T7: a Host naming another live server, also on a keep-alive request,
// still goes to the original destination over one upstream connection.
func TestTransparent_HostNamingOtherServer_StillOriginalDst(t *testing.T) {
	ctx := transparentCtx(t)
	orig := newRawHTTPUpstream(t)
	other := newRawHTTPUpstream(t)
	p := startTransparentProxy(t, ctx, orig.addr(), nil)

	c := p.dial(t)
	br := bufio.NewReader(c)
	for i, host := range []string{other.addr().String(), "second.invalid"} {
		fmt.Fprintf(c, "GET /ka%d HTTP/1.1\r\nHost: %s\r\n\r\n", i, host)
		resp, body := readHTTPResponse(t, br)
		if resp.StatusCode != 200 || body != fmt.Sprintf("GET /ka%d HTTP/1.1", i) {
			t.Errorf("request %d: %d %q", i, resp.StatusCode, body)
		}
	}
	if n := len(orig.seenHeads()); n != 2 {
		t.Errorf("original destination saw %d requests, want 2", n)
	}
	if n := other.accepts.Load(); n != 0 {
		t.Errorf("the Host's server accepted %d connections, want 0", n)
	}
	if n := orig.accepts.Load(); n != 1 {
		t.Errorf("original destination accepted %d connections, want 1", n)
	}
}

// T8: a request-target net/url would refuse is forwarded verbatim, not
// answered with 400.
func TestTransparent_MalformedRequestTarget_Forwarded(t *testing.T) {
	for _, line := range []string{
		"GET http://bad%zz.example/%zz HTTP/1.1",
		"GET /path%zz?q=%G1 HTTP/1.1",
		"GET http://ctl.example/a\x7fb HTTP/1.1",
	} {
		t.Run(line, func(t *testing.T) {
			ctx := transparentCtx(t)
			up := newRawHTTPUpstream(t)
			p := startTransparentProxy(t, ctx, up.addr(), nil)
			resp, body, _ := transparentExchange(t, p.addr, line+"\r\nHost: x.invalid\r\nConnection: close\r\n\r\n")
			if resp.StatusCode != 200 || body != line {
				t.Fatalf("response %d %q, want the upstream's 200 echoing %q", resp.StatusCode, body, line)
			}
		})
	}
}

// T10: client-first bytes that are neither HTTP nor TLS are passed
// through unchanged both ways; only metadata is recorded.
func TestTransparent_OpaqueClientFirst_PassthroughUnchanged(t *testing.T) {
	payload := make([]byte, 64<<10)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		first []byte
	}{
		{name: "SSH banner then binary", first: []byte("SSH-2.0-OpenSSH_9.6\r\n")},
		{name: "lone G then non-HTTP", first: []byte("G")},
		{name: "lowercase method", first: []byte("get / HTTP/1.1\r\n")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := transparentCtx(t)
			up := newEchoUpstream(t)
			p := startTransparentProxy(t, ctx, up.addr(), nil)
			c := p.dial(t)
			want := append(append([]byte(nil), tc.first...), payload...)
			if want[0] == 'G' && len(tc.first) == 1 {
				want[1] = 0x00 // never an HTTP method character
			}
			go func() {
				_, _ = c.Write(want[:len(tc.first)])
				time.Sleep(20 * time.Millisecond)
				_, _ = c.Write(want[len(tc.first):])
				_ = c.(*net.TCPConn).CloseWrite()
			}()
			got, err := io.ReadAll(c)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("echoed %d bytes, want the %d sent bytes unchanged", len(got), len(want))
			}
			_ = c.Close()
			st, upd, fl := waitPassthroughDone(t, p.store, "opaque")
			if st.Protocol != "raw" {
				t.Errorf("Protocol = %q, want raw", st.Protocol)
			}
			if upd.State != "complete" {
				t.Errorf("State = %q, want complete", upd.State)
			}
			n := fmt.Sprint(len(want))
			if fl.Metadata["bytes_client_to_upstream"] != n || fl.Metadata["bytes_upstream_to_client"] != n {
				t.Errorf("byte counts %v, want %s both ways", fl.Metadata, n)
			}
			for _, f := range p.store.flowsOf(st.ID) {
				if len(f.RawBytes) != 0 || len(f.Body) != 0 {
					t.Errorf("flow %s carries payload bytes", f.ID)
				}
			}
			for _, s := range p.store.allStreams() {
				if s.Protocol == "http" {
					t.Errorf("an http Stream was recorded for a non-HTTP connection")
				}
			}
		})
	}
}

// T12: a server-first connection whose client starts TLS after the
// banner is recorded as late TLS with its ClientHello metadata.
func TestTransparent_LateTLS_Recorded(t *testing.T) {
	ctx := transparentCtx(t)
	const banner = "* OK IMAP ready\r\n"
	up := newTCPTestServer(t, "tcp4", "127.0.0.1:0", func(c net.Conn) {
		_, _ = io.WriteString(c, banner)
		buf := make([]byte, 1)
		_, _ = c.Read(buf) // first ClientHello byte, then hang up
	})
	p := startTransparentProxy(t, ctx, up.addr(), nil)
	c := p.dial(t)
	br := bufio.NewReader(c)
	if line, err := br.ReadString('\n'); err != nil || line != banner {
		t.Fatalf("banner %q, %v", line, err)
	}
	_ = tlsHandshakeVia(c, "late.example") // the upstream is not TLS; fails
	_ = c.Close()

	st, upd, fl := waitPassthroughDone(t, p.store, "late_tls")
	if upd.Protocol != "tls-handshake" && st.Protocol != "tls-handshake" {
		t.Errorf("late TLS Stream protocol not tls-handshake (stream %q, update %q)", st.Protocol, upd.Protocol)
	}
	if fl.Metadata["route"] != "late_tls" || fl.Metadata["sni"] != "late.example" || fl.Metadata["client_ja3"] == "" || fl.Metadata["client_ja4"] == "" {
		t.Errorf("metadata = %v, want route late_tls, sni late.example, JA3/JA4", fl.Metadata)
	}
}

// T13: exactly one upstream connection per client connection on every
// route.
func TestTransparent_OneUpstreamDialPerConnection(t *testing.T) {
	t.Run("http keep-alive", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newRawHTTPUpstream(t)
		p := startTransparentProxy(t, ctx, up.addr(), nil)
		c := p.dial(t)
		br := bufio.NewReader(c)
		for i := 0; i < 3; i++ {
			fmt.Fprintf(c, "GET /%d HTTP/1.1\r\nHost: a.invalid\r\n\r\n", i)
			readHTTPResponse(t, br)
		}
		if n := up.accepts.Load(); n != 1 {
			t.Errorf("accepts = %d, want 1", n)
		}
	})
	t.Run("server-first", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newBannerUpstream(t, "hello\r\n")
		p := startTransparentProxy(t, ctx, up.addr(), nil)
		c := p.dial(t)
		br := bufio.NewReader(c)
		_, _ = br.ReadString('\n')
		_, _ = io.WriteString(c, "QUIT\r\n")
		_, _ = br.ReadString('\n')
		if n := up.accepts.Load(); n != 1 {
			t.Errorf("accepts = %d, want 1", n)
		}
	})
	t.Run("opaque", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newEchoUpstream(t)
		p := startTransparentProxy(t, ctx, up.addr(), nil)
		c := p.dial(t)
		_, _ = io.WriteString(c, "\x00\x01\x02")
		buf := make([]byte, 3)
		if _, err := io.ReadFull(c, buf); err != nil {
			t.Fatalf("read: %v", err)
		}
		if n := up.accepts.Load(); n != 1 {
			t.Errorf("accepts = %d, want 1", n)
		}
	})
}

// T14: a deny on the original destination refuses before any upstream
// contact and records the refusal; a scheme-scoped deny applies to the
// matching route only.
func TestTransparent_OriginalDstDenied(t *testing.T) {
	t.Run("HTTP route", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newRawHTTPUpstream(t)
		scope := policyScope(nil, []connector.TargetRule{{Hostname: "127.0.0.1", Ports: []int{int(up.addr().Port())}}})
		p := startTransparentProxy(t, ctx, up.addr(), withScope(scope))
		resp, _, clientAddr := transparentExchange(t, p.addr, "GET / HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
		if resp.StatusCode != 403 {
			t.Errorf("status %d, want 403", resp.StatusCode)
		}
		expectNoUpstreamContact(t, up.tcpTestServer)
		st := blockedStream(t, p)
		if st.State != "error" || st.Tags["target"] != up.addr().String() {
			t.Errorf("audit Stream = %+v", st)
		}
		if st.ConnInfo == nil || st.ConnInfo.ServerAddr != "" || st.ConnInfo.ClientAddr != clientAddr {
			t.Errorf("ConnInfo = %+v, want ServerAddr empty, ClientAddr %s", st.ConnInfo, clientAddr)
		}
		if !p.logs.Contains("transparent target blocked by scope") {
			t.Errorf("no Info log for the block; log:\n%s", p.logs.Output())
		}
	})
	t.Run("server-first route", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newBannerUpstream(t, "hi\r\n")
		scope := policyScope(nil, []connector.TargetRule{{Hostname: "127.0.0.1"}})
		p := startTransparentProxy(t, ctx, up.addr(), withScope(scope))
		expectClosedNoBytes(t, p.dial(t))
		expectNoUpstreamContact(t, up)
		blockedStream(t, p)
	})
	t.Run("https-only deny blocks TLS, allows HTTP", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newRawHTTPUpstream(t)
		scope := policyScope(nil, []connector.TargetRule{{Hostname: "127.0.0.1", Schemes: []string{"https"}}})
		p := startTransparentProxy(t, ctx, up.addr(), withScope(scope))
		resp, _, _ := transparentExchange(t, p.addr, "GET /ok HTTP/1.1\r\nHost: a.invalid\r\nConnection: close\r\n\r\n")
		if resp.StatusCode != 200 {
			t.Errorf("HTTP status %d, want 200", resp.StatusCode)
		}
		before := up.accepts.Load()
		c := p.dial(t)
		if err := tlsHandshakeVia(c, "a.example"); err == nil {
			t.Error("TLS handshake succeeded, want the connection refused")
		}
		time.Sleep(100 * time.Millisecond)
		if n := up.accepts.Load(); n != before {
			t.Errorf("TLS connection reached the upstream (%d → %d accepts)", before, n)
		}
		st := blockedStream(t, p)
		if st.Protocol != "tls-handshake" {
			t.Errorf("audit Stream protocol %q, want tls-handshake", st.Protocol)
		}
	})
}

// T15: name-leg denies — Host on plain HTTP (403 per request), SNI on
// TLS (closed, no dial).
func TestTransparent_NameDenied(t *testing.T) {
	t.Run("Host deny", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newRawHTTPUpstream(t)
		scope := policyScope(nil, []connector.TargetRule{{Hostname: "denied.example"}})
		p := startTransparentProxy(t, ctx, up.addr(), withScope(scope))
		c := p.dial(t)
		br := bufio.NewReader(c)
		_, _ = io.WriteString(c, "GET /a HTTP/1.1\r\nHost: ok.example\r\n\r\n")
		if resp, _ := readHTTPResponse(t, br); resp.StatusCode != 200 {
			t.Errorf("allowed Host: %d, want 200", resp.StatusCode)
		}
		_, _ = io.WriteString(c, "GET /b HTTP/1.1\r\nHost: denied.example\r\n\r\n")
		if resp, _ := readHTTPResponse(t, br); resp.StatusCode != 403 {
			t.Errorf("denied Host: %d, want 403", resp.StatusCode)
		}
		if n := len(up.seenHeads()); n != 1 {
			t.Errorf("upstream saw %d requests, want 1", n)
		}
	})
	t.Run("Host deny on the first request", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newRawHTTPUpstream(t)
		scope := policyScope(nil, []connector.TargetRule{{Hostname: "denied.example"}})
		p := startTransparentProxy(t, ctx, up.addr(), withScope(scope))
		resp, _, _ := transparentExchange(t, p.addr, "GET / HTTP/1.1\r\nHost: denied.example\r\n\r\n")
		if resp.StatusCode != 403 {
			t.Errorf("status %d, want 403", resp.StatusCode)
		}
		if n := len(up.seenHeads()); n != 0 {
			t.Errorf("upstream saw %d requests, want 0", n)
		}
	})
	t.Run("SNI deny", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newTLSTestUpstream(t)
		scope := policyScope(nil, []connector.TargetRule{{Hostname: "denied.example"}})
		p := startTransparentProxy(t, ctx, up.addr(), withScope(scope))
		if err := tlsHandshakeVia(p.dial(t), "denied.example"); err == nil {
			t.Error("handshake succeeded, want refusal")
		}
		time.Sleep(100 * time.Millisecond)
		if n := up.accepts.Load(); n != 0 {
			t.Errorf("upstream accepted %d connections, want 0", n)
		}
		st := blockedStream(t, p)
		if st.Protocol != "tls-handshake" {
			t.Errorf("audit Stream protocol %q", st.Protocol)
		}
	})
}

// T15b (decision U3, amended): with an allow list that does not name the
// original destination's IP, a name leg admits the connection only when
// it matches an allow rule AND resolves to the original destination.
func TestTransparent_NameAllowAdmitsBoundOriginalDst(t *testing.T) {
	loop := netip.MustParseAddr("127.0.0.1")
	elsewhere := netip.MustParseAddr("192.0.2.77")
	names := func() *fakeNameResolver {
		return newFakeNameResolver(map[string][]netip.Addr{
			"allowed.example":     {elsewhere, loop},
			"api.wild.example":    {loop},
			"unbound.example":     {elsewhere},
			"denied.example":      {loop},
			"other-bound.example": {loop},
		})
	}
	nameScope := func() *connector.TargetScope {
		return policyScope([]connector.TargetRule{
			{Hostname: "allowed.example"}, {Hostname: "*.wild.example"}, {Hostname: "unbound.example"},
		}, nil)
	}
	mutate := func(r *fakeNameResolver, s *connector.TargetScope) func(*proxybuild.Deps) {
		return func(d *proxybuild.Deps) { d.Scope = s; d.NameResolver = r }
	}

	t.Run("TLS allowed and bound SNI passes through", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newTLSTestUpstream(t)
		p := startTransparentProxy(t, ctx, up.addr(), mutate(names(), nameScope()))
		if err := tlsHandshakeVia(p.dial(t), "allowed.example"); err != nil {
			t.Fatalf("handshake: %v", err)
		}
		if n := up.accepts.Load(); n != 1 {
			t.Errorf("accepts = %d, want 1", n)
		}
	})
	t.Run("TLS wildcard allow with bound observed name", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newTLSTestUpstream(t)
		p := startTransparentProxy(t, ctx, up.addr(), mutate(names(), nameScope()))
		if err := tlsHandshakeVia(p.dial(t), "api.wild.example"); err != nil {
			t.Fatalf("handshake: %v", err)
		}
	})
	for _, tc := range []struct{ name, sni, reason string }{
		{"TLS allowed SNI resolving elsewhere", "unbound.example", connector.ReasonNameNotBound},
		{"TLS allowed SNI with resolver error", "nx.wild.example", connector.ReasonNameResolutionFailed},
		{"TLS SNI not in allow list", "other-bound.example", "target_scope"},
		{"TLS empty SNI", "", "target_scope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := transparentCtx(t)
			up := newTLSTestUpstream(t)
			p := startTransparentProxy(t, ctx, up.addr(), mutate(names(), nameScope()))
			c := p.dial(t)
			tcc := tls.Client(c, &tls.Config{ServerName: tc.sni, InsecureSkipVerify: true}) //nolint:gosec // test
			if tc.sni == "" {
				tcc = tls.Client(c, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test; IP-less config sends no SNI
			}
			if err := tcc.Handshake(); err == nil {
				t.Fatal("handshake succeeded, want refusal")
			}
			time.Sleep(100 * time.Millisecond)
			if n := up.accepts.Load(); n != 0 {
				t.Errorf("accepts = %d, want 0", n)
			}
			if st := blockedStream(t, p); st.FailureReason != tc.reason {
				t.Errorf("FailureReason = %q, want %q", st.FailureReason, tc.reason)
			}
		})
	}
	t.Run("HTTP allowed and bound Host relayed; keep-alive unbound Host 403", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newRawHTTPUpstream(t)
		p := startTransparentProxy(t, ctx, up.addr(), mutate(names(), nameScope()))
		c := p.dial(t)
		br := bufio.NewReader(c)
		_, _ = io.WriteString(c, "GET /1 HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
		if resp, _ := readHTTPResponse(t, br); resp.StatusCode != 200 {
			t.Fatalf("first request %d, want 200", resp.StatusCode)
		}
		_, _ = io.WriteString(c, "GET /2 HTTP/1.1\r\nHost: unbound.example\r\n\r\n")
		if resp, _ := readHTTPResponse(t, br); resp.StatusCode != 403 {
			t.Errorf("allowed-but-unbound keep-alive Host: %d, want 403", resp.StatusCode)
		}
		if n := len(up.seenHeads()); n != 1 {
			t.Errorf("upstream saw %d requests, want 1", n)
		}
	})
	t.Run("HTTP keep-alive Host not in allow list 403", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newRawHTTPUpstream(t)
		p := startTransparentProxy(t, ctx, up.addr(), mutate(names(), nameScope()))
		c := p.dial(t)
		br := bufio.NewReader(c)
		_, _ = io.WriteString(c, "GET /1 HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
		readHTTPResponse(t, br)
		_, _ = io.WriteString(c, "GET /2 HTTP/1.1\r\nHost: other-bound.example\r\n\r\n")
		if resp, _ := readHTTPResponse(t, br); resp.StatusCode != 403 {
			t.Errorf("status %d, want 403", resp.StatusCode)
		}
	})
	for _, tc := range []struct{ name, host, reason string }{
		{"HTTP allowed Host not bound", "unbound.example", connector.ReasonNameNotBound},
		{"HTTP Host not in allow list", "other-bound.example", "target_scope"},
		{"HTTP no Host", "", "target_scope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := transparentCtx(t)
			up := newRawHTTPUpstream(t)
			p := startTransparentProxy(t, ctx, up.addr(), mutate(names(), nameScope()))
			req := "GET / HTTP/1.1\r\nHost: " + tc.host + "\r\n\r\n"
			if tc.host == "" {
				req = "GET / HTTP/1.0\r\n\r\n"
			}
			resp, _, _ := transparentExchange(t, p.addr, req)
			if resp.StatusCode != 403 {
				t.Errorf("status %d, want 403", resp.StatusCode)
			}
			expectNoUpstreamContact(t, up.tcpTestServer)
			if st := blockedStream(t, p); st.FailureReason != tc.reason {
				t.Errorf("FailureReason = %q, want %q", st.FailureReason, tc.reason)
			}
		})
	}
	t.Run("server-first and opaque need an IP allow", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newEchoUpstream(t)
		p := startTransparentProxy(t, ctx, up.addr(), mutate(names(), nameScope()))
		expectClosedNoBytes(t, p.dial(t))
		c := p.dial(t)
		_, _ = io.WriteString(c, "\x00opaque")
		expectClosedNoBytes(t, c)
		expectNoUpstreamContact(t, up)
	})
	t.Run("IP allow: names deny-only, no DNS lookup", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newRawHTTPUpstream(t)
		r := names()
		scope := policyScope([]connector.TargetRule{{Hostname: "127.0.0.1"}}, []connector.TargetRule{{Hostname: "denied.example"}})
		p := startTransparentProxy(t, ctx, up.addr(), mutate(r, scope))
		resp, _, _ := transparentExchange(t, p.addr, "GET / HTTP/1.1\r\nHost: unlisted.example\r\nConnection: close\r\n\r\n")
		if resp.StatusCode != 200 {
			t.Errorf("unlisted Host on an IP-allowed dst: %d, want 200", resp.StatusCode)
		}
		resp, _, _ = transparentExchange(t, p.addr, "GET / HTTP/1.1\r\nHost: denied.example\r\nConnection: close\r\n\r\n")
		if resp.StatusCode != 403 {
			t.Errorf("denied Host: %d, want 403", resp.StatusCode)
		}
		if n := r.calls.Load(); n != 0 {
			t.Errorf("name lookups = %d, want 0 when the original destination is IP-allowed", n)
		}
	})
	t.Run("cache: two connections with the same name, one lookup", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newRawHTTPUpstream(t)
		r := names()
		p := startTransparentProxy(t, ctx, up.addr(), mutate(r, nameScope()))
		for i := 0; i < 2; i++ {
			resp, _, _ := transparentExchange(t, p.addr, "GET / HTTP/1.1\r\nHost: allowed.example\r\nConnection: close\r\n\r\n")
			if resp.StatusCode != 200 {
				t.Fatalf("request %d: %d", i, resp.StatusCode)
			}
		}
		if n := r.calls.Load(); n != 1 {
			t.Errorf("name lookups = %d, want 1 (cached)", n)
		}
	})
}

// T17: relay termination. An upstream RST fully closes the client
// promptly and records an error; a clean upstream FIN half-closes so the
// client can still send.
func TestTransparent_RelayTermination(t *testing.T) {
	t.Run("upstream RST", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newTCPTestServer(t, "tcp4", "127.0.0.1:0", func(c net.Conn) {
			buf := make([]byte, 4)
			_, _ = io.ReadFull(c, buf)
			_, _ = c.Write([]byte("pong"))
			_ = c.(*net.TCPConn).SetLinger(0)
		})
		p := startTransparentProxy(t, ctx, up.addr(), nil)
		c := p.dial(t)
		_, _ = io.WriteString(c, "\x00png")
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, err := io.ReadAll(c)
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatal("client not closed within 3s of the upstream RST")
		}
		_, upd, _ := waitPassthroughDone(t, p.store, "opaque")
		if upd.State != "error" {
			t.Errorf("State = %q, want error", upd.State)
		}
	})
	t.Run("upstream FIN half-closes", func(t *testing.T) {
		ctx := transparentCtx(t)
		got := make(chan string, 1)
		up := newTCPTestServer(t, "tcp4", "127.0.0.1:0", func(c net.Conn) {
			buf := make([]byte, 4)
			_, _ = io.ReadFull(c, buf)
			_, _ = c.Write([]byte("pong"))
			_ = c.(*net.TCPConn).CloseWrite()
			rest, _ := io.ReadAll(c)
			got <- string(buf) + string(rest)
		})
		p := startTransparentProxy(t, ctx, up.addr(), nil)
		c := p.dial(t)
		_, _ = io.WriteString(c, "\x00png")
		reply, err := io.ReadAll(c)
		if err != nil || string(reply) != "pong" {
			t.Fatalf("read %q, %v; want pong then EOF", reply, err)
		}
		_, _ = io.WriteString(c, "more")
		_ = c.(*net.TCPConn).CloseWrite()
		select {
		case s := <-got:
			if s != "\x00pngmore" {
				t.Errorf("upstream received %q, want the bytes sent after its FIN too", s)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("upstream never saw the client's half-close")
		}
		_, upd, fl := waitPassthroughDone(t, p.store, "opaque")
		if upd.State != "complete" || fl.Metadata["bytes_client_to_upstream"] != "8" {
			t.Errorf("State %q, metadata %v; want complete, 8 bytes client→upstream", upd.State, fl.Metadata)
		}
	})
}

// T18: an upstream dial failure closes the client (no synthetic 502) and
// records an error Stream without a server address.
func TestTransparent_DialFailure(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := netip.MustParseAddrPort(ln.Addr().String())
	_ = ln.Close()
	ctx := transparentCtx(t)
	p := startTransparentProxy(t, ctx, dead, nil)
	c := p.dial(t)
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: a.invalid\r\n\r\n")
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	b, _ := io.ReadAll(c)
	if len(b) != 0 {
		t.Errorf("client received %q, want the connection closed without a response", b)
	}
	st, _ := waitStream(t, p.store, 0, func(st *flow.Stream) bool { return st.State == "error" })
	if st.FailureReason != "transparent_dial_failed" || st.Tags["target"] != dead.String() {
		t.Errorf("Stream = %+v", st)
	}
	if st.ConnInfo != nil && st.ConnInfo.ServerAddr != "" {
		t.Errorf("ServerAddr = %q, want empty", st.ConnInfo.ServerAddr)
	}
}

// T19: a policy change that denies the original destination closes a
// live passthrough connection.
func TestTransparent_PolicyRevokeClosesPassthrough(t *testing.T) {
	ctx := transparentCtx(t)
	up := newEchoUpstream(t)
	scope := connector.NewTargetScope()
	live := connector.NewLiveConns(nil)
	p := startTransparentProxy(t, ctx, up.addr(), func(d *proxybuild.Deps) { d.Scope = scope; d.LiveConns = live })
	c := p.dial(t)
	_, _ = io.WriteString(c, "\x00abc")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("echo: %v", err)
	}
	scope.ReplacePolicyRules(nil, []connector.TargetRule{{Hostname: "127.0.0.1"}}, connector.PolicyOrigin{})
	if n := live.Reconcile("test"); n != 1 {
		t.Errorf("Reconcile revoked %d connections, want 1", n)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := io.ReadAll(c)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("revoked connection still open after 3s")
	}
}

// T22: IPv6 original destination.
func TestTransparent_IPv6OriginalDst(t *testing.T) {
	ctx := transparentCtx(t)
	up := newRawHTTPUpstreamOn(t, "tcp6", "[::1]:0")
	p := startTransparentProxy(t, ctx, up.addr(), func(d *proxybuild.Deps) { d.ListenAddr = "[::1]:0" })
	resp, body, _ := transparentExchange(t, p.addr, "GET /v6 HTTP/1.1\r\nHost: v6.invalid\r\nConnection: close\r\n\r\n")
	if resp.StatusCode != 200 || body != "GET /v6 HTTP/1.1" {
		t.Fatalf("response %d %q", resp.StatusCode, body)
	}
}

// connectProxy is a minimal HTTP CONNECT upstream proxy recording the
// CONNECT request lines it served.
type connectProxy struct {
	*tcpTestServer
	mu    sync.Mutex
	lines []string
}

func newConnectProxy(t *testing.T) *connectProxy {
	t.Helper()
	cp := &connectProxy{}
	cp.tcpTestServer = newTCPTestServer(t, "tcp4", "127.0.0.1:0", func(c net.Conn) {
		br := bufio.NewReader(c)
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		for {
			l, err := br.ReadString('\n')
			if err != nil || l == "\r\n" {
				break
			}
		}
		cp.mu.Lock()
		cp.lines = append(cp.lines, strings.TrimRight(line, "\r\n"))
		cp.mu.Unlock()
		target := strings.Fields(line)[1]
		up, err := net.Dial("tcp", target)
		if err != nil {
			_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			return
		}
		defer up.Close()
		_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() {
			_, _ = io.Copy(up, br)
			_ = up.Close()
		}()
		_, _ = io.Copy(c, up)
	})
	return cp
}

// T23: through an upstream proxy the CONNECT names the original
// destination's IP:port, not the Host.
func TestTransparent_UpstreamProxyConnectsToOriginalDst(t *testing.T) {
	ctx := transparentCtx(t)
	up := newRawHTTPUpstream(t)
	cp := newConnectProxy(t)
	p := startTransparentProxy(t, ctx, up.addr(), func(d *proxybuild.Deps) {
		d.BuildConfig.UpstreamProxy = &url.URL{Scheme: "http", Host: cp.addr().String()}
	})
	resp, _, _ := transparentExchange(t, p.addr, "GET /p HTTP/1.1\r\nHost: named.invalid\r\nConnection: close\r\n\r\n")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if len(cp.lines) != 1 || cp.lines[0] != "CONNECT "+up.addr().String()+" HTTP/1.1" {
		t.Errorf("CONNECT lines %q, want one CONNECT to %s", cp.lines, up.addr())
	}
}

// T23 (IPv6): the CONNECT target of an IPv6 original destination is the
// bracketed [ip]:port.
func TestTransparent_UpstreamProxyConnectsToOriginalDst_IPv6(t *testing.T) {
	ctx := transparentCtx(t)
	up := newRawHTTPUpstreamOn(t, "tcp6", "[::1]:0")
	cp := newConnectProxy(t)
	p := startTransparentProxy(t, ctx, up.addr(), func(d *proxybuild.Deps) {
		d.BuildConfig.UpstreamProxy = &url.URL{Scheme: "http", Host: cp.addr().String()}
	})
	resp, _, _ := transparentExchange(t, p.addr, "GET /p6 HTTP/1.1\r\nHost: named.invalid\r\nConnection: close\r\n\r\n")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	want := "CONNECT [::1]:" + fmt.Sprint(up.addr().Port()) + " HTTP/1.1"
	if len(cp.lines) != 1 || cp.lines[0] != want {
		t.Errorf("CONNECT lines %q, want %q", cp.lines, want)
	}
}

// T24: connection.on_connect fires on a transparent connection, and the
// HTTP route dispatches (http, on_request).
func TestTransparent_PluginHooks(t *testing.T) {
	t.Run("connection.on_connect", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newBannerUpstream(t, "hi\r\n")
		engine := loadRawWinsPlugin(t, ctx, "def on_conn(msg, ctx):\n    return action.DROP\nregister_hook(\"connection\", \"on_connect\", on_conn)\n")
		p := startTransparentProxy(t, ctx, up.addr(), func(d *proxybuild.Deps) { d.PluginV2Engine = engine })
		expectClosedNoBytes(t, p.dial(t))
		expectNoUpstreamContact(t, up)
	})
	t.Run("http.on_request", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newRawHTTPUpstream(t)
		engine := loadRawWinsPlugin(t, ctx, "def on_req(msg, ctx):\n    return action.RESPOND(status_code=299)\nregister_hook(\"http\", \"on_request\", on_req)\n")
		p := startTransparentProxy(t, ctx, up.addr(), func(d *proxybuild.Deps) { d.PluginV2Engine = engine })
		resp, _, _ := transparentExchange(t, p.addr, "GET / HTTP/1.1\r\nHost: a.invalid\r\nConnection: close\r\n\r\n")
		if resp.StatusCode != 299 {
			t.Errorf("status %d, want the plugin's 299", resp.StatusCode)
		}
	})
}
