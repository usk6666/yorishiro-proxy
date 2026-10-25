//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
)

// USK-1318: every transparent-mode Stream records the original
// destination as tags.original_dst — in particular when an upstream proxy
// makes server_addr the proxy's address.

func withUpstreamProxy(cp *connectProxy) func(*proxybuild.Deps) {
	return func(d *proxybuild.Deps) {
		d.BuildConfig.UpstreamProxy = &url.URL{Scheme: "http", Host: cp.addr().String()}
	}
}

func assertOriginalDst(t *testing.T, st *flow.Stream, want netip.AddrPort) {
	t.Helper()
	if got := st.Tags["original_dst"]; got != want.String() {
		t.Errorf("Tags[original_dst] = %q, want %q (tags %v)", got, want, st.Tags)
	}
}

// T1: a plain-HTTP Stream through an upstream proxy carries the original
// destination while server_addr is the proxy.
func TestTransparent_OriginalDst_PlainHTTPViaUpstreamProxy(t *testing.T) {
	ctx := transparentCtx(t)
	up := newRawHTTPUpstream(t)
	cp := newConnectProxy(t)
	p := startTransparentProxy(t, ctx, up.addr(), withUpstreamProxy(cp))
	resp, _, _ := transparentExchange(t, p.addr, "GET /od HTTP/1.1\r\nHost: named.invalid\r\nConnection: close\r\n\r\n")
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	st, _ := waitStream(t, p.store, 2, isHTTPStream)
	assertOriginalDst(t, st, up.addr())
	waitUpdate(t, p.store, st.ID, "ServerAddr="+cp.addr().String()+" via an upstream proxy", func(u flow.StreamUpdate) bool {
		return u.ServerAddr == cp.addr().String() && u.UpstreamProxy != ""
	})
}

// T2: TLS MITM Streams through an upstream proxy carry both the SNI and
// the original destination, independently.
func TestTransparent_OriginalDst_TLSMITMViaUpstreamProxy(t *testing.T) {
	t.Run("h2", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newCapturingTLSUpstream(t, []string{"h2", "http/1.1"}, serveHTTPS)
		cp := newConnectProxy(t)
		p := startTransparentProxy(t, ctx, up.addr(), withUpstreamProxy(cp))
		_, body := h2Get(t, p, "h2.example", []string{"h2"}, "/od")
		if body != "tls host=h2.example path=/od proto=HTTP/2.0" {
			t.Fatalf("body %q", body)
		}
		st, _ := waitStream(t, p.store, 2, isMITMHTTPSStream)
		assertOriginalDst(t, st, up.addr())
		if st.Tags["sni"] != "h2.example" {
			t.Errorf("Tags[sni] = %q, want h2.example", st.Tags["sni"])
		}
		if got := streamUpdateField(t, p.store, st.ID, "ServerAddr", func(u flow.StreamUpdate) string { return u.ServerAddr }); got != cp.addr().String() {
			t.Errorf("ServerAddr = %q, want the upstream proxy %s", got, cp.addr())
		}
	})
	t.Run("no-ALPN raw", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newCapturingTLSUpstream(t, nil, func(tc *tls.Conn) { _, _ = io.Copy(tc, tc) })
		cp := newConnectProxy(t)
		p := startTransparentProxy(t, ctx, up.addr(), withUpstreamProxy(cp))
		tc := mitmTLS(t, p, "echo.example", nil)
		payload := "\x00od\r\n"
		_, _ = io.WriteString(tc, payload)
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(tc, got); err != nil || string(got) != payload {
			t.Fatalf("echo %q, %v", got, err)
		}
		_ = tc.Close()
		st, _ := waitRawStream(t, p.store, payload, payload)
		assertOriginalDst(t, st, up.addr())
		if st.Tags["sni"] != "echo.example" {
			t.Errorf("Tags[sni] = %q, want echo.example", st.Tags["sni"])
		}
	})
}

// T3: accept-time scope refusals record the original destination next to
// tags.target.
func TestTransparent_OriginalDst_AcceptTimeRefusal(t *testing.T) {
	t.Run("HTTP route", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newRawHTTPUpstream(t)
		scope := policyScope(nil, []connector.TargetRule{{Hostname: "127.0.0.1", Ports: []int{int(up.addr().Port())}}})
		p := startTransparentProxy(t, ctx, up.addr(), withScope(scope))
		resp, _, _ := transparentExchange(t, p.addr, "GET / HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
		if resp.StatusCode != 403 {
			t.Fatalf("status %d, want 403", resp.StatusCode)
		}
		st := blockedStream(t, p)
		assertOriginalDst(t, st, up.addr())
		if st.Tags["target"] != up.addr().String() {
			t.Errorf("Tags[target] = %q, want %s (kept)", st.Tags["target"], up.addr())
		}
	})
	t.Run("TLS SNI deny", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newCapturingTLSUpstream(t, []string{"http/1.1"}, serveHTTPS)
		p := startTransparentProxy(t, ctx, up.addr(), withScope(policyScope(nil, []connector.TargetRule{{Hostname: "denied.example"}})))
		c := tls.Client(p.dial(t), &tls.Config{ServerName: "denied.example", NextProtos: []string{"http/1.1"}, RootCAs: p.roots()})
		if err := c.Handshake(); err == nil {
			t.Fatal("handshake succeeded, want refusal")
		}
		st := blockedStream(t, p)
		assertOriginalDst(t, st, up.addr())
		if st.Tags["target"] != up.addr().String() || st.Tags["name"] != "denied.example" {
			t.Errorf("tags %v, want target=%s name=denied.example", st.Tags, up.addr())
		}
	})
}

// T4: a dial-failure Stream records the original destination.
func TestTransparent_OriginalDst_DialFailure(t *testing.T) {
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
	_, _ = io.ReadAll(c)
	st, _ := waitStream(t, p.store, 0, func(st *flow.Stream) bool { return st.State == "error" })
	if st.FailureReason != "transparent_dial_failed" {
		t.Fatalf("Stream = %+v", st)
	}
	assertOriginalDst(t, st, dead)
}

// T5: a Pipeline-Drop audit Stream on a transparent session (a later
// keep-alive request whose Host the scope refuses) records the original
// destination.
func TestTransparent_OriginalDst_PipelineDropAudit(t *testing.T) {
	ctx := transparentCtx(t)
	up := newCapturingTLSUpstream(t, []string{"http/1.1"}, serveHTTPS)
	p := startTransparentProxy(t, ctx, up.addr(), t13NameScope)
	tc := mitmTLS(t, p, "allowed.example", []string{"http/1.1"})
	br := bufio.NewReader(tc)
	if resp, body := httpsGet(t, tc, br, "/ok", "allowed.example", false); resp.StatusCode != 200 {
		t.Fatalf("allowed bound Host: %d %q", resp.StatusCode, body)
	}
	if resp, _ := httpsGet(t, tc, br, "/no", "unbound.example", false); resp.StatusCode != 403 {
		t.Fatalf("allowed-but-unbound Host: %d, want 403", resp.StatusCode)
	}
	st, _ := waitStream(t, p.store, 0, func(st *flow.Stream) bool {
		return st.BlockedBy == "target_scope" && st.Tags["via"] != "transparent"
	})
	assertOriginalDst(t, st, up.addr())
}

// T6: a request head the proxy closes (431) on the transparent HTTP route
// records the original destination.
func TestTransparent_OriginalDst_RequestHeadReject(t *testing.T) {
	ctx := transparentCtx(t)
	up := newRawHTTPUpstream(t)
	p := startTransparentProxy(t, ctx, up.addr(), nil)
	c := p.dial(t)
	payload := "GET / HTTP/1.1\r\nHost: a.invalid\r\nX-Big: " + strings.Repeat("b", 4<<20) + "\r\n\r\n"
	got := usk1181Reject(t, c, payload)
	if !strings.HasPrefix(string(got), "HTTP/1.1 431 ") {
		t.Fatalf("client read %.120q, want HTTP/1.1 431", got)
	}
	st, _ := awaitErrorStream(t, p.store, "request_header_too_large", 1, 10*time.Second)
	assertOriginalDst(t, st, up.addr())
}
