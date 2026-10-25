//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	gohttp "net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/pool"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// USK-1317 exhaustive tier: TLS MITM on the transparent listener. Helpers
// shared with the smoke tier live in transparent_smoke_integration_test.go.

// mitmTLS dials the proxy and completes a TLS handshake trusting only the
// proxy CA.
func mitmTLS(t *testing.T, p *transparentProxy, sni string, alpn []string) *tls.Conn {
	t.Helper()
	tc := tls.Client(p.dial(t), &tls.Config{ServerName: sni, NextProtos: alpn, RootCAs: p.roots()})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("TLS handshake (SNI %q, ALPN %v) against the proxy CA: %v", sni, alpn, err)
	}
	return tc
}

// h2Get runs one HTTP/2 GET over a fresh MITM'd connection. The
// connection stays open until the test ends.
func h2Get(t *testing.T, p *transparentProxy, sni string, alpn []string, path string) (*tls.Conn, string) {
	t.Helper()
	tc := mitmTLS(t, p, sni, alpn)
	if got := tc.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("client negotiated %q, want h2", got)
	}
	cc, err := (&http2.Transport{}).NewClientConn(tc)
	if err != nil {
		t.Fatalf("h2 client conn: %v", err)
	}
	req, _ := gohttp.NewRequest("GET", "https://"+sni+path, nil)
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2 round trip: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return tc, string(body)
}

// isMITMRawStream matches a raw Stream recorded by the Pipeline (not a
// metadata-only passthrough Stream).
func isMITMRawStream(st *flow.Stream) bool {
	return st.Protocol == "raw" && st.Tags["transparent"] != "passthrough" && st.BlockedBy == ""
}

// rawFlowBytes concatenates the RawBytes of a Stream's flows in one
// direction.
func rawFlowBytes(flows []*flow.Flow, dir string) string {
	var b strings.Builder
	for _, f := range flows {
		if f.Direction == dir && f.Metadata["variant"] != "modified" {
			b.Write(f.RawBytes)
		}
	}
	return b.String()
}

// waitRawStream waits for the MITM raw Stream whose flows carry want in
// each direction.
func waitRawStream(t *testing.T, s *usk1181Store, wantSend, wantRecv string) (*flow.Stream, []*flow.Flow) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, st := range s.allStreams() {
			if !isMITMRawStream(st) {
				continue
			}
			fl := s.flowsOf(st.ID)
			if rawFlowBytes(fl, "send") == wantSend && rawFlowBytes(fl, "receive") == wantRecv {
				return st, fl
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no raw Stream with send %q / receive %q within 5s; streams=%s", wantSend, wantRecv, describeStreams(s))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// T2: an ALPN offer of [http/1.1, h2] is forwarded upstream verbatim, the
// client gets the upstream's pick (h2), and the h2 exchange is recorded.
func TestTransparent_TLS_H2MITM_ALPNOfferVerbatim(t *testing.T) {
	ctx := transparentCtx(t)
	up := newCapturingTLSUpstream(t, []string{"h2", "http/1.1"}, serveHTTPS)
	p := startTransparentProxy(t, ctx, up.addr(), nil)

	_, body := h2Get(t, p, "h2.example", []string{"http/1.1", "h2"}, "/t2")
	if body != "tls host=h2.example path=/t2 proto=HTTP/2.0" {
		t.Fatalf("body %q", body)
	}
	hellos := up.seenHellos()
	if len(hellos) != 1 || hellos[0].serverName != "h2.example" || strings.Join(hellos[0].protos, ",") != "http/1.1,h2" {
		t.Errorf("upstream ClientHellos = %+v, want SNI h2.example and ALPN [http/1.1 h2] byte-identical", hellos)
	}
	st, _ := waitStream(t, p.store, 2, isMITMHTTPSStream)
	if st.Tags["sni"] != "h2.example" {
		t.Errorf("Tags[sni] = %q", st.Tags["sni"])
	}
	if got := streamUpdateField(t, p.store, st.ID, "TLSALPN", func(u flow.StreamUpdate) string { return u.TLSALPN }); got != "h2" {
		t.Errorf("recorded ALPN %q, want h2", got)
	}
}

// T3: a client that offers no ALPN is MITM'd, the upstream is offered no
// ALPN either, and the HTTPS request is recorded as HTTP/1.
func TestTransparent_TLS_NoALPN_HTTPS_RecordedAsHTTP1(t *testing.T) {
	ctx := transparentCtx(t)
	up := newCapturingTLSUpstream(t, []string{"h2", "http/1.1"}, serveHTTPS)
	p := startTransparentProxy(t, ctx, up.addr(), nil)

	tc := mitmTLS(t, p, "noalpn.example", nil)
	resp, body := httpsGet(t, tc, bufio.NewReader(tc), "/t3", "noalpn.example", true)
	if resp.StatusCode != 200 || body != "tls host=noalpn.example path=/t3 proto=HTTP/1.1" {
		t.Fatalf("response %d %q", resp.StatusCode, body)
	}
	hellos := up.seenHellos()
	if len(hellos) != 1 || len(hellos[0].protos) != 0 || hellos[0].serverName != "noalpn.example" {
		t.Errorf("upstream ClientHellos = %+v, want SNI noalpn.example and no ALPN offer", hellos)
	}
	_, flows := waitStream(t, p.store, 2, isMITMHTTPSStream)
	if send := flowByDirection(flows, "send"); send == nil || !strings.HasPrefix(string(send.RawBytes), "GET /t3 HTTP/1.1\r\n") {
		t.Errorf("send raw = %q", rawOf(send))
	}
}

// T4: no-ALPN TLS carrying a non-HTTP protocol is MITM'd and recorded as
// raw decrypted bytes, unchanged in both directions — client-first and
// server-first.
func TestTransparent_TLS_NoALPN_NonHTTP_RawRecorded(t *testing.T) {
	t.Run("client first", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newCapturingTLSUpstream(t, nil, func(tc *tls.Conn) { _, _ = io.Copy(tc, tc) })
		p := startTransparentProxy(t, ctx, up.addr(), nil)
		tc := mitmTLS(t, p, "echo.example", nil)
		payload := "\x00ping\xff\r\n"
		if _, err := io.WriteString(tc, payload); err != nil {
			t.Fatalf("write: %v", err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(tc, got); err != nil || string(got) != payload {
			t.Fatalf("echo %q, %v; want %q", got, err, payload)
		}
		_ = tc.Close()
		st, _ := waitRawStream(t, p.store, payload, payload)
		if st.Tags["sni"] != "echo.example" {
			t.Errorf("Tags[sni] = %q", st.Tags["sni"])
		}
	})
	t.Run("server first", func(t *testing.T) {
		ctx := transparentCtx(t)
		const banner = "* OK IMAP4rev1 ready\r\n"
		up := newCapturingTLSUpstream(t, nil, func(tc *tls.Conn) {
			if _, err := io.WriteString(tc, banner); err != nil {
				return
			}
			line, err := bufio.NewReader(tc).ReadString('\n')
			if err == nil {
				_, _ = io.WriteString(tc, "ok "+line)
			}
		})
		p := startTransparentProxy(t, ctx, up.addr(), nil)
		tc := mitmTLS(t, p, "imap.example", nil)
		br := bufio.NewReader(tc)
		if line, err := br.ReadString('\n'); err != nil || line != banner {
			t.Fatalf("banner %q, %v (the client sent nothing)", line, err)
		}
		_, _ = io.WriteString(tc, "a1 NOOP\r\n")
		if line, err := br.ReadString('\n'); err != nil || line != "ok a1 NOOP\r\n" {
			t.Fatalf("reply %q, %v", line, err)
		}
		_ = tc.Close()
		waitRawStream(t, p.store, "a1 NOOP\r\n", banner+"ok a1 NOOP\r\n")
	})
}

// T6: two connections to the same original destination with different
// SNIs never share an upstream connection (the h2 pool key carries the
// TLS name); the same SNI twice does reuse the pooled one.
func TestTransparent_TLS_SameDstDifferentSNI_NoSharedUpstream(t *testing.T) {
	withPool := func(t *testing.T) func(*proxybuild.Deps) {
		pl := pool.New(pool.PoolOptions{})
		t.Cleanup(func() { _ = pl.Close() })
		return func(d *proxybuild.Deps) { d.BuildConfig.HTTP2Pool = pl }
	}
	t.Run("different SNI", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newCapturingTLSUpstream(t, []string{"h2"}, serveHTTPS)
		p := startTransparentProxy(t, ctx, up.addr(), withPool(t))
		_, a := h2Get(t, p, "a.example", []string{"h2"}, "/a")
		_, b := h2Get(t, p, "b.example", []string{"h2"}, "/b")
		if a != "tls host=a.example path=/a proto=HTTP/2.0" || b != "tls host=b.example path=/b proto=HTTP/2.0" {
			t.Fatalf("bodies %q / %q", a, b)
		}
		if n := up.accepts.Load(); n != 2 {
			t.Errorf("upstream accepted %d connections, want 2 (one per SNI)", n)
		}
		hellos := up.seenHellos()
		if len(hellos) != 2 || hellos[0].serverName != "a.example" || hellos[1].serverName != "b.example" {
			t.Errorf("upstream ClientHellos = %+v, want a.example then b.example", hellos)
		}
	})
	t.Run("same SNI reuses the pooled upstream", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newCapturingTLSUpstream(t, []string{"h2"}, serveHTTPS)
		p := startTransparentProxy(t, ctx, up.addr(), withPool(t))
		h2Get(t, p, "a.example", []string{"h2"}, "/1")
		h2Get(t, p, "a.example", []string{"h2"}, "/2")
		if n := up.accepts.Load(); n != 1 {
			t.Errorf("upstream accepted %d connections, want 1 (pooled)", n)
		}
	})
}

// T7: an SNI deny and an original-destination deny each refuse a
// MITM-class connection before any upstream contact, and record it.
func TestTransparent_TLS_MITMClassScopeDeny(t *testing.T) {
	for _, tc := range []struct {
		name    string
		denies  func(dst netip.AddrPort) []connector.TargetRule
		wantSNI string
	}{
		{"SNI deny", func(netip.AddrPort) []connector.TargetRule {
			return []connector.TargetRule{{Hostname: "denied.example"}}
		}, "denied.example"},
		{"original dst deny", func(dst netip.AddrPort) []connector.TargetRule {
			return []connector.TargetRule{{Hostname: dst.Addr().String(), Ports: []int{int(dst.Port())}}}
		}, "denied.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := transparentCtx(t)
			up := newCapturingTLSUpstream(t, []string{"http/1.1"}, serveHTTPS)
			p := startTransparentProxy(t, ctx, up.addr(), withScope(policyScope(nil, tc.denies(up.addr()))))
			c := tls.Client(p.dial(t), &tls.Config{ServerName: tc.wantSNI, NextProtos: []string{"h2", "http/1.1"}, RootCAs: p.roots()})
			if err := c.Handshake(); err == nil {
				t.Fatal("handshake succeeded, want refusal")
			}
			expectNoUpstreamContact(t, up.tcpTestServer)
			st := blockedStream(t, p)
			if st.Protocol != "tls-handshake" || st.Tags["name"] != tc.wantSNI || st.Tags["route"] != "tls" {
				t.Errorf("audit Stream = %s tags %v, want tls-handshake name=%s route=tls", st.Protocol, st.Tags, tc.wantSNI)
			}
			// The deny itself refused it — not a later name-binding failure.
			if st.FailureReason != "target_scope" {
				t.Errorf("FailureReason = %q, want target_scope", st.FailureReason)
			}
		})
	}
}

// T8: a ClientHello without SNI is MITM'd with an IP-SAN certificate and
// the upstream is sent no SNI either.
func TestTransparent_TLS_NoSNI_IPCertificate(t *testing.T) {
	ctx := transparentCtx(t)
	up := newCapturingTLSUpstream(t, []string{"http/1.1"}, serveHTTPS)
	p := startTransparentProxy(t, ctx, up.addr(), nil)
	// An IP-literal ServerName makes crypto/tls send no SNI and verify the
	// certificate against its IP SANs.
	tc := mitmTLS(t, p, up.addr().Addr().String(), []string{"http/1.1"})
	leaf := tc.ConnectionState().PeerCertificates[0]
	if len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.IP(up.addr().Addr().AsSlice())) {
		t.Errorf("MITM certificate DNSNames %v IPAddresses %v, want only the original destination IP", leaf.DNSNames, leaf.IPAddresses)
	}
	resp, _ := httpsGet(t, tc, bufio.NewReader(tc), "/t8", "ip.example", true)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if hellos := up.seenHellos(); len(hellos) != 1 || hellos[0].serverName != "" {
		t.Errorf("upstream ClientHellos = %+v, want one without SNI", hellos)
	}
}

// T9: a client rejecting the MITM certificate leaves a client_tls_error
// record carrying the SNI and the client's JA3 / JA4; an upstream TLS
// failure leaves an upstream_tls_error record.
func TestTransparent_TLS_HandshakeFailuresRecorded(t *testing.T) {
	t.Run("client rejects the MITM certificate", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newCapturingTLSUpstream(t, []string{"http/1.1"}, serveHTTPS)
		p := startTransparentProxy(t, ctx, up.addr(), nil)
		c := tls.Client(p.dial(t), &tls.Config{ServerName: "pinned.example", NextProtos: []string{"http/1.1"}, RootCAs: x509.NewCertPool()})
		if err := c.Handshake(); err == nil {
			t.Fatal("handshake succeeded with an empty root pool")
		}
		st, _ := waitStream(t, p.store, 0, func(st *flow.Stream) bool {
			return st.Tags["via"] == "transparent" && st.FailureReason == "client_tls_error"
		})
		if st.Protocol != "tls-handshake" || st.Scheme != "https" || st.State != "error" {
			t.Errorf("Stream = %s/%s/%s, want tls-handshake/https/error", st.Protocol, st.Scheme, st.State)
		}
		if st.Tags["name"] != "pinned.example" || st.Tags["target"] != up.addr().String() || st.Tags["error"] == "" {
			t.Errorf("Tags = %v, want name=pinned.example target=%s and an error", st.Tags, up.addr())
		}
		if st.ConnInfo == nil || st.ConnInfo.TLSClientJA3 == "" || st.ConnInfo.TLSClientJA4 == "" {
			t.Errorf("ConnInfo = %+v, want client JA3 / JA4", st.ConnInfo)
		}
	})
	t.Run("upstream TLS failure", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newTCPTestServer(t, "tcp4", "127.0.0.1:0", func(c net.Conn) {
			_, _ = io.WriteString(c, "not tls at all\r\n")
		})
		p := startTransparentProxy(t, ctx, up.addr(), nil)
		c := tls.Client(p.dial(t), &tls.Config{ServerName: "broken.example", NextProtos: []string{"http/1.1"}, RootCAs: p.roots()})
		if err := c.Handshake(); err == nil {
			t.Fatal("handshake succeeded, want the connection closed")
		}
		st, _ := waitStream(t, p.store, 0, func(st *flow.Stream) bool {
			return st.Tags["via"] == "transparent" && st.FailureReason == "upstream_tls_error"
		})
		if st.Tags["name"] != "broken.example" || st.Protocol != "tls-handshake" {
			t.Errorf("Stream = %s tags %v", st.Protocol, st.Tags)
		}
	})
}

// T10: (tls, on_handshake) fires for both MITM handshakes and the client
// fingerprints reach the recorded Stream.
func TestTransparent_TLS_OnHandshakeHookAndFingerprints(t *testing.T) {
	ctx := transparentCtx(t)
	pluginPath := writeUSK913PluginScript(t, `
def on_hs(msg, ctx):
    print("USK1317_HS side=" + msg["side"] + " sni=" + msg["sni"])
    return None
register_hook("tls", "on_handshake", on_hs)
`)
	hookLogs, hookLogger := testutil.NewCaptureLogger()
	engine := pluginv2.NewEngine(hookLogger)
	if err := engine.LoadPlugins(ctx, []pluginv2.PluginConfig{{Path: pluginPath, OnError: string(pluginv2.OnErrorAbort)}}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	up := newCapturingTLSUpstream(t, []string{"http/1.1"}, serveHTTPS)
	p := startTransparentProxy(t, ctx, up.addr(), func(d *proxybuild.Deps) {
		d.PluginV2Engine = engine
		d.BuildConfig.PluginV2Engine = engine
	})
	tc := mitmTLS(t, p, "hook.example", []string{"http/1.1"})
	httpsGet(t, tc, bufio.NewReader(tc), "/t10", "hook.example", true)
	_ = tc.Close()

	st, flows := waitStream(t, p.store, 2, isMITMHTTPSStream)
	if ja4 := streamUpdateField(t, p.store, st.ID, "TLSClientJA4", func(u flow.StreamUpdate) string { return u.TLSClientJA4 }); ja4 == "" {
		t.Error("no client JA4 recorded")
	}
	if len(rawOf(flowByDirection(flows, "send"))) == 0 || len(rawOf(flowByDirection(flows, "receive"))) == 0 {
		t.Error("raw bytes not recorded on both directions")
	}
	for _, side := range []string{"server", "client"} {
		want := "USK1317_HS side=" + side + " sni=hook.example"
		deadline := time.Now().Add(3 * time.Second)
		for !hookLogs.Contains(want) && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		if !hookLogs.Contains(want) {
			t.Errorf("hook sentinel %q not observed; log:\n%s", want, hookLogs.Output())
		}
	}
}

// T11b: an SNI on the TLS passthrough list is passed through without
// MITM and recorded; another SNI on the same original destination is
// MITM'd.
func TestTransparent_TLS_PassthroughListBySNI(t *testing.T) {
	ctx := transparentCtx(t)
	up := newCapturingTLSUpstream(t, []string{"http/1.1"}, serveHTTPS)
	pl := connector.NewPassthroughList()
	pl.Add("pass.example")
	p := startTransparentProxy(t, ctx, up.addr(), func(d *proxybuild.Deps) { d.PassthroughList = pl })

	pc := tls.Client(p.dial(t), &tls.Config{ServerName: "pass.example", NextProtos: []string{"http/1.1"}, InsecureSkipVerify: true}) //nolint:gosec // identity checked below
	if err := pc.Handshake(); err != nil {
		t.Fatalf("passthrough handshake: %v", err)
	}
	if !up.issuedByUpstream(pc.ConnectionState().PeerCertificates[0]) {
		t.Error("passthrough-listed SNI saw a MITM certificate")
	}
	httpsGet(t, pc, bufio.NewReader(pc), "/pass", "pass.example", true)
	_ = pc.Close()
	_, _, fl := waitPassthroughDone(t, p.store, "tls")
	if fl.Metadata["sni"] != "pass.example" {
		t.Errorf("passthrough metadata sni %q", fl.Metadata["sni"])
	}

	mc := mitmTLS(t, p, "other.example", []string{"http/1.1"})
	httpsGet(t, mc, bufio.NewReader(mc), "/mitm", "other.example", true)
	waitStream(t, p.store, 2, isMITMHTTPSStream)
}

// T12 (guard): CONNECT and SOCKS5 with a no-ALPN inner ClientHello keep
// the legacy path — the upstream is offered [h2 http/1.1] and the
// exchange is recorded as HTTP/1.
func TestTransparent_TLS_ExplicitProxyNoALPNUnchanged(t *testing.T) {
	explicit := func(d *proxybuild.Deps) { d.TransparentMode = ""; d.OriginalDstResolver = nil }
	for _, tc := range []struct {
		name   string
		tunnel func(t *testing.T, c net.Conn, target netip.AddrPort)
	}{
		{"CONNECT", func(t *testing.T, c net.Conn, target netip.AddrPort) {
			_, _ = io.WriteString(c, "CONNECT "+target.String()+" HTTP/1.1\r\nHost: "+target.String()+"\r\n\r\n")
			resp, err := gohttp.ReadResponse(bufio.NewReader(c), nil)
			if err != nil || resp.StatusCode != 200 {
				t.Fatalf("CONNECT: %v %v", resp, err)
			}
		}},
		{"SOCKS5", func(t *testing.T, c net.Conn, target netip.AddrPort) {
			_, _ = c.Write([]byte{0x05, 0x01, 0x00})
			reply := make([]byte, 2)
			if _, err := io.ReadFull(c, reply); err != nil || reply[1] != 0x00 {
				t.Fatalf("SOCKS5 method: %x %v", reply, err)
			}
			req := append([]byte{0x05, 0x01, 0x00, 0x01}, target.Addr().AsSlice()...)
			req = binary.BigEndian.AppendUint16(req, target.Port())
			_, _ = c.Write(req)
			rep := make([]byte, 10)
			if _, err := io.ReadFull(c, rep); err != nil || rep[1] != 0x00 {
				t.Fatalf("SOCKS5 connect: %x %v", rep, err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := transparentCtx(t)
			up := newCapturingTLSUpstream(t, []string{"h2", "http/1.1"}, serveHTTPS)
			p := startTransparentProxy(t, ctx, up.addr(), explicit)
			c := p.dial(t)
			tc.tunnel(t, c, up.addr())
			tlc := tls.Client(c, &tls.Config{ServerName: "legacy.example", InsecureSkipVerify: true}) //nolint:gosec // test
			if err := tlc.Handshake(); err != nil {
				t.Fatalf("inner handshake: %v", err)
			}
			resp, _ := httpsGet(t, tlc, bufio.NewReader(tlc), "/t12", "legacy.example", true)
			if resp.StatusCode != 200 {
				t.Fatalf("status %d", resp.StatusCode)
			}
			hellos := up.seenHellos()
			if len(hellos) == 0 || strings.Join(hellos[0].protos, ",") != "h2,http/1.1" {
				t.Errorf("upstream ClientHellos = %+v, want the legacy [h2 http/1.1] offer", hellos)
			}
			st, _ := waitStream(t, p.store, 2, isMITMHTTPSStream)
			// USK-1318: an explicit-proxy Stream is not transparent and
			// carries no original_dst tag.
			if v, ok := st.Tags["original_dst"]; ok {
				t.Errorf("Tags[original_dst] = %q on an explicit-proxy Stream, want absent", v)
			}
		})
	}
}

// t13NameScope is the T15b shape: an allow list that does not name the
// original destination's IP, and a resolver binding some names to it.
func t13NameScope(d *proxybuild.Deps) {
	loop := netip.MustParseAddr("127.0.0.1")
	d.Scope = policyScope([]connector.TargetRule{{Hostname: "allowed.example"}, {Hostname: "unbound.example"}}, nil)
	d.NameResolver = newFakeNameResolver(map[string][]netip.Addr{
		"allowed.example": {loop},
		"unbound.example": {netip.MustParseAddr("192.0.2.77")},
	})
}

// T13: a MITM connection admitted only by its (allowed, bound) SNI still
// checks every request's Host at stage 3.
func TestTransparent_TLS_NameAdmittedMITM_HostCheckedPerRequest(t *testing.T) {
	ctx := transparentCtx(t)
	up := newCapturingTLSUpstream(t, []string{"http/1.1"}, serveHTTPS)
	p := startTransparentProxy(t, ctx, up.addr(), t13NameScope)
	tc := mitmTLS(t, p, "allowed.example", []string{"http/1.1"})
	br := bufio.NewReader(tc)
	if resp, body := httpsGet(t, tc, br, "/ok", "allowed.example", false); resp.StatusCode != 200 {
		t.Fatalf("allowed bound Host: %d %q", resp.StatusCode, body)
	}
	if resp, _ := httpsGet(t, tc, br, "/no", "unbound.example", false); resp.StatusCode != 403 {
		t.Errorf("allowed-but-unbound Host: %d, want 403", resp.StatusCode)
	}
}

// T14 (guard): an upstream TCP dial failure on the MITM route resets the
// client and records transparent_dial_failed.
func TestTransparent_TLS_MITMDialFailure(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := netip.MustParseAddrPort(ln.Addr().String())
	_ = ln.Close()
	ctx := transparentCtx(t)
	p := startTransparentProxy(t, ctx, dead, nil)
	c := tls.Client(p.dial(t), &tls.Config{ServerName: "dead.example", NextProtos: []string{"http/1.1"}, RootCAs: p.roots()})
	if err := c.Handshake(); err == nil {
		t.Fatal("handshake succeeded against a dead destination")
	}
	st, _ := waitStream(t, p.store, 0, func(st *flow.Stream) bool { return st.State == "error" })
	if st.FailureReason != "transparent_dial_failed" || st.Tags["target"] != dead.String() || st.Tags["route"] != "tls" {
		t.Errorf("Stream = %+v", st)
	}
}

// T16 (owner decision U4): a no-ALPN, non-HTTP TLS connection admitted
// only by its allowed SNI bound to the original destination is relayed
// and its decrypted bytes recorded (no request path is ever checked on
// it, so without the SNI admission it would fail closed).
func TestTransparent_TLS_NameAdmittedRawRelayed(t *testing.T) {
	ctx := transparentCtx(t)
	up := newCapturingTLSUpstream(t, nil, func(tc *tls.Conn) { _, _ = io.Copy(tc, tc) })
	p := startTransparentProxy(t, ctx, up.addr(), t13NameScope)
	tc := mitmTLS(t, p, "allowed.example", nil)
	payload := "\x00raw-u4\r\n"
	_, _ = io.WriteString(tc, payload)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(tc, got); err != nil || string(got) != payload {
		t.Fatalf("echo %q, %v; want %q", got, err, payload)
	}
	_ = tc.Close()
	waitRawStream(t, p.store, payload, payload)
}

// withFirefoxFingerprint sets the production-default uTLS profile
// (mcpserver resolves tls_fingerprint to "firefox"), whose own ClientHello
// carries an ALPN extension of its own.
func withFirefoxFingerprint(d *proxybuild.Deps) { d.BuildConfig.TLSFingerprint = "firefox" }

// Review F-1: with a uTLS profile configured (the production default), a
// no-ALPN client's upstream ClientHello still carries no ALPN — neither on
// the HTTP/1 route nor on the raw route — and the upstream is dialed once.
func TestTransparent_TLS_NoALPN_UTLSProfile_NoUpstreamALPN(t *testing.T) {
	t.Run("http1", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newCapturingTLSUpstream(t, []string{"h2", "http/1.1"}, serveHTTPS)
		p := startTransparentProxy(t, ctx, up.addr(), withFirefoxFingerprint)
		tc := mitmTLS(t, p, "noalpn.example", nil)
		resp, body := httpsGet(t, tc, bufio.NewReader(tc), "/f1", "noalpn.example", true)
		if resp.StatusCode != 200 || body != "tls host=noalpn.example path=/f1 proto=HTTP/1.1" {
			t.Fatalf("response %d %q", resp.StatusCode, body)
		}
		if hellos := up.seenHellos(); len(hellos) != 1 || len(hellos[0].protos) != 0 {
			t.Errorf("upstream ClientHellos = %+v, want exactly one with no ALPN offer", hellos)
		}
	})
	t.Run("raw", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newCapturingTLSUpstream(t, []string{"h2", "http/1.1"}, func(tc *tls.Conn) { _, _ = io.Copy(tc, tc) })
		p := startTransparentProxy(t, ctx, up.addr(), withFirefoxFingerprint)
		tc := mitmTLS(t, p, "echo.example", nil)
		payload := "\x00ff-raw\r\n"
		if _, err := io.WriteString(tc, payload); err != nil {
			t.Fatalf("write: %v", err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(tc, got); err != nil || string(got) != payload {
			t.Fatalf("echo %q, %v; want %q", got, err, payload)
		}
		_ = tc.Close()
		if hellos := up.seenHellos(); len(hellos) != 1 || len(hellos[0].protos) != 0 {
			t.Errorf("upstream ClientHellos = %+v, want exactly one with no ALPN offer", hellos)
		}
	})
}

// Review F-2: an upstream-proxy rotation failure on the MITM route happens
// before any TLS byte reaches the upstream, so it is recorded like the
// plain route's dial failure (transparent_dial_failed), not as an upstream
// TLS error.
func TestTransparent_TLS_MITMRotationFailure_DialFailed(t *testing.T) {
	for name, alpn := range map[string][]string{"alpn": {"http/1.1"}, "no alpn": nil} {
		t.Run(name, func(t *testing.T) {
			ctx := transparentCtx(t)
			up := newCapturingTLSUpstream(t, []string{"http/1.1"}, serveHTTPS)
			p := startTransparentProxy(t, ctx, up.addr(), func(d *proxybuild.Deps) {
				d.BuildConfig.SetRotationForListener(transparentListenerName, connector.NewRotationResolver(connector.RotationConfig{
					Template:     "ftp://broken-§__nonce§.example:21",
					Policy:       connector.RotationPerRequest,
					ListenerName: transparentListenerName,
				}, 0, 0))
			})
			c := tls.Client(p.dial(t), &tls.Config{ServerName: "rot.example", NextProtos: alpn, RootCAs: p.roots()})
			if err := c.Handshake(); err == nil {
				t.Fatal("handshake succeeded although the upstream proxy rotation failed")
			}
			st, _ := waitStream(t, p.store, 0, func(st *flow.Stream) bool { return st.State == "error" })
			if st.FailureReason != "transparent_dial_failed" || st.Tags["route"] != "tls" {
				t.Errorf("Stream FailureReason = %q, route = %q; want transparent_dial_failed / tls", st.FailureReason, st.Tags["route"])
			}
			if n := len(up.seenHellos()); n != 0 {
				t.Errorf("upstream saw %d ClientHellos, want 0 (fail closed)", n)
			}
		})
	}
}

// Review S-1: a no-ALPN MITM connection that resolved to the raw relay is
// re-evaluated strictly by Reconcile, so narrowing its destination to a
// path-scoped allow cuts it (a raw relay never yields a request path).
func TestTransparent_TLS_NoALPNRawRelay_NarrowedToPathOnlyCutByReconcile(t *testing.T) {
	ctx := transparentCtx(t)
	up := newCapturingTLSUpstream(t, nil, func(tc *tls.Conn) { _, _ = io.Copy(tc, tc) })
	scope := policyScope([]connector.TargetRule{{Hostname: "127.0.0.1"}}, nil)
	live := connector.NewLiveConns(nil)
	p := startTransparentProxy(t, ctx, up.addr(), func(d *proxybuild.Deps) { d.Scope = scope; d.LiveConns = live })
	// No SNI (IP-literal ServerName): only the destination leg admits the
	// connection, so the narrowed path-scoped allow is the sole decider.
	tc := mitmTLS(t, p, up.addr().Addr().String(), nil)
	payload := "\x00s1-raw\r\n"
	if _, err := io.WriteString(tc, payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(tc, got); err != nil || string(got) != payload {
		t.Fatalf("echo %q, %v; want %q", got, err, payload)
	}
	scope.ReplacePolicyRules([]connector.TargetRule{{Hostname: "127.0.0.1", PathPrefix: "/api/"}}, nil, connector.PolicyOrigin{})
	if n := live.Reconcile("test"); n != 1 {
		t.Errorf("Reconcile after narrowing to a path-only allow revoked %d connections, want 1", n)
	}
}
