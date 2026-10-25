//go:build e2e && !e2e_smoke

// USK-1382: per_target_host upstream-proxy rotation keys its cached
// upstream proxy on the dial target. Every upstream dial for one
// destination — the first dial, an HTTP/1 redial after the upstream closed
// its keep-alive connection, an HTTP/2 redial after GOAWAY, and the first
// dial of a plaintext CONNECT / SOCKS5 tunnel — must therefore go through
// the same upstream proxy (here: the same §__nonce§ username, which is
// minted fresh for every dial that reaches the resolver without a target).
package proxybuild_test

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
)

// rotationTunnel is one CONNECT the upstream proxy served.
type rotationTunnel struct {
	user   string // Basic-auth username (the rotation slot)
	target string // CONNECT authority
}

// rotationProxyRecorder is an upstream HTTP CONNECT proxy that records the
// Proxy-Authorization username and authority of every tunnel and bridges
// it to the authority.
type rotationProxyRecorder struct {
	*tcpTestServer
	mu      sync.Mutex
	tunnels []rotationTunnel
}

func newRotationProxyRecorder(t *testing.T) *rotationProxyRecorder {
	t.Helper()
	r := &rotationProxyRecorder{}
	r.tcpTestServer = newTCPTestServer(t, "tcp4", "127.0.0.1:0", func(c net.Conn) {
		br := bufio.NewReader(c)
		req, err := gohttp.ReadRequest(br)
		if err != nil || req.Method != gohttp.MethodConnect {
			return
		}
		user := req.Header.Get("Proxy-Authorization")
		if dec, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(user, "Basic ")); err == nil {
			user, _, _ = strings.Cut(string(dec), ":")
		}
		r.mu.Lock()
		r.tunnels = append(r.tunnels, rotationTunnel{user: user, target: req.Host})
		r.mu.Unlock()
		up, err := net.Dial("tcp", req.Host)
		if err != nil {
			_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			return
		}
		defer up.Close()
		_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(up, br); done <- struct{}{} }()
		go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
		<-done
		// Either side ending tears both down so the other copy returns.
		_ = up.Close()
		_ = c.Close()
		<-done
	})
	return r
}

func (r *rotationProxyRecorder) seen() []rotationTunnel {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]rotationTunnel(nil), r.tunnels...)
}

// withPerTargetHostRotation installs a per_target_host rotation on the
// harness listener whose every freshly minted URL names rec with a new
// §__nonce§ username.
func withPerTargetHostRotation(rec *rotationProxyRecorder) func(*proxybuild.Deps) {
	return func(d *proxybuild.Deps) {
		d.BuildConfig.SetRotationForListener(transparentListenerName, connector.NewRotationResolver(connector.RotationConfig{
			Template:     fmt.Sprintf("http://session-§__nonce§:pass@%s", rec.addr()),
			Policy:       connector.RotationPerTargetHost,
			ListenerName: transparentListenerName,
		}, 0, 0))
	}
}

// requireSameRotation fails unless rec served at least want tunnels, all
// to target and all under one rotation username.
func requireSameRotation(t *testing.T, rec *rotationProxyRecorder, want int, exact bool, target string) {
	t.Helper()
	got := rec.seen()
	if len(got) < want || (exact && len(got) != want) {
		t.Fatalf("upstream proxy served %d tunnels %+v, want %d", len(got), got, want)
	}
	for i, tn := range got {
		if tn.target != target {
			t.Errorf("tunnel %d CONNECT target = %q, want %q", i, tn.target, target)
		}
		if !strings.HasPrefix(tn.user, "session-") {
			t.Errorf("tunnel %d user = %q, want session-<nonce>", i, tn.user)
		}
		if tn.user != got[0].user {
			t.Errorf("tunnel %d user = %q, want %q (tunnel 0's rotation slot): per_target_host chose another upstream proxy", i, tn.user, got[0].user)
		}
	}
}

// newRawH2Client starts a frame-level h2 client on an established
// h2-negotiated TLS connection.
func newRawH2Client(t *testing.T, tc *tls.Conn) *rawH2Client {
	t.Helper()
	if got := tc.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("negotiated ALPN = %q, want h2", got)
	}
	if _, err := tc.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	c := &rawH2Client{conn: tc, fr: http2.NewFramer(tc, tc)}
	c.enc = hpack.NewEncoder(&c.buf)
	c.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	c.fr.MaxHeaderListSize = 1 << 20
	if err := c.fr.WriteSettings(); err != nil {
		t.Fatalf("write SETTINGS: %v", err)
	}
	return c
}

// h2AcrossUpstreamGoAway answers stream 1 on the first upstream connection
// (which then sends GOAWAY) and stream 3 on a redialed one, and waits until
// the origin accepted that second connection.
func h2AcrossUpstreamGoAway(t *testing.T, cli *rawH2Client, origin *refusingH2Origin) {
	t.Helper()
	cli.sendGETs(t, "localhost", 1)
	requireOK(t, 1, cli.collect(t, 10*time.Second, 1)[1])
	// Let the proxy observe the GOAWAY written right behind stream 1.
	time.Sleep(100 * time.Millisecond)
	cli.sendGETs(t, "localhost", 3)
	requireOK(t, 3, cli.collect(t, 10*time.Second, 3)[3])
	if n := waitAccepts(origin, 2, 5*time.Second); n < 2 {
		t.Fatalf("origin accepted %d connections, want >= 2 (first dial + redial)", n)
	}
	// A pre-warm redial may still be connecting through the proxy.
	time.Sleep(100 * time.Millisecond)
}

// T1: CONNECT and SOCKS5 HTTPS (HTTP/1) — after the upstream closes its
// keep-alive connection, the redial goes through the first dial's upstream
// proxy.
func TestRotation_ExplicitProxyH1Redial_SameUpstreamProxy(t *testing.T) {
	for _, tc := range explicitTunnels {
		t.Run(tc.name, func(t *testing.T) {
			ctx := transparentCtx(t)
			rec := newRotationProxyRecorder(t)
			closed := make(chan struct{}, 2)
			up := newCapturingTLSUpstream(t, []string{"http/1.1"}, serveOnceThenClose(closed))
			p := startTransparentProxy(t, ctx, up.addr(), func(d *proxybuild.Deps) {
				explicitProxy(d)
				withPerTargetHostRotation(rec)(d)
			})
			c := p.dial(t)
			tc.tunnel(t, c, up.addr())
			tlc := tls.Client(c, &tls.Config{ServerName: "rot.example", NextProtos: []string{"http/1.1"}, InsecureSkipVerify: true}) //nolint:gosec // test
			if err := tlc.Handshake(); err != nil {
				t.Fatalf("inner handshake: %v", err)
			}
			keepAliveAcrossUpstreamClose(t, tlc, "rot.example", closed)

			if n := len(up.seenHellos()); n != 2 {
				t.Fatalf("origin saw %d ClientHellos, want 2 (first dial + redial)", n)
			}
			requireSameRotation(t, rec, 2, true, up.addr().String())
		})
	}
}

// T2: CONNECT and SOCKS5 HTTP/2 — the redial after upstream GOAWAY (and
// any pre-warm redial) goes through the first dial's upstream proxy.
func TestRotation_ExplicitProxyH2GoAwayRedial_SameUpstreamProxy(t *testing.T) {
	for _, tc := range explicitTunnels {
		t.Run(tc.name, func(t *testing.T) {
			ctx := transparentCtx(t)
			rec := newRotationProxyRecorder(t)
			origin := startRefusingH2Origin(t, originGoAwayAfterEachFirst, 0)
			dst := netip.MustParseAddrPort(origin.addr)
			p := startTransparentProxy(t, ctx, dst, func(d *proxybuild.Deps) {
				explicitProxy(d)
				withPerTargetHostRotation(rec)(d)
			})
			c := p.dial(t)
			tc.tunnel(t, c, dst)
			tlc := tls.Client(c, &tls.Config{ServerName: "localhost", NextProtos: []string{"h2"}, InsecureSkipVerify: true}) //nolint:gosec // test
			if err := tlc.Handshake(); err != nil {
				t.Fatalf("inner handshake: %v", err)
			}
			h2AcrossUpstreamGoAway(t, newRawH2Client(t, tlc), origin)
			requireSameRotation(t, rec, 2, false, origin.addr)
		})
	}
}

// T3 (h1): transparent TLS with an ALPN offer — the HTTP/1 redial goes
// through the first dial's upstream proxy, CONNECTing to the original dst.
func TestRotation_TransparentALPNH1Redial_SameUpstreamProxy(t *testing.T) {
	ctx := transparentCtx(t)
	rec := newRotationProxyRecorder(t)
	closed := make(chan struct{}, 2)
	up := newCapturingTLSUpstream(t, []string{"http/1.1"}, serveOnceThenClose(closed))
	p := startTransparentProxy(t, ctx, up.addr(), withPerTargetHostRotation(rec))
	tc := mitmTLS(t, p, "alpn.example", []string{"http/1.1"})
	keepAliveAcrossUpstreamClose(t, tc, "alpn.example", closed)

	if n := len(up.seenHellos()); n != 2 {
		t.Fatalf("origin saw %d ClientHellos, want 2 (first dial + redial)", n)
	}
	requireSameRotation(t, rec, 2, true, up.addr().String())
}

// T3 (h2): transparent TLS with an [h2] offer — the redial after upstream
// GOAWAY goes through the first dial's upstream proxy.
func TestRotation_TransparentALPNH2GoAwayRedial_SameUpstreamProxy(t *testing.T) {
	ctx := transparentCtx(t)
	rec := newRotationProxyRecorder(t)
	origin := startRefusingH2Origin(t, originGoAwayAfterEachFirst, 0)
	p := startTransparentProxy(t, ctx, netip.MustParseAddrPort(origin.addr), withPerTargetHostRotation(rec))
	tc := mitmTLS(t, p, "localhost", []string{"h2"})
	h2AcrossUpstreamGoAway(t, newRawH2Client(t, tc), origin)
	requireSameRotation(t, rec, 2, false, origin.addr)
}

// T4 (guard): the transparent no-ALPN HTTP/1 redial already keyed rotation
// by the dial target; it must stay on the same upstream proxy.
func TestRotation_TransparentNoALPNH1Redial_SameUpstreamProxy(t *testing.T) {
	ctx := transparentCtx(t)
	rec := newRotationProxyRecorder(t)
	closed := make(chan struct{}, 2)
	up := newCapturingTLSUpstream(t, []string{"http/1.1"}, serveOnceThenClose(closed))
	p := startTransparentProxy(t, ctx, up.addr(), withPerTargetHostRotation(rec))
	tc := mitmTLS(t, p, "noalpn.example", nil)
	keepAliveAcrossUpstreamClose(t, tc, "noalpn.example", closed)

	if n := len(up.seenHellos()); n != 2 {
		t.Fatalf("origin saw %d ClientHellos, want 2 (first dial + redial)", n)
	}
	requireSameRotation(t, rec, 2, true, up.addr().String())
}

// T6: two separate plaintext CONNECT / SOCKS5 tunnels (inner HTTP/1) to
// one target go through the same upstream proxy.
func TestRotation_ExplicitProxyPlaintextTunnels_SameUpstreamProxy(t *testing.T) {
	for _, tc := range explicitTunnels {
		t.Run(tc.name, func(t *testing.T) {
			ctx := transparentCtx(t)
			rec := newRotationProxyRecorder(t)
			up := newRawHTTPUpstream(t)
			p := startTransparentProxy(t, ctx, up.addr(), func(d *proxybuild.Deps) {
				explicitProxy(d)
				withPerTargetHostRotation(rec)(d)
			})
			for i := 0; i < 2; i++ {
				c := p.dial(t)
				tc.tunnel(t, c, up.addr())
				resp, body := httpsGet(t, c, bufio.NewReader(c), fmt.Sprintf("/plain-%d", i), "plain.example", true)
				if resp.StatusCode != 200 || !strings.Contains(body, fmt.Sprintf("/plain-%d", i)) {
					t.Fatalf("tunnel %d: response %d %q", i, resp.StatusCode, body)
				}
				_ = c.Close()
			}
			requireSameRotation(t, rec, 2, true, up.addr().String())
		})
	}
}
