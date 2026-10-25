//go:build e2e

package proxybuild_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// USK-1316: a transparent (REDIRECT) listener routes every TCP connection
// to its original destination by its first bytes. A real REDIRECT needs
// root and an nftables rule, so the listener's OriginalDstResolver is a
// fake naming the upstream test server, and the client dials the
// listener directly — what the kernel would have done after rewriting
// the destination.

// transparentTestPeek is the shortened first-bytes peek deadline the
// tests run with (decision U1: overridable per listener).
const transparentTestPeek = 80 * time.Millisecond

const transparentListenerName = "gw-transparent"

// tcpTestServer is a counting TCP server running handle per connection.
type tcpTestServer struct {
	ln      net.Listener
	accepts atomic.Int32
	wg      sync.WaitGroup
}

func newTCPTestServer(t *testing.T, network, addr string, handle func(net.Conn)) *tcpTestServer {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("listen %s %s: %v", network, addr, err)
	}
	s := &tcpTestServer{ln: ln}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.accepts.Add(1)
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				defer c.Close()
				handle(c)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		s.wg.Wait()
	})
	return s
}

func (s *tcpTestServer) addr() netip.AddrPort {
	return netip.MustParseAddrPort(s.ln.Addr().String())
}

// rawHTTPUpstream answers every request head it reads with a 200 whose
// body is the request line, keeping the connection alive. It never
// validates the request (so a malformed request-target reaches it).
type rawHTTPUpstream struct {
	*tcpTestServer
	mu    sync.Mutex
	heads []string
}

func newRawHTTPUpstream(t *testing.T) *rawHTTPUpstream {
	t.Helper()
	return newRawHTTPUpstreamOn(t, "tcp4", "127.0.0.1:0")
}

func newRawHTTPUpstreamOn(t *testing.T, network, addr string) *rawHTTPUpstream {
	t.Helper()
	u := &rawHTTPUpstream{}
	u.tcpTestServer = newTCPTestServer(t, network, addr, func(c net.Conn) {
		br := bufio.NewReader(c)
		for {
			var head strings.Builder
			for {
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				head.WriteString(line)
				if line == "\r\n" {
					break
				}
			}
			h := head.String()
			u.mu.Lock()
			u.heads = append(u.heads, h)
			u.mu.Unlock()
			reqLine := strings.TrimRight(strings.SplitN(h, "\r\n", 2)[0], "\r\n")
			fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(reqLine), reqLine)
		}
	})
	return u
}

func (u *rawHTTPUpstream) seenHeads() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.heads...)
}

// bannerUpstream writes banner on accept, then answers each client line
// with "ok <line>" and closes after the client's "QUIT".
func newBannerUpstream(t *testing.T, banner string) *tcpTestServer {
	t.Helper()
	return newTCPTestServer(t, "tcp4", "127.0.0.1:0", func(c net.Conn) {
		if _, err := io.WriteString(c, banner); err != nil {
			return
		}
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			fmt.Fprintf(c, "ok %s", line)
			if strings.TrimSpace(line) == "QUIT" {
				return
			}
		}
	})
}

// newEchoUpstream echoes every byte until the client half-closes.
func newEchoUpstream(t *testing.T) *tcpTestServer {
	t.Helper()
	return newTCPTestServer(t, "tcp4", "127.0.0.1:0", func(c net.Conn) {
		_, _ = io.Copy(c, c)
		if cw, ok := c.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	})
}

// tlsTestUpstream is an HTTPS (HTTP/1.1 only) upstream with its own cert.
type tlsTestUpstream struct {
	srv     *httptest.Server
	accepts atomic.Int32
}

type countingNetListener struct {
	net.Listener
	n *atomic.Int32
}

func (l countingNetListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.n.Add(1)
	}
	return c, err
}

func newTLSTestUpstream(t *testing.T) *tlsTestUpstream {
	t.Helper()
	u := &tlsTestUpstream{}
	u.srv = httptest.NewUnstartedServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		fmt.Fprintf(w, "tls host=%s path=%s", r.Host, r.URL.Path)
	}))
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	u.srv.Listener = countingNetListener{Listener: ln, n: &u.accepts}
	u.srv.EnableHTTP2 = false
	u.srv.StartTLS()
	t.Cleanup(u.srv.Close)
	return u
}

func (u *tlsTestUpstream) addr() netip.AddrPort {
	return netip.MustParseAddrPort(u.srv.Listener.Addr().String())
}

// fakeNameResolver answers name-binding lookups from a table and counts
// them. An unknown name fails (no real DNS in tests).
type fakeNameResolver struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr
	calls   atomic.Int32
}

func newFakeNameResolver(answers map[string][]netip.Addr) *fakeNameResolver {
	return &fakeNameResolver{answers: answers}
}

func (f *fakeNameResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.answers[host]
	if !ok {
		return nil, fmt.Errorf("fake resolver: no such host %q", host)
	}
	return a, nil
}

// transparentProxy is a started transparent listener.
type transparentProxy struct {
	stack *proxybuild.Stack
	store *usk1181Store
	logs  *testutil.CaptureLogger
	names *fakeNameResolver
	addr  string
}

// startTransparentProxy builds a transparent listener whose fake resolver
// reports origDst for every connection. mutate may adjust Deps.
func startTransparentProxy(t *testing.T, ctx context.Context, origDst netip.AddrPort, mutate func(*proxybuild.Deps)) *transparentProxy {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	logs, logger := testutil.NewCaptureLogger()
	p := &transparentProxy{store: &usk1181Store{}, logs: logs, names: newFakeNameResolver(nil)}
	deps := proxybuild.Deps{
		Logger:       logger,
		ListenerName: transparentListenerName,
		ListenAddr:   "127.0.0.1:0",
		FlowStore:    p.store,
		BuildConfig: &connector.BuildConfig{
			ProxyConfig:        &config.ProxyConfig{},
			Issuer:             cert.NewIssuer(ca),
			InsecureSkipVerify: true,
		},
		TransparentMode:        config.TransparentModeRedirect,
		TransparentPeekTimeout: transparentTestPeek,
		NameResolver:           p.names,
		OriginalDstResolver: connector.OriginalDstFunc(func(net.Conn) (netip.AddrPort, error) {
			return origDst, nil
		}),
	}
	if mutate != nil {
		mutate(&deps)
	}
	if r, ok := deps.NameResolver.(*fakeNameResolver); ok {
		p.names = r
	}
	stack, err := proxybuild.BuildLiveStack(ctx, deps)
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	lctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = stack.Listener.Start(lctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	select {
	case <-stack.Listener.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("listener not ready in 5s")
	}
	p.stack = stack
	p.addr = stack.Listener.Addr()
	return p
}

func (p *transparentProxy) dial(t *testing.T) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", p.addr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return c
}

// transparentExchange sends raw request bytes on a fresh connection and
// returns the response, its body, and the client's local address.
func transparentExchange(t *testing.T, proxyAddr, req string) (*gohttp.Response, string, string) {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := gohttp.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(body), c.LocalAddr().String()
}

// waitStream polls the store until a Stream satisfies match and has at
// least wantFlows flows.
func waitStream(t *testing.T, s *usk1181Store, wantFlows int, match func(*flow.Stream) bool) (*flow.Stream, []*flow.Flow) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, st := range s.allStreams() {
			if !match(st) {
				continue
			}
			if fl := s.flowsOf(st.ID); len(fl) >= wantFlows {
				return st, fl
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no matching stream with %d flows within 5s; streams=%s", wantFlows, describeStreams(s))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func describeStreams(s *usk1181Store) string {
	var got []string
	for _, st := range s.allStreams() {
		got = append(got, fmt.Sprintf("{%s/%s/%s state=%s blocked=%s reason=%s tags=%v}",
			st.Protocol, st.Scheme, st.ID, st.State, st.BlockedBy, st.FailureReason, st.Tags))
	}
	return strings.Join(got, " ")
}

// streamUpdates returns the updates recorded for id.
func (s *usk1181Store) streamUpdates(id string) []flow.StreamUpdate {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]flow.StreamUpdate(nil), s.updates[id]...)
}

// waitUpdate polls until an update for id satisfies match.
func waitUpdate(t *testing.T, s *usk1181Store, id string, what string, match func(flow.StreamUpdate) bool) flow.StreamUpdate {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, u := range s.streamUpdates(id) {
			if match(u) {
				return u
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("stream %s: no update with %s within 5s; updates=%+v", id, what, s.streamUpdates(id))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitPassthroughDone waits for the passthrough Stream with the given
// route to reach a terminal state and its single metadata Flow, and
// returns the Stream, the final update and the Flow.
func waitPassthroughDone(t *testing.T, s *usk1181Store, route string) (*flow.Stream, flow.StreamUpdate, *flow.Flow) {
	t.Helper()
	st, flows := waitStream(t, s, 1, func(st *flow.Stream) bool {
		return st.Tags["transparent"] == "passthrough" && (st.Tags["route"] == route || hasRouteUpdate(s, st.ID, route))
	})
	upd := waitUpdate(t, s, st.ID, "terminal State", func(u flow.StreamUpdate) bool {
		return u.State == "complete" || u.State == "error"
	})
	if len(flows) != 1 {
		t.Errorf("passthrough Stream has %d flows, want exactly 1 metadata flow", len(flows))
	}
	return st, upd, flows[0]
}

func hasRouteUpdate(s *usk1181Store, id, route string) bool {
	for _, u := range s.streamUpdates(id) {
		if u.AppendTags["route"] == route {
			return true
		}
	}
	return false
}

func flowByDirection(flows []*flow.Flow, dir string) *flow.Flow {
	for _, f := range flows {
		if f.Direction == dir && f.Metadata["variant"] != "modified" {
			return f
		}
	}
	return nil
}

func isHTTPStream(st *flow.Stream) bool { return st.Protocol == "http" && st.BlockedBy == "" }

// T9 (smoke): a server-first protocol's banner is relayed after the
// (shortened) peek deadline although the client sends nothing, and the
// connection is recorded as metadata only.
func TestTransparent_ServerFirst_BannerRelayed_Smoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const banner = "220 smtp.test ESMTP ready\r\n"
	up := newBannerUpstream(t, banner)
	p := startTransparentProxy(t, ctx, up.addr(), nil)

	c := p.dial(t)
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil || line != banner {
		t.Fatalf("read banner %q, %v; want %q without the client sending a byte", line, err, banner)
	}
	if _, err := io.WriteString(c, "QUIT\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if reply, err := br.ReadString('\n'); err != nil || reply != "ok QUIT\r\n" {
		t.Fatalf("reply %q, %v", reply, err)
	}
	clientAddr := c.LocalAddr().String()
	_ = c.Close()

	st, upd, fl := waitPassthroughDone(t, p.store, "server_first")
	if st.Protocol != "raw" || st.Scheme != "http" || st.State != "active" {
		t.Errorf("Stream = %s/%s/%s, want raw/http/active at start", st.Protocol, st.Scheme, st.State)
	}
	if st.Tags["target"] != up.addr().String() {
		t.Errorf("Tags[target] = %q, want %s", st.Tags["target"], up.addr())
	}
	if st.ListenerName != transparentListenerName {
		t.Errorf("ListenerName = %q", st.ListenerName)
	}
	if st.ConnInfo == nil || st.ConnInfo.ClientAddr != clientAddr || st.ConnInfo.ServerAddr != up.addr().String() {
		t.Errorf("ConnInfo = %+v, want client %s server %s", st.ConnInfo, clientAddr, up.addr())
	}
	if upd.State != "complete" {
		t.Errorf("final State = %q, want complete", upd.State)
	}
	if got, want := fl.Metadata["bytes_upstream_to_client"], fmt.Sprint(len(banner)+len("ok QUIT\r\n")); got != want {
		t.Errorf("bytes_upstream_to_client = %q, want %s", got, want)
	}
	if got := fl.Metadata["bytes_client_to_upstream"]; got != "6" {
		t.Errorf("bytes_client_to_upstream = %q, want 6", got)
	}
	if len(fl.RawBytes) != 0 || len(fl.Body) != 0 {
		t.Errorf("metadata flow carries payload bytes (raw %d, body %d)", len(fl.RawBytes), len(fl.Body))
	}
	if n := up.accepts.Load(); n != 1 {
		t.Errorf("upstream accepted %d connections, want 1", n)
	}
}

// T11 (smoke): a 0x16 connection is passed through unmodified — the
// client sees the upstream's own certificate — and SNI, the ALPN offer
// list in wire order, JA3 and JA4 are recorded.
func TestTransparent_TLS_PassthroughWithClientHelloMetadata_Smoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	up := newTLSTestUpstream(t)
	p := startTransparentProxy(t, ctx, up.addr(), nil)

	raw := p.dial(t)
	tc := tls.Client(raw, &tls.Config{
		ServerName:         "sni.example",
		NextProtos:         []string{"h2", "http/1.1"},
		InsecureSkipVerify: true, //nolint:gosec // the test checks the cert by identity below
	})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("TLS handshake through the proxy: %v", err)
	}
	if got := tc.ConnectionState().PeerCertificates[0]; !got.Equal(up.srv.Certificate()) {
		t.Fatalf("client saw certificate %q, want the upstream's own (no MITM)", got.Subject)
	}
	if _, err := io.WriteString(tc, "GET /tls HTTP/1.1\r\nHost: sni.example\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := gohttp.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "tls host=sni.example path=/tls" {
		t.Fatalf("body %q", body)
	}
	_ = tc.Close()

	st, _, fl := waitPassthroughDone(t, p.store, "tls")
	if st.Protocol != "tls-handshake" || st.Scheme != "https" {
		t.Errorf("Stream = %s/%s, want tls-handshake/https", st.Protocol, st.Scheme)
	}
	if st.ConnInfo == nil || st.ConnInfo.TLSClientJA3 == "" || st.ConnInfo.TLSClientJA4 == "" {
		t.Errorf("ConnInfo = %+v, want client JA3 / JA4", st.ConnInfo)
	}
	if fl.Metadata["sni"] != "sni.example" {
		t.Errorf("sni = %q", fl.Metadata["sni"])
	}
	if fl.Metadata["alpn_offers"] != "h2,http/1.1" {
		t.Errorf("alpn_offers = %q, want h2,http/1.1 (wire order)", fl.Metadata["alpn_offers"])
	}
	if fl.Metadata["client_ja3"] == "" || fl.Metadata["client_ja4"] == "" {
		t.Errorf("metadata = %v, want client_ja3 / client_ja4", fl.Metadata)
	}
	if n := up.accepts.Load(); n != 1 {
		t.Errorf("upstream accepted %d connections, want 1", n)
	}
}
