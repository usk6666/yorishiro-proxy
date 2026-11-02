//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"bufio"
	"context"
	"io"
	"net"
	gohttp "net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// USK-1410 through BuildLiveStack (the production listener wiring): on one
// keep-alive connection to the explicit plain-HTTP forward proxy, every
// request reaches the upstream it names — not the first request's.

// rtUpstream is a plain HTTP/1.1 upstream that records every request head
// and identifies itself in each response (X-Upstream header and body).
// A request whose path starts with /sse is answered with an event stream
// of two events named after the upstream. closeAfter closes each
// connection after that many responses (0 = never).
type rtUpstream struct {
	name       string
	ln         net.Listener
	closeAfter int

	mu    sync.Mutex
	heads []string
	conns int
}

func startRTUpstream(t *testing.T, name string, closeAfter int) *rtUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	u := &rtUpstream{name: name, ln: ln, closeAfter: closeAfter}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			u.mu.Lock()
			u.conns++
			u.mu.Unlock()
			go u.serve(c)
		}
	}()
	return u
}

func (u *rtUpstream) addr() string { return u.ln.Addr().String() }

func (u *rtUpstream) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(c)
	for served := 0; ; {
		var head strings.Builder
		for {
			line, err := br.ReadString('\n')
			head.WriteString(line)
			if err != nil {
				return
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}
		u.mu.Lock()
		u.heads = append(u.heads, head.String())
		u.mu.Unlock()
		fields := strings.Fields(strings.SplitN(head.String(), "\r\n", 2)[0])
		if len(fields) >= 2 && strings.Contains(fields[1], "/sse") {
			_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n\r\n"+
				"data: "+u.name+"-1\n\n"+"data: "+u.name+"-2\n\n")
			buf := make([]byte, 256)
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, _ = c.Read(buf)
			return
		}
		resp := "HTTP/1.1 200 OK\r\nX-Upstream: " + u.name + "\r\nContent-Length: " +
			strconv.Itoa(len(u.name)) + "\r\n\r\n" + u.name
		if _, err := io.WriteString(c, resp); err != nil {
			return
		}
		served++
		if u.closeAfter > 0 && served >= u.closeAfter {
			return
		}
	}
}

// requestLines returns the request line of every head received, in order.
func (u *rtUpstream) requestLines() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]string, len(u.heads))
	for i, h := range u.heads {
		out[i] = strings.SplitN(h, "\r\n", 2)[0]
	}
	return out
}

func (u *rtUpstream) headsSnapshot() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.heads...)
}

func (u *rtUpstream) connCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.conns
}

// startRetargetProxy builds the production listener with a flow store;
// mutate may adjust Deps (BuildConfig is already set).
func startRetargetProxy(t *testing.T, mutate func(*proxybuild.Deps)) (*flowStoreForH2Pool, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	store := &flowStoreForH2Pool{}
	deps := proxybuild.Deps{
		Logger:       testutil.DiscardLogger(),
		ListenerName: "usk-1410",
		ListenAddr:   "127.0.0.1:0",
		FlowStore:    store,
		BuildConfig: &connector.BuildConfig{
			ProxyConfig:        &config.ProxyConfig{},
			Issuer:             cert.NewIssuer(ca),
			InsecureSkipVerify: true,
		},
	}
	if mutate != nil {
		mutate(&deps)
	}
	stack, err := proxybuild.BuildLiveStack(ctx, deps)
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	go func() { _ = stack.Listener.Start(ctx) }()
	select {
	case <-stack.Listener.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("listener not ready in 5s")
	}
	return store, stack.Listener.Addr()
}

// absGet is a forward-proxy GET in absolute-form with a matching Host.
func absGet(addr, path string) string {
	return "GET http://" + addr + path + " HTTP/1.1\r\nHost: " + addr + "\r\n\r\n"
}

// rtResponse is one response read off the client connection.
type rtResponse struct {
	status   int
	upstream string
	server   string
	body     string
}

func readRTResponse(t *testing.T, br *bufio.Reader) rtResponse {
	t.Helper()
	resp, err := gohttp.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return rtResponse{
		status:   resp.StatusCode,
		upstream: resp.Header.Get("X-Upstream"),
		server:   resp.Header.Get("Server"),
		body:     string(body),
	}
}

func rtWrite(t *testing.T, c net.Conn, s string) {
	t.Helper()
	if _, err := io.WriteString(c, s); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// expectLines fails unless u received exactly want (request lines).
func expectLines(t *testing.T, u *rtUpstream, want ...string) {
	t.Helper()
	got := u.requestLines()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("upstream %s request lines = %q, want %q", u.name, got, want)
	}
}

// sendStreamOf returns the StreamID of the send flow whose URL path is path.
func sendStreamOf(t *testing.T, store *flowStoreForH2Pool, path string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, f := range store.Flows() {
			if f.Direction == "send" && f.URL != nil && f.URL.Path == path {
				return f.StreamID
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no send flow recorded for %s within 5s", path)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// streamUpdates returns every StreamUpdate recorded for id.
func streamUpdates(store *flowStoreForH2Pool, id string) []flow.StreamUpdate {
	store.mu.Lock()
	defer store.mu.Unlock()
	return append([]flow.StreamUpdate(nil), store.updates[id]...)
}

// waitStreamUpdate waits until a StreamUpdate for id satisfies ok.
func waitStreamUpdate(t *testing.T, store *flowStoreForH2Pool, id, what string, ok func(flow.StreamUpdate) bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, u := range streamUpdates(store, id) {
			if ok(u) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Errorf("Stream %s: no update with %s within 5s (updates %+v)", id, what, streamUpdates(store, id))
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitBlockedStream waits until a Stream with blockedBy was saved or
// updated in store and returns it as (State, BlockedBy) pairs seen.
func waitBlocked(t *testing.T, store *flowStoreForH2Pool, blockedBy string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, st := range store.Streams() {
			if st.BlockedBy == blockedBy && st.State == "error" {
				return
			}
		}
		store.mu.Lock()
		for _, ups := range store.updates {
			for _, u := range ups {
				if u.BlockedBy == blockedBy && u.State == "error" {
					store.mu.Unlock()
					return
				}
			}
		}
		store.mu.Unlock()
		if time.Now().After(deadline) {
			t.Errorf("no Stream recorded with State=error blocked_by=%s within 5s", blockedBy)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// T1 + T2: absolute-form A then B on one keep-alive connection. B's
// request reaches B (A never sees it), B's response is B's, and B's Stream
// records B's socket as its server address.
func TestProxybuild_ForwardRetarget_AbsoluteFormSwitch(t *testing.T) {
	a := startRTUpstream(t, "A", 0)
	b := startRTUpstream(t, "B", 0)
	store, proxyAddr := startRetargetProxy(t, nil)
	c, br := fwdDial(t, proxyAddr)

	rtWrite(t, c, absGet(a.addr(), "/one"))
	if r := readRTResponse(t, br); r.status != 200 || r.upstream != "A" {
		t.Fatalf("first response = %+v, want 200 from A", r)
	}
	rtWrite(t, c, absGet(b.addr(), "/two"))
	if r := readRTResponse(t, br); r.status != 200 || r.upstream != "B" {
		t.Errorf("second response = %+v, want 200 from B", r)
	}
	expectLines(t, a, "GET /one HTTP/1.1")
	expectLines(t, b, "GET /two HTTP/1.1")

	idA := sendStreamOf(t, store, "/one")
	idB := sendStreamOf(t, store, "/two")
	waitStreamUpdate(t, store, idA, "server_addr "+a.addr(), func(u flow.StreamUpdate) bool { return u.ServerAddr == a.addr() })
	waitStreamUpdate(t, store, idB, "server_addr "+b.addr(), func(u flow.StreamUpdate) bool { return u.ServerAddr == b.addr() })
	for _, u := range streamUpdates(store, idB) {
		if u.ServerAddr == a.addr() {
			t.Errorf("B's Stream recorded A's server_addr %s", a.addr())
		}
	}
}

// T3: an origin-form later request routes by its Host header.
func TestProxybuild_ForwardRetarget_OriginFormHostSwitch(t *testing.T) {
	a := startRTUpstream(t, "A", 0)
	b := startRTUpstream(t, "B", 0)
	_, proxyAddr := startRetargetProxy(t, nil)
	c, br := fwdDial(t, proxyAddr)

	rtWrite(t, c, absGet(a.addr(), "/one"))
	if r := readRTResponse(t, br); r.upstream != "A" {
		t.Fatalf("first response = %+v, want A", r)
	}
	rtWrite(t, c, "GET /two HTTP/1.1\r\nHost: "+b.addr()+"\r\n\r\n")
	if r := readRTResponse(t, br); r.status != 200 || r.upstream != "B" {
		t.Errorf("origin-form Host: B response = %+v, want 200 from B", r)
	}
	expectLines(t, a, "GET /one HTTP/1.1")
	expectLines(t, b, "GET /two HTTP/1.1")
}

// T4: A → B → A; each request reaches its own upstream. Returning to A
// dials A again (no per-destination pool).
func TestProxybuild_ForwardRetarget_AlternatingTargets(t *testing.T) {
	a := startRTUpstream(t, "A", 0)
	b := startRTUpstream(t, "B", 0)
	_, proxyAddr := startRetargetProxy(t, nil)
	c, br := fwdDial(t, proxyAddr)

	for i, step := range []struct {
		u    *rtUpstream
		path string
	}{{a, "/one"}, {b, "/two"}, {a, "/three"}} {
		rtWrite(t, c, absGet(step.u.addr(), step.path))
		if r := readRTResponse(t, br); r.status != 200 || r.upstream != step.u.name {
			t.Errorf("response %d = %+v, want 200 from %s", i+1, r, step.u.name)
		}
	}
	expectLines(t, a, "GET /one HTTP/1.1", "GET /three HTTP/1.1")
	expectLines(t, b, "GET /two HTTP/1.1")
	if n := a.connCount(); n != 2 {
		t.Errorf("connections to A = %d, want 2 (A is redialed after the switch to B)", n)
	}
}

// T5: two pipelined requests in one write, to A then B: responses come
// back in request order, each from its own upstream.
func TestProxybuild_ForwardRetarget_Pipelined(t *testing.T) {
	a := startRTUpstream(t, "A", 0)
	b := startRTUpstream(t, "B", 0)
	_, proxyAddr := startRetargetProxy(t, nil)
	c, br := fwdDial(t, proxyAddr)

	rtWrite(t, c, absGet(a.addr(), "/one")+absGet(b.addr(), "/two"))
	if r := readRTResponse(t, br); r.upstream != "A" {
		t.Errorf("first pipelined response = %+v, want A", r)
	}
	if r := readRTResponse(t, br); r.upstream != "B" {
		t.Errorf("second pipelined response = %+v, want B", r)
	}
	expectLines(t, a, "GET /one HTTP/1.1")
	expectLines(t, b, "GET /two HTTP/1.1")
}

// T8: forward_as_received still routes per request; B receives its
// request exactly as the client sent it (absolute-form, Proxy-* kept).
func TestProxybuild_ForwardRetarget_ForwardAsReceived(t *testing.T) {
	a := startRTUpstream(t, "A", 0)
	b := startRTUpstream(t, "B", 0)
	_, proxyAddr := startRetargetProxy(t, func(d *proxybuild.Deps) { d.ForwardAsReceived = true })
	c, br := fwdDial(t, proxyAddr)

	rtWrite(t, c, fwdReq(a.addr(), "/one", "keep-alive"))
	if r := readRTResponse(t, br); r.upstream != "A" {
		t.Fatalf("first response = %+v, want A", r)
	}
	req := fwdReq(b.addr(), "/two", "keep-alive")
	rtWrite(t, c, req)
	if r := readRTResponse(t, br); r.upstream != "B" {
		t.Errorf("second response = %+v, want B", r)
	}
	if got := b.headsSnapshot(); len(got) != 1 || got[0] != req {
		t.Errorf("B heads = %q, want exactly [%q] (verbatim)", got, req)
	}
	if got := a.requestLines(); len(got) != 1 {
		t.Errorf("A request lines = %q, want only the first request", got)
	}
}

// T9: through an upstream CONNECT proxy, the switch opens a second
// tunnel naming B.
func TestProxybuild_ForwardRetarget_ThroughUpstreamProxy(t *testing.T) {
	a := startRTUpstream(t, "A", 0)
	b := startRTUpstream(t, "B", 0)
	chain := startFwdConnectProxy(t)
	_, proxyAddr := startRetargetProxy(t, func(d *proxybuild.Deps) {
		d.BuildConfig.SetUpstreamProxy(&url.URL{Scheme: "http", Host: chain.ln.Addr().String()})
	})
	c, br := fwdDial(t, proxyAddr)

	rtWrite(t, c, absGet(a.addr(), "/one"))
	if r := readRTResponse(t, br); r.upstream != "A" {
		t.Fatalf("first response = %+v, want A", r)
	}
	rtWrite(t, c, absGet(b.addr(), "/two"))
	if r := readRTResponse(t, br); r.upstream != "B" {
		t.Errorf("second response = %+v, want B", r)
	}
	heads := chain.connectHeads()
	if len(heads) != 2 ||
		!strings.HasPrefix(heads[0], "CONNECT "+a.addr()+" HTTP/1.1\r\n") ||
		!strings.HasPrefix(heads[1], "CONNECT "+b.addr()+" HTTP/1.1\r\n") {
		t.Errorf("upstream proxy CONNECTs = %q, want CONNECT %s then CONNECT %s", heads, a.addr(), b.addr())
	}
}

// readSSEHeadAndEvents reads an event-stream response head and want
// events (data values), bounded by a 5s read deadline.
func readSSEHeadAndEvents(t *testing.T, c net.Conn, br *bufio.Reader, want int) (status string, events []string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	status, err := br.ReadString('\n')
	if err != nil {
		return "", nil
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}
	for len(events) < want {
		line, err := br.ReadString('\n')
		if err != nil {
			return status, events
		}
		if v, ok := strings.CutPrefix(strings.TrimRight(line, "\r\n"), "data: "); ok {
			events = append(events, v)
		}
	}
	return strings.TrimRight(status, "\r\n"), events
}

// T10 (SSE): an event stream requested on a later request to B is relayed
// from B — the upgrade detaches B's upstream Layer, not A's.
func TestProxybuild_ForwardRetarget_SSEOnSwitchedTarget(t *testing.T) {
	a := startRTUpstream(t, "A", 0)
	b := startRTUpstream(t, "B", 0)
	_, proxyAddr := startRetargetProxy(t, nil)
	c, br := fwdDial(t, proxyAddr)

	rtWrite(t, c, absGet(a.addr(), "/one"))
	if r := readRTResponse(t, br); r.upstream != "A" {
		t.Fatalf("first response = %+v, want A", r)
	}
	rtWrite(t, c, absGet(b.addr(), "/sse"))
	status, events := readSSEHeadAndEvents(t, c, br, 2)
	if !strings.Contains(status, " 200") || strings.Join(events, ",") != "B-1,B-2" {
		t.Errorf("SSE on B: status %q events %q, want 200 and [B-1 B-2]", status, events)
	}
	expectLines(t, a, "GET /one HTTP/1.1")
}

// T10 (WebSocket): a WebSocket Upgrade on a later request to B is relayed
// to B and the frames echo from B.
func TestProxybuild_ForwardRetarget_WebSocketOnSwitchedTarget(t *testing.T) {
	a := startRTUpstream(t, "A", 0)
	hits := newWSEchoHitsUSK913()
	bAddr, stopB := startWSEchoUpstreamForUSK913(t, hits)
	t.Cleanup(stopB)
	_, proxyAddr := startRetargetProxy(t, nil)
	c, br := fwdDial(t, proxyAddr)

	rtWrite(t, c, absGet(a.addr(), "/one"))
	if r := readRTResponse(t, br); r.upstream != "A" {
		t.Fatalf("first response = %+v, want A", r)
	}
	if err := writeWSClientHandshakeForUSK913(c, bAddr); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if err := readWS101ForUSK913(br); err != nil {
		t.Fatalf("WebSocket Upgrade to B: %v (A request lines %q)", err, a.requestLines())
	}
	frame := &ws.Frame{Fin: true, Opcode: ws.OpcodeText, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("hello-b")}
	if err := ws.WriteFrame(c, frame); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	echo, err := ws.ReadFrame(br)
	if err != nil || string(echo.Payload) != "hello-b" {
		t.Errorf("echo = %v, %v; want hello-b from B", echo, err)
	}
	if hits.text.Load() != 1 {
		t.Errorf("B text frames = %d, want 1", hits.text.Load())
	}
	expectLines(t, a, "GET /one HTTP/1.1")
}

// T11: the upstream closes after the first response, so the second
// request on the same target is redialed — and an event stream on that
// redialed upstream is relayed (the upgrade detaches the live Layer).
func TestProxybuild_ForwardRetarget_SSEAfterStaleRedial(t *testing.T) {
	a := startRTUpstream(t, "A", 1)
	_, proxyAddr := startRetargetProxy(t, nil)
	c, br := fwdDial(t, proxyAddr)

	rtWrite(t, c, absGet(a.addr(), "/one"))
	if r := readRTResponse(t, br); r.upstream != "A" {
		t.Fatalf("first response = %+v, want A", r)
	}
	time.Sleep(200 * time.Millisecond) // let A's FIN reach the proxy
	rtWrite(t, c, absGet(a.addr(), "/sse"))
	status, events := readSSEHeadAndEvents(t, c, br, 2)
	if !strings.Contains(status, " 200") || strings.Join(events, ",") != "A-1,A-2" {
		t.Errorf("SSE after redial: status %q events %q, want 200 and [A-1 A-2]", status, events)
	}
	if n := a.connCount(); n != 2 {
		t.Errorf("connections to A = %d, want 2 (redialed)", n)
	}
}

// T12 (guard): plaintext inside a CONNECT tunnel to A stays on A whatever
// a later request names — the tunnel's target is the client's choice.
func TestProxybuild_ForwardRetarget_CONNECTTunnelStaysPinned(t *testing.T) {
	a := startRTUpstream(t, "A", 0)
	b := startRTUpstream(t, "B", 0)
	_, proxyAddr := startRetargetProxy(t, nil)
	c, br := fwdDial(t, proxyAddr)

	rtWrite(t, c, "CONNECT "+a.addr()+" HTTP/1.1\r\nHost: "+a.addr()+"\r\n\r\n")
	if status := readFwdResponse(t, br); !strings.Contains(status, " 200") {
		t.Fatalf("CONNECT status = %q, want 200", status)
	}
	rtWrite(t, c, absGet(a.addr(), "/one"))
	if r := readRTResponse(t, br); r.upstream != "A" {
		t.Fatalf("first response = %+v, want A", r)
	}
	rtWrite(t, c, absGet(b.addr(), "/two"))
	if r := readRTResponse(t, br); r.upstream != "A" {
		t.Errorf("second in-tunnel response = %+v, want A (tunnel stays pinned)", r)
	}
	if got := b.requestLines(); len(got) != 0 {
		t.Errorf("B received %q through a tunnel to A", got)
	}
}

// T13 (guard): a tcp_forwards HTTP listener is pinned to its target.
func TestProxybuild_ForwardRetarget_TCPForwardStaysPinned(t *testing.T) {
	a := startRTUpstream(t, "A", 0)
	b := startRTUpstream(t, "B", 0)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	mgr := newForwardTestManager(t, &flowStoreCapture{})
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Stop(context.Background()) })
	if err := mgr.StartTCPForwards(ctx, proxybuild.TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{"0": {Target: a.addr(), Protocol: "auto"}},
	}); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}
	c, br := fwdDial(t, mgr.TCPForwardAddrs()["0"])
	rtWrite(t, c, "GET /one HTTP/1.1\r\nHost: "+a.addr()+"\r\n\r\n")
	if r := readRTResponse(t, br); r.upstream != "A" {
		t.Fatalf("first response = %+v, want A", r)
	}
	rtWrite(t, c, absGet(b.addr(), "/two"))
	if r := readRTResponse(t, br); r.upstream != "A" {
		t.Errorf("second response = %+v, want A (tcp_forwards stays pinned)", r)
	}
	if got := b.requestLines(); len(got) != 0 {
		t.Errorf("B received %q through a tcp_forwards listener to A", got)
	}
}

// T13 (guard): a transparent connection is pinned to SO_ORIGINAL_DST.
func TestProxybuild_ForwardRetarget_TransparentStaysPinned(t *testing.T) {
	a := startRTUpstream(t, "A", 0)
	b := startRTUpstream(t, "B", 0)
	ctx := transparentCtx(t)
	p := startTransparentProxy(t, ctx, netip.MustParseAddrPort(a.addr()), nil)
	c, br := fwdDial(t, p.addr)
	rtWrite(t, c, "GET /one HTTP/1.1\r\nHost: "+a.addr()+"\r\n\r\n")
	if r := readRTResponse(t, br); r.upstream != "A" {
		t.Fatalf("first response = %+v, want A", r)
	}
	rtWrite(t, c, absGet(b.addr(), "/two"))
	if r := readRTResponse(t, br); r.upstream != "A" {
		t.Errorf("second response = %+v, want A (transparent stays pinned)", r)
	}
	if got := b.requestLines(); len(got) != 0 {
		t.Errorf("B received %q through a transparent connection to A", got)
	}
}

// T15: the switch costs one rate-limit token. With the budget spent by
// the first request, the switch to B is answered 429 by the proxy and
// recorded as a rate_limit block; neither upstream receives B's request.
func TestProxybuild_ForwardRetarget_RateLimitOnSwitch(t *testing.T) {
	a := startRTUpstream(t, "A", 0)
	b := startRTUpstream(t, "B", 0)
	rl := connector.NewRateLimiter()
	rl.SetPolicyLimits(connector.RateLimitConfig{MaxRequestsPerSecond: 0.01})
	store, proxyAddr := startRetargetProxy(t, func(d *proxybuild.Deps) { d.RateLimiter = rl })
	c, br := fwdDial(t, proxyAddr)

	rtWrite(t, c, absGet(a.addr(), "/one"))
	if r := readRTResponse(t, br); r.upstream != "A" {
		t.Fatalf("first response = %+v, want A", r)
	}
	rtWrite(t, c, absGet(b.addr(), "/two"))
	if r := readRTResponse(t, br); r.status != 429 || r.server != "yorishiro-proxy" {
		t.Errorf("switch under an exhausted rate limit = %+v, want the proxy's 429", r)
	}
	expectLines(t, a, "GET /one HTTP/1.1")
	expectLines(t, b)
	waitBlocked(t, store, "rate_limit")
}

// T16: a later request whose target cannot be resolved (HTTP/1.0
// origin-form without Host) is refused 400 like the first-request gate,
// the connection ends, and no upstream receives a byte of it.
func TestProxybuild_ForwardRetarget_UnresolvableLaterRequest(t *testing.T) {
	a := startRTUpstream(t, "A", 0)
	store, proxyAddr := startRetargetProxy(t, nil)
	c, br := fwdDial(t, proxyAddr)

	rtWrite(t, c, absGet(a.addr(), "/one"))
	if r := readRTResponse(t, br); r.upstream != "A" {
		t.Fatalf("first response = %+v, want A", r)
	}
	rtWrite(t, c, "GET /no-host HTTP/1.0\r\nUser-Agent: legacy\r\n\r\n")
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if r := readRTResponse(t, br); r.status != 400 || r.server != "yorishiro-proxy" {
		t.Errorf("unresolvable later request = %+v, want the proxy's 400", r)
	}
	if _, err := br.ReadByte(); err == nil {
		t.Errorf("connection still open after the 400, want it closed")
	}
	expectLines(t, a, "GET /one HTTP/1.1")

	deadline := time.Now().Add(5 * time.Second)
	for {
		found := false
		for _, st := range store.Streams() {
			if st.State == "error" && st.FailureReason == "forward_target_invalid" {
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Errorf("no Stream with State=error FailureReason=forward_target_invalid within 5s")
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// T18: B is unreachable at the switch. The client gets the proxy's 502,
// B's Stream ends in State=error, and A receives nothing more.
func TestProxybuild_ForwardRetarget_UnreachableTarget(t *testing.T) {
	a := startRTUpstream(t, "A", 0)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close()
	store, proxyAddr := startRetargetProxy(t, nil)
	c, br := fwdDial(t, proxyAddr)

	rtWrite(t, c, absGet(a.addr(), "/one"))
	if r := readRTResponse(t, br); r.upstream != "A" {
		t.Fatalf("first response = %+v, want A", r)
	}
	rtWrite(t, c, absGet(deadAddr, "/two"))
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if r := readRTResponse(t, br); r.status != 502 || r.server != "yorishiro-proxy" {
		t.Errorf("switch to an unreachable target = %+v, want the proxy's 502", r)
	}
	expectLines(t, a, "GET /one HTTP/1.1")
	idB := sendStreamOf(t, store, "/two")
	waitStreamUpdate(t, store, idB, "State=error", func(u flow.StreamUpdate) bool { return u.State == "error" })
}

// T16 after a switch (review F-2): A, then B, then an unresolvable
// request. The 400 record names the upstream the connection was bound to
// when the head failed — B, not the connection's first target A.
func TestProxybuild_ForwardRetarget_UnresolvableAfterSwitchTagsCurrentTarget(t *testing.T) {
	a := startRTUpstream(t, "A", 0)
	b := startRTUpstream(t, "B", 0)
	store, proxyAddr := startRetargetProxy(t, nil)
	c, br := fwdDial(t, proxyAddr)

	rtWrite(t, c, absGet(a.addr(), "/one"))
	if r := readRTResponse(t, br); r.upstream != "A" {
		t.Fatalf("first response = %+v, want A", r)
	}
	rtWrite(t, c, absGet(b.addr(), "/two"))
	if r := readRTResponse(t, br); r.upstream != "B" {
		t.Fatalf("second response = %+v, want B", r)
	}
	rtWrite(t, c, "GET /no-host HTTP/1.0\r\nUser-Agent: legacy\r\n\r\n")
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if r := readRTResponse(t, br); r.status != 400 {
		t.Errorf("unresolvable request after a switch = %+v, want the proxy's 400", r)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		var rec *flow.Stream
		for _, st := range store.Streams() {
			if st.State == "error" && st.FailureReason == "forward_target_invalid" {
				rec = st
			}
		}
		if rec != nil {
			if got := rec.Tags["target"]; got != b.addr() {
				t.Errorf("forward_target_invalid Stream tags.target = %q, want %q (current upstream B; A is %s)", got, b.addr(), a.addr())
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no Stream with State=error FailureReason=forward_target_invalid within 5s")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
