//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// USK-1079: RFC-001 §9.3 D4 "Raw wins" on HTTP/1.x and raw TCP. A plugin
// that assigns msg["raw"] must have exactly those bytes reach the wire,
// and the recorded modified variant must equal what was sent.
//
// Every test here drives a real Starlark plugin (pluginv2.Engine
// .LoadPlugins on a .star file) through BuildLiveStack, and observes the
// bytes on the far side with a capturing peer.

// smuggleRaw is a plugin payload whose framing a Message-path serializer
// would never produce: an odd header with a double space.
const smuggleRaw = "POST /p HTTP/1.1\r\nHost: x\r\nX-Odd:  v\r\nContent-Length: 2\r\n\r\nhi"

// --- capturing upstream ----------------------------------------------------

// rawCaptureUpstream records every byte it reads per accepted connection.
// In HTTP mode it parses each request (Content-Length or chunked) and
// answers it with a body naming the request path and the 1-based
// connection index, so a test can tell whose response it received.
type rawCaptureUpstream struct {
	ln       net.Listener
	httpMode bool

	mu    sync.Mutex
	conns []*bytes.Buffer
	wg    sync.WaitGroup
}

func startRawCaptureUpstream(t *testing.T, httpMode bool, tlsCfg *tls.Config) *rawCaptureUpstream {
	t.Helper()
	var ln net.Listener
	var err error
	if tlsCfg != nil {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	u := &rawCaptureUpstream{ln: ln, httpMode: httpMode}
	u.wg.Add(1)
	go u.acceptLoop()
	t.Cleanup(u.stop)
	return u
}

func (u *rawCaptureUpstream) Addr() string { return u.ln.Addr().String() }

func (u *rawCaptureUpstream) stop() {
	_ = u.ln.Close()
	done := make(chan struct{})
	go func() { u.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

func (u *rawCaptureUpstream) acceptLoop() {
	defer u.wg.Done()
	for {
		c, err := u.ln.Accept()
		if err != nil {
			return
		}
		u.mu.Lock()
		buf := &bytes.Buffer{}
		u.conns = append(u.conns, buf)
		idx := len(u.conns)
		u.mu.Unlock()
		u.wg.Add(1)
		go u.serve(c, idx, buf)
	}
}

type lockedWriter struct {
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (u *rawCaptureUpstream) serve(c net.Conn, idx int, buf *bytes.Buffer) {
	defer u.wg.Done()
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	tee := io.TeeReader(c, lockedWriter{mu: &u.mu, buf: buf})
	if !u.httpMode {
		_, _ = io.Copy(io.Discard, tee)
		return
	}
	br := bufio.NewReader(tee)
	var out bytes.Buffer
	for {
		path, err := readUpstreamRequest(br)
		if err != nil {
			return
		}
		body := fmt.Sprintf("path=%s conn=%d", path, idx)
		fmt.Fprintf(&out, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
		// Answer pipelined requests in one write, so their responses
		// reach the proxy together and land in its read buffer — where a
		// conn-level idle probe cannot see the leftover.
		if br.Buffered() > 0 {
			continue
		}
		if _, err := c.Write(out.Bytes()); err != nil {
			return
		}
		out.Reset()
	}
}

// ConnCount returns the number of accepted connections.
func (u *rawCaptureUpstream) ConnCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.conns)
}

// Bytes returns a copy of the bytes read on connection idx (1-based).
func (u *rawCaptureUpstream) Bytes(idx int) []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	if idx < 1 || idx > len(u.conns) {
		return nil
	}
	return append([]byte(nil), u.conns[idx-1].Bytes()...)
}

// waitBytes polls until connection idx has read at least n bytes or the
// deadline passes, then returns what it has.
func (u *rawCaptureUpstream) waitBytes(idx, n int) []byte {
	end := time.Now().Add(3 * time.Second)
	for time.Now().Before(end) {
		if b := u.Bytes(idx); len(b) >= n {
			return b
		}
		time.Sleep(20 * time.Millisecond)
	}
	return u.Bytes(idx)
}

// readUpstreamRequest parses one HTTP/1.x request (start line, headers,
// Content-Length or chunked body) and returns its request-target.
func readUpstreamRequest(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return "", fmt.Errorf("bad request line %q", line)
	}
	target := parts[1]
	var contentLen int
	chunked := false
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			return "", err
		}
		if h == "\r\n" || h == "\n" {
			break
		}
		name, value, _ := strings.Cut(h, ":")
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "content-length":
			contentLen, _ = strconv.Atoi(value)
		case "transfer-encoding":
			chunked = strings.Contains(strings.ToLower(value), "chunked")
		}
	}
	if chunked {
		for {
			sizeLine, err := br.ReadString('\n')
			if err != nil {
				return "", err
			}
			sizeStr, _, _ := strings.Cut(strings.TrimSpace(sizeLine), ";")
			size, err := strconv.ParseInt(sizeStr, 16, 64)
			if err != nil {
				return "", err
			}
			if size == 0 {
				for {
					tr, err := br.ReadString('\n')
					if err != nil {
						return "", err
					}
					if tr == "\r\n" || tr == "\n" {
						return target, nil
					}
				}
			}
			if _, err := io.CopyN(io.Discard, br, size+2); err != nil {
				return "", err
			}
		}
	}
	if contentLen > 0 {
		if _, err := io.CopyN(io.Discard, br, int64(contentLen)); err != nil {
			return "", err
		}
	}
	return target, nil
}

// readOneResponse reads one Content-Length-framed HTTP/1.x response and
// returns its exact bytes and body.
func readOneResponse(br *bufio.Reader) (raw []byte, body string, err error) {
	var out bytes.Buffer
	contentLen := 0
	first := true
	for {
		line, err := br.ReadString('\n')
		out.WriteString(line)
		if err != nil {
			return out.Bytes(), "", err
		}
		if !first && (line == "\r\n" || line == "\n") {
			break
		}
		first = false
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "content-length") {
			contentLen, _ = strconv.Atoi(strings.TrimSpace(value))
		}
	}
	b := make([]byte, contentLen)
	if _, err := io.ReadFull(br, b); err != nil {
		return out.Bytes(), "", err
	}
	out.Write(b)
	return out.Bytes(), string(b), nil
}

// --- proxy harness ---------------------------------------------------------

type rawWinsHarness struct {
	store *flowStoreCapture
	mgr   *proxybuild.Manager
}

// startRawWinsForward boots a Manager whose stack carries a real plugin
// engine loaded from script (and optionally an HTTP Transform engine),
// then opens a TCP forward to target with the given protocol. Returns
// the harness and the forward listener address.
func startRawWinsForward(t *testing.T, ctx context.Context, script, target, protocol string, transform *httprules.TransformEngine) (*rawWinsHarness, string) {
	t.Helper()
	h := &rawWinsHarness{store: &flowStoreCapture{}}
	engine := loadRawWinsPlugin(t, ctx, script)
	buildCfg := rawWinsBuildConfig(t)
	mgr, err := proxybuild.NewManager(proxybuild.ManagerConfig{
		Logger: testutil.DiscardLogger(),
		StackFactory: func(ctx context.Context, name, addr string) (*proxybuild.Stack, error) {
			return proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
				Logger:              testutil.DiscardLogger(),
				ListenerName:        name,
				ListenAddr:          addr,
				FlowStore:           h.store,
				BuildConfig:         buildCfg,
				PluginV2Engine:      engine,
				HTTPTransformEngine: transform,
			})
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.StopAll(context.Background()) })
	h.mgr = mgr
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	if err := mgr.StartTCPForwards(ctx, proxybuild.TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{"0": {Target: target, Protocol: protocol}},
	}); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}
	fwdAddr := mgr.TCPForwardAddrs()["0"]
	if fwdAddr == "" {
		t.Fatal("TCPForwardAddrs missing port 0")
	}
	return h, fwdAddr
}

// startRawWinsMITM boots a BuildLiveStack listener (CONNECT MITM path,
// which owns the h1 redial chain) with a real plugin engine.
func startRawWinsMITM(t *testing.T, ctx context.Context, script string) (*flowStoreCapture, string) {
	t.Helper()
	store := &flowStoreCapture{}
	stack, err := proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
		Logger:         testutil.DiscardLogger(),
		ListenerName:   "usk-1079-mitm",
		ListenAddr:     "127.0.0.1:0",
		FlowStore:      store,
		BuildConfig:    rawWinsBuildConfig(t),
		PluginV2Engine: loadRawWinsPlugin(t, ctx, script),
	})
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

func rawWinsBuildConfig(t *testing.T) *connector.BuildConfig {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	return &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
	}
}

func loadRawWinsPlugin(t *testing.T, ctx context.Context, script string) *pluginv2.Engine {
	t.Helper()
	engine := pluginv2.NewEngine(testutil.DiscardLogger())
	path := writeUSK913PluginScript(t, script)
	if err := engine.LoadPlugins(ctx, []pluginv2.PluginConfig{{Path: path, OnError: string(pluginv2.OnErrorAbort)}}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	return engine
}

// waitFlow polls the store for a flow matching direction and variant
// ("" matches an unvariant-tagged flow) whose RawBytes satisfy match.
func waitFlow(store *flowStoreCapture, direction, variant string, match func([]byte) bool) *flow.Flow {
	end := time.Now().Add(5 * time.Second)
	for time.Now().Before(end) {
		for _, f := range store.Flows() {
			if f == nil || f.Direction != direction || f.Metadata["variant"] != variant {
				continue
			}
			if match == nil || match(f.RawBytes) {
				return f
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return nil
}

func describeFlows(store *flowStoreCapture) string {
	var b strings.Builder
	for _, f := range store.Flows() {
		fmt.Fprintf(&b, "\n  dir=%s variant=%q raw=%q", f.Direction, f.Metadata["variant"], f.RawBytes)
	}
	return b.String()
}

func dialForward(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return c, bufio.NewReader(c)
}

// --- tests -----------------------------------------------------------------

// TestPluginRawWins_HTTP1_Request covers Test Plan #1-#3: a plugin
// msg["raw"] write on the request (pre_pipeline, post_pipeline, and
// together with a Message-field write) reaches the upstream verbatim,
// and the variants record client bytes / plugin bytes.
func TestPluginRawWins_HTTP1_Request(t *testing.T) {
	cases := []struct {
		name   string
		script string
	}{
		{
			name: "pre_pipeline raw only",
			script: `
def on_req(msg, ctx):
    msg["raw"] = b"POST /p HTTP/1.1\r\nHost: x\r\nX-Odd:  v\r\nContent-Length: 2\r\n\r\nhi"
register_hook("http", "on_request", on_req)
`,
		},
		{
			name: "post_pipeline raw only",
			script: `
def on_req(msg, ctx):
    msg["raw"] = b"POST /p HTTP/1.1\r\nHost: x\r\nX-Odd:  v\r\nContent-Length: 2\r\n\r\nhi"
register_hook("http", "on_request", on_req, phase="post_pipeline")
`,
		},
		{
			name: "raw and message both written",
			script: `
def on_req(msg, ctx):
    msg["path"] = "/msgside"
    msg["raw"] = b"POST /p HTTP/1.1\r\nHost: x\r\nX-Odd:  v\r\nContent-Length: 2\r\n\r\nhi"
register_hook("http", "on_request", on_req)
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			up := startRawCaptureUpstream(t, true, nil)
			h, fwd := startRawWinsForward(t, ctx, tc.script, up.Addr(), "http", nil)

			const clientReq = "GET /orig HTTP/1.1\r\nHost: example.test\r\n\r\n"
			c, br := dialForward(t, fwd)
			if _, err := c.Write([]byte(clientReq)); err != nil {
				t.Fatalf("write: %v", err)
			}
			_, body, err := readOneResponse(br)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}

			if got := up.waitBytes(1, len(smuggleRaw)); string(got) != smuggleRaw {
				t.Errorf("upstream received %q, want plugin bytes %q", got, smuggleRaw)
			}
			if body != "path=/p conn=1" {
				t.Errorf("client response body = %q, want the response to the plugin's request", body)
			}

			orig := waitFlow(h.store, "send", "original", nil)
			if orig == nil || string(orig.RawBytes) != clientReq {
				t.Errorf("original send variant missing or wrong; flows:%s", describeFlows(h.store))
			}
			mod := waitFlow(h.store, "send", "modified", nil)
			if mod == nil || string(mod.RawBytes) != smuggleRaw {
				t.Errorf("modified send variant must equal the wire bytes %q; flows:%s", smuggleRaw, describeFlows(h.store))
			}
		})
	}
}

// TestPluginRawWins_HTTP1_Response covers Test Plan #4: an on_response
// msg["raw"] write reaches the client verbatim.
func TestPluginRawWins_HTTP1_Response(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const respRaw = "HTTP/1.1 418 Teapot\r\nContent-Length: 2\r\n\r\nok"
	up := startRawCaptureUpstream(t, true, nil)
	h, fwd := startRawWinsForward(t, ctx, `
def on_resp(msg, ctx):
    msg["raw"] = b"HTTP/1.1 418 Teapot\r\nContent-Length: 2\r\n\r\nok"
register_hook("http", "on_response", on_resp)
`, up.Addr(), "http", nil)

	c, br := dialForward(t, fwd)
	if _, err := c.Write([]byte("GET /orig HTTP/1.1\r\nHost: example.test\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	raw, _, err := readOneResponse(br)
	if err != nil {
		t.Fatalf("read response: %v (got %q)", err, raw)
	}
	if string(raw) != respRaw {
		t.Errorf("client received %q, want plugin bytes %q", raw, respRaw)
	}
	mod := waitFlow(h.store, "receive", "modified", nil)
	if mod == nil || string(mod.RawBytes) != respRaw {
		t.Errorf("modified receive variant must equal the wire bytes; flows:%s", describeFlows(h.store))
	}
}

// oddChunkedReq has wire details a normalizing path would destroy:
// lowercase host, duplicate headers differing only by case, a chunk
// extension.
const oddChunkedReq = "POST /g HTTP/1.1\r\nhost: example.test\r\nx-A: 1\r\nX-a: 2\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n0\r\n\r\n"

// TestPluginRawWins_HTTP1_NoOpPluginKeepsWire covers Test Plan #5 (reverse
// guard): a plugin that only reads msg["raw"] leaves the wire
// byte-identical.
func TestPluginRawWins_HTTP1_NoOpPluginKeepsWire(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	up := startRawCaptureUpstream(t, true, nil)
	_, fwd := startRawWinsForward(t, ctx, `
def on_req(msg, ctx):
    _ = msg["raw"]
    return None
register_hook("http", "on_request", on_req)
`, up.Addr(), "http", nil)

	c, br := dialForward(t, fwd)
	if _, err := c.Write([]byte(oddChunkedReq)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := readOneResponse(br); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if got := up.waitBytes(1, len(oddChunkedReq)); string(got) != oddChunkedReq {
		t.Errorf("upstream received %q, want client bytes %q", got, oddChunkedReq)
	}
}

// TestPluginRawWins_HTTP1_MessageOnlyKeepsOpaquePath covers Test Plan #6
// (reverse guard): a header-only plugin mutation still patches the
// original wire (framing, casing, chunk extension preserved).
func TestPluginRawWins_HTTP1_MessageOnlyKeepsOpaquePath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	up := startRawCaptureUpstream(t, true, nil)
	_, fwd := startRawWinsForward(t, ctx, `
def on_req(msg, ctx):
    msg["headers"].append("X-Added", "1")
register_hook("http", "on_request", on_req)
`, up.Addr(), "http", nil)

	c, br := dialForward(t, fwd)
	if _, err := c.Write([]byte(oddChunkedReq)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := readOneResponse(br); err != nil {
		t.Fatalf("read response: %v", err)
	}
	got := string(up.waitBytes(1, len(oddChunkedReq)+len("X-Added: 1\r\n")))
	for _, want := range []string{"POST /g HTTP/1.1\r\n", "host: example.test\r\nx-A: 1\r\nX-a: 2\r\n", "X-Added: 1\r\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("upstream bytes %q missing %q", got, want)
		}
	}
	if !strings.HasSuffix(got, "\r\n\r\n5;ext=1\r\nhello\r\n0\r\n\r\n") {
		t.Errorf("upstream bytes %q lost the original chunk framing", got)
	}
}

// pipelinedSmuggle carries two requests; the proxy forwards one client
// request, so the second response is left over on the upstream conn.
const pipelinedSmuggle = "GET /first HTTP/1.1\r\nHost: x\r\n\r\nGET /second HTTP/1.1\r\nHost: x\r\n\r\n"

const smuggleScript = `
def on_req(msg, ctx):
    if msg["path"] == "/smuggle":
        msg["raw"] = b"GET /first HTTP/1.1\r\nHost: x\r\n\r\nGET /second HTTP/1.1\r\nHost: x\r\n\r\n"
register_hook("http", "on_request", on_req)
`

// TestPluginRawWins_HTTP1_SmuggleRetiresUpstream_MITM covers Test Plan #7
// on the CONNECT MITM path: both smuggled requests reach the upstream,
// the client gets the first response, and the next client request on
// the same connection is answered on a fresh upstream connection — never
// with the leftover response to the smuggled second request.
func TestPluginRawWins_HTTP1_SmuggleRetiresUpstream_MITM(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	up := startRawCaptureUpstream(t, true, &tls.Config{
		Certificates: []tls.Certificate{rawWinsSelfSignedCert(t)},
		NextProtos:   []string{"http/1.1"},
	})
	_, proxyAddr := startRawWinsMITM(t, ctx, smuggleScript)

	raw, err := connectTunnelDialerForPoolTest(proxyAddr, up.Addr())
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}) //nolint:gosec // test
	t.Cleanup(func() { _ = tc.Close() })
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	br := bufio.NewReader(tc)

	if _, err := tc.Write([]byte("GET /smuggle HTTP/1.1\r\nHost: " + up.Addr() + "\r\n\r\n")); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	_, body1, err := readOneResponse(br)
	if err != nil {
		t.Fatalf("read response 1: %v", err)
	}
	if got := up.waitBytes(1, len(pipelinedSmuggle)); string(got) != pipelinedSmuggle {
		t.Fatalf("upstream conn 1 received %q, want both smuggled requests %q", got, pipelinedSmuggle)
	}
	if body1 != "path=/first conn=1" {
		t.Errorf("response 1 body = %q, want %q", body1, "path=/first conn=1")
	}

	if _, err := tc.Write([]byte("GET /next HTTP/1.1\r\nHost: " + up.Addr() + "\r\n\r\n")); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	_, body2, err := readOneResponse(br)
	if err != nil {
		t.Fatalf("read response 2: %v", err)
	}
	if body2 != "path=/next conn=2" {
		t.Errorf("response 2 body = %q, want %q (a fresh upstream conn, not the leftover smuggled response)", body2, "path=/next conn=2")
	}
	if got := up.ConnCount(); got != 2 {
		t.Errorf("upstream connections = %d, want 2", got)
	}
}

// openPlaintextProxyConn opens a client connection that speaks plain
// HTTP/1.1 through the proxy at proxyAddr to the plain upstream upAddr,
// either as a forward proxy (absolute-form) or through a CONNECT tunnel,
// and returns the conn plus the request-target prefix to use.
func openPlaintextProxyConn(t *testing.T, mode, proxyAddr, upAddr string) (net.Conn, *bufio.Reader, string) {
	t.Helper()
	var c net.Conn
	var prefix string
	var err error
	switch mode {
	case "forward":
		c, err = net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		prefix = "http://" + upAddr
	case "connect":
		c, err = connectTunnelDialerForPoolTest(proxyAddr, upAddr)
		if err != nil {
			t.Fatalf("CONNECT: %v", err)
		}
	default:
		t.Fatalf("unknown mode %q", mode)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return c, bufio.NewReader(c), prefix
}

// TestPluginRawWins_HTTP1_SmuggleRetiresUpstream_Plaintext covers Test
// Plan #7 on the plaintext h1-chain paths (plain-HTTP forward proxy with
// absolute-form, and plain HTTP inside a CONNECT tunnel): the retired
// upstream is replaced by a fresh plain-TCP connection, so the next
// client request is answered on upstream conn 2.
func TestPluginRawWins_HTTP1_SmuggleRetiresUpstream_Plaintext(t *testing.T) {
	for _, mode := range []string{"forward", "connect"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			up := startRawCaptureUpstream(t, true, nil)
			_, proxyAddr := startRawWinsMITM(t, ctx, smuggleScript)
			c, br, prefix := openPlaintextProxyConn(t, mode, proxyAddr, up.Addr())

			if _, err := c.Write([]byte("GET " + prefix + "/smuggle HTTP/1.1\r\nHost: " + up.Addr() + "\r\n\r\n")); err != nil {
				t.Fatalf("write 1: %v", err)
			}
			_, body1, err := readOneResponse(br)
			if err != nil {
				t.Fatalf("read response 1: %v", err)
			}
			if got := up.waitBytes(1, len(pipelinedSmuggle)); string(got) != pipelinedSmuggle {
				t.Fatalf("upstream conn 1 received %q, want both smuggled requests %q", got, pipelinedSmuggle)
			}
			if body1 != "path=/first conn=1" {
				t.Errorf("response 1 body = %q, want %q", body1, "path=/first conn=1")
			}

			if _, err := c.Write([]byte("GET " + prefix + "/next HTTP/1.1\r\nHost: " + up.Addr() + "\r\n\r\n")); err != nil {
				t.Fatalf("write 2: %v", err)
			}
			_, body2, err := readOneResponse(br)
			if err != nil {
				t.Fatalf("read response 2: %v", err)
			}
			if !strings.HasSuffix(body2, "/next conn=2") {
				t.Errorf("response 2 body = %q, want the /next response on a fresh upstream conn 2", body2)
			}
			if got := up.ConnCount(); got != 2 {
				t.Errorf("upstream connections = %d, want 2", got)
			}
		})
	}
}

// TestPluginRawWins_HTTP1_RedialFailureClosesClient: when the upstream
// that replaces a retired one cannot be dialed, the client connection is
// ended promptly instead of being left waiting for a response that will
// never come.
func TestPluginRawWins_HTTP1_RedialFailureClosesClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	up := startRawCaptureUpstream(t, true, nil)
	_, proxyAddr := startRawWinsMITM(t, ctx, smuggleScript)
	c, br, prefix := openPlaintextProxyConn(t, "forward", proxyAddr, up.Addr())

	if _, err := c.Write([]byte("GET " + prefix + "/smuggle HTTP/1.1\r\nHost: " + up.Addr() + "\r\n\r\n")); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	if _, _, err := readOneResponse(br); err != nil {
		t.Fatalf("read response 1: %v", err)
	}
	// No further upstream connection can be accepted, so the redial for
	// the retired upstream fails.
	_ = up.ln.Close()

	if _, err := c.Write([]byte("GET " + prefix + "/next HTTP/1.1\r\nHost: " + up.Addr() + "\r\n\r\n")); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	assertClientClosedPromptly(t, c, br)
}

// assertClientClosedPromptly fails unless the proxy ends the client
// connection (EOF or reset) with no further data, well before the
// client's own timeout.
func assertClientClosedPromptly(t *testing.T, c net.Conn, br *bufio.Reader) {
	t.Helper()
	const limit = 3 * time.Second
	start := time.Now()
	_ = c.SetReadDeadline(start.Add(limit))
	b, err := br.ReadByte()
	if err == nil {
		rest, _ := br.Peek(br.Buffered())
		t.Fatalf("client received data %q, want the connection closed", append([]byte{b}, rest...))
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("client connection still open after %v; want a prompt close", limit)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("client connection closed after %v; want well under %v", el, limit)
	}
}

// TestPluginRawWins_HTTP1_SmuggleRetiresUpstream_TCPForward covers Test
// Plan #7 on the TCP forward path, which owns a single upstream conn and
// no redial chain: the proxy ends the client connection after the
// raw-authoritative exchange, so the leftover smuggled response is never
// handed to a next request, and it keeps serving new connections.
func TestPluginRawWins_HTTP1_SmuggleRetiresUpstream_TCPForward(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	up := startRawCaptureUpstream(t, true, nil)
	_, fwd := startRawWinsForward(t, ctx, smuggleScript, up.Addr(), "http", nil)

	c, br := dialForward(t, fwd)
	if _, err := c.Write([]byte("GET /smuggle HTTP/1.1\r\nHost: example.test\r\n\r\n")); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	_, body1, err := readOneResponse(br)
	if err != nil {
		t.Fatalf("read response 1: %v", err)
	}
	if got := up.waitBytes(1, len(pipelinedSmuggle)); string(got) != pipelinedSmuggle {
		t.Fatalf("upstream received %q, want both smuggled requests %q", got, pipelinedSmuggle)
	}
	if body1 != "path=/first conn=1" {
		t.Errorf("response 1 body = %q, want %q", body1, "path=/first conn=1")
	}

	// Second request on the same client conn: the proxy has no upstream
	// to answer it on, so the client conn is closed promptly with no
	// further bytes — never the leftover response to the smuggled
	// /second request, and never a hang until the client's own timeout.
	// The write may already fail if the proxy closed first; either way
	// the read below must observe the close.
	_, _ = c.Write([]byte("GET /next HTTP/1.1\r\nHost: example.test\r\n\r\n"))
	assertClientClosedPromptly(t, c, br)
	if got := up.ConnCount(); got != 1 {
		t.Errorf("upstream connections = %d, want 1", got)
	}

	// The proxy is still alive for new client connections.
	c2, br2 := dialForward(t, fwd)
	if _, err := c2.Write([]byte("GET /again HTTP/1.1\r\nHost: example.test\r\n\r\n")); err != nil {
		t.Fatalf("write 3: %v", err)
	}
	if _, body3, err := readOneResponse(br2); err != nil || !strings.HasPrefix(body3, "path=/again ") {
		t.Errorf("new connection response = %q, %v; want path=/again", body3, err)
	}
}

// TestPluginRawWins_HTTP1_TransformPrecedence covers Test Plan #8
// (decision U1, last writer in Pipeline order wins): a pre_pipeline raw
// write is superseded by a Transform rule that fires; a post_pipeline raw
// write supersedes it.
func TestPluginRawWins_HTTP1_TransformPrecedence(t *testing.T) {
	cases := []struct {
		name      string
		phaseArg  string
		wantRaw   bool
		wantParts []string
	}{
		{name: "pre_pipeline raw then Transform", phaseArg: "", wantRaw: false,
			wantParts: []string{"GET /orig HTTP/1.1\r\n", "Host: example.test\r\n", "X-T: 1\r\n"}},
		{name: "Transform then post_pipeline raw", phaseArg: `, phase="post_pipeline"`, wantRaw: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			te := httprules.NewTransformEngine()
			te.AddRule(httprules.TransformRule{
				ID: "usk-1079-add", Enabled: true, Direction: httprules.DirectionRequest,
				ActionType: httprules.TransformAddHeader, HeaderName: "X-T", HeaderValue: "1",
			})
			script := `
def on_req(msg, ctx):
    msg["raw"] = b"POST /p HTTP/1.1\r\nHost: x\r\nX-Odd:  v\r\nContent-Length: 2\r\n\r\nhi"
register_hook("http", "on_request", on_req` + tc.phaseArg + `)
`
			up := startRawCaptureUpstream(t, true, nil)
			_, fwd := startRawWinsForward(t, ctx, script, up.Addr(), "http", te)

			c, br := dialForward(t, fwd)
			if _, err := c.Write([]byte("GET /orig HTTP/1.1\r\nHost: example.test\r\n\r\n")); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, _, err := readOneResponse(br); err != nil {
				t.Fatalf("read response: %v", err)
			}
			got := string(up.waitBytes(1, 30))
			if tc.wantRaw {
				if got != smuggleRaw {
					t.Errorf("upstream received %q, want plugin bytes %q", got, smuggleRaw)
				}
				return
			}
			if got == smuggleRaw {
				t.Fatalf("upstream received the pre_pipeline plugin bytes; the later Transform must win")
			}
			for _, p := range tc.wantParts {
				if !strings.Contains(got, p) {
					t.Errorf("upstream bytes %q missing %q", got, p)
				}
			}
		})
	}
}

// TestPluginRawWins_RawTCP covers Test Plan #12 (decision U2): a
// (raw, on_chunk) plugin msg["raw"] write reaches the upstream verbatim;
// an untouched chunk passes through as-is.
func TestPluginRawWins_RawTCP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	up := startRawCaptureUpstream(t, false, nil)
	h, fwd := startRawWinsForward(t, ctx, `
def on_chunk(msg, ctx):
    if msg["bytes"] == b"ping":
        msg["raw"] = b"PLUGIN-RAW"
register_hook("raw", "on_chunk", on_chunk)
`, up.Addr(), "raw", nil)

	c, _ := dialForward(t, fwd)
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatalf("write 1: %v", err)
	}
	// Let the first chunk land on its own before sending the second.
	up.waitBytes(1, len("PLUGIN-RAW"))
	if _, err := c.Write([]byte("keep")); err != nil {
		t.Fatalf("write 2: %v", err)
	}
	const want = "PLUGIN-RAWkeep"
	if got := up.waitBytes(1, len(want)); string(got) != want {
		t.Errorf("upstream received %q, want %q", got, want)
	}
	mod := waitFlow(h.store, "send", "modified", nil)
	if mod == nil || string(mod.RawBytes) != "PLUGIN-RAW" {
		t.Errorf("modified send variant must equal the wire bytes %q; flows:%s", "PLUGIN-RAW", describeFlows(h.store))
	}
}

// rawWinsSelfSignedCert produces a throwaway ECDSA cert for the TLS
// upstream of the MITM test.
func rawWinsSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ECDSA generate: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1079),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}
