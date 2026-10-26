//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	h2pool "github.com/usk6666/yorishiro-proxy/internal/layer/http2/pool"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// USK-1188: client_idle_timeout_ms bounds how long a client-facing HTTP/2
// connection may sit with no open stream; when it elapses the proxy sends
// GOAWAY(NO_ERROR, last processed stream) and closes. These tests drive the
// real Manager → BuildLiveStack path for each production site that builds a
// client-facing h2 Layer.

const usk1188Idle = 300 * time.Millisecond

// newUSK1188Manager returns a Manager wired with an HTTP2Pool (so the pool-
// hit fast path is reachable) and BuildConfig shared with the Manager (so
// SetClientIdleTimeout reaches the stack builder).
func newUSK1188Manager(t *testing.T, store *flowStoreCapture) *proxybuild.Manager {
	t.Helper()
	logger := testutil.DiscardLogger()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	pool := h2pool.New(h2pool.PoolOptions{})
	t.Cleanup(func() { _ = pool.Close() })
	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
		HTTP2Pool:          pool,
	}
	factory := func(ctx context.Context, name, addr string) (*proxybuild.Stack, error) {
		return proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
			Logger:       logger,
			ListenerName: name,
			ListenAddr:   addr,
			FlowStore:    store,
			BuildConfig:  buildCfg,
		})
	}
	mgr, err := proxybuild.NewManager(proxybuild.ManagerConfig{
		Logger:       logger,
		StackFactory: factory,
		BuildConfig:  buildCfg,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.StopAll(context.Background()) })
	return mgr
}

// startUSK1188Proxy starts the main listener after mutate ran.
func startUSK1188Proxy(t *testing.T, ctx context.Context, store *flowStoreCapture, mutate func(*proxybuild.Manager)) (*proxybuild.Manager, string) {
	t.Helper()
	mgr := newUSK1188Manager(t, store)
	if mutate != nil {
		mutate(mgr)
	}
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	running, addr := mgr.Status()
	if !running || addr == "" {
		t.Fatal("no listener address")
	}
	return mgr, addr
}

func usk1188SetIdle(m *proxybuild.Manager) { m.SetClientIdleTimeout(usk1188Idle) }

// idleH2Client speaks HTTP/2 frames directly so the test sees GOAWAY and EOF
// exactly as they reach the client.
type idleH2Client struct {
	t      *testing.T
	conn   net.Conn // the h2 transport (TLS or plain)
	raw    net.Conn // the TCP conn, for deadlines
	fr     *http2.Framer
	encBuf bytes.Buffer
	enc    *hpack.Encoder
	scheme string
}

func newIdleH2Client(t *testing.T, conn, raw net.Conn, scheme string) *idleH2Client {
	t.Helper()
	c := &idleH2Client{t: t, conn: conn, raw: raw, scheme: scheme}
	c.fr = http2.NewFramer(conn, conn)
	c.enc = hpack.NewEncoder(&c.encBuf)
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	if err := c.fr.WriteSettings(); err != nil {
		t.Fatalf("write SETTINGS: %v", err)
	}
	return c
}

// get sends a bodyless GET on sid and reads until its response ends.
func (c *idleH2Client) get(sid uint32, authority, path string) {
	c.t.Helper()
	c.encBuf.Reset()
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: c.scheme},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: path},
	} {
		_ = c.enc.WriteField(f)
	}
	if err := c.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: sid, BlockFragment: c.encBuf.Bytes(), EndStream: true, EndHeaders: true,
	}); err != nil {
		c.t.Fatalf("write HEADERS(%d): %v", sid, err)
	}
	_ = c.raw.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer func() { _ = c.raw.SetReadDeadline(time.Time{}) }()
	for {
		f, err := c.fr.ReadFrame()
		if err != nil {
			c.t.Fatalf("read response for stream %d: %v", sid, err)
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = c.fr.WriteSettingsAck()
			}
		case *http2.GoAwayFrame:
			c.t.Fatalf("GOAWAY(%v) before stream %d completed", f.ErrCode, sid)
		case *http2.RSTStreamFrame:
			if f.StreamID == sid {
				c.t.Fatalf("RST_STREAM(%v) on stream %d", f.ErrCode, sid)
			}
		case *http2.HeadersFrame:
			if f.StreamID == sid && f.StreamEnded() {
				return
			}
		case *http2.DataFrame:
			if f.StreamID == sid && f.StreamEnded() {
				return
			}
		}
	}
}

// awaitIdleGoAway reads until GOAWAY, checks it is NO_ERROR with wantLast,
// then reads until EOF. Returns the time from the call to the GOAWAY.
func (c *idleH2Client) awaitIdleGoAway(wantLast uint32) time.Duration {
	c.t.Helper()
	start := time.Now()
	_ = c.raw.SetReadDeadline(start.Add(5 * time.Second))
	var el time.Duration
	for {
		f, err := c.fr.ReadFrame()
		if err != nil {
			c.t.Fatalf("no GOAWAY from the proxy: %v", err)
		}
		if ga, ok := f.(*http2.GoAwayFrame); ok {
			el = time.Since(start)
			if ga.ErrCode != http2.ErrCodeNo || ga.LastStreamID != wantLast {
				c.t.Fatalf("GOAWAY(%v, last=%d), want GOAWAY(NO_ERROR, last=%d)", ga.ErrCode, ga.LastStreamID, wantLast)
			}
			break
		}
	}
	for {
		f, err := c.fr.ReadFrame()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				c.t.Fatal("proxy did not close the connection after the idle GOAWAY")
			}
			return el
		}
		if ga, ok := f.(*http2.GoAwayFrame); ok {
			c.t.Errorf("second GOAWAY(%v) after the idle GOAWAY", ga.ErrCode)
		}
	}
}

// expectStaysOpen reads for d and fails on GOAWAY or EOF.
func (c *idleH2Client) expectStaysOpen(d time.Duration) {
	c.t.Helper()
	_ = c.raw.SetReadDeadline(time.Now().Add(d))
	defer func() { _ = c.raw.SetReadDeadline(time.Time{}) }()
	for {
		f, err := c.fr.ReadFrame()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return
			}
			c.t.Fatalf("connection closed while idle with the bound disabled: %v", err)
		}
		if ga, ok := f.(*http2.GoAwayFrame); ok {
			c.t.Fatalf("GOAWAY(%v) with the bound disabled", ga.ErrCode)
		}
	}
}

// usk1188Connect opens a CONNECT tunnel to target through proxyAddr.
func usk1188Connect(t *testing.T, proxyAddr, target string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := io.WriteString(conn, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := gohttp.ReadResponse(br, &gohttp.Request{Method: gohttp.MethodConnect})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT response = %v, err = %v", resp, err)
	}
	if br.Buffered() != 0 {
		t.Fatalf("%d unexpected bytes after the CONNECT response", br.Buffered())
	}
	_ = conn.SetReadDeadline(time.Time{})
	return conn
}

// usk1188MITMClient opens CONNECT + TLS (ALPN h2) to target.
func usk1188MITMClient(t *testing.T, proxyAddr, target string) *idleH2Client {
	t.Helper()
	conn := usk1188Connect(t, proxyAddr, target)
	tc := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test against the MITM CA
		ServerName:         "127.0.0.1",
		NextProtos:         []string{"h2"},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	if got := tc.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("negotiated ALPN = %q, want h2", got)
	}
	return newIdleH2Client(t, tc, conn, "https")
}

// usk1188AwaitComplete waits until n streams are recorded complete and
// fails if any stream update recorded state "error".
func usk1188AwaitComplete(t *testing.T, store *flowStoreCapture, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		complete := 0
		for _, st := range store.Streams() {
			for _, u := range store.StreamUpdates(st.ID) {
				if u.State == "error" {
					t.Fatalf("stream %s (%s) recorded state error: %q", st.ID, st.Protocol, u.FailureReason)
				}
				if u.State == "complete" {
					complete++
					break
				}
			}
		}
		if complete >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d streams recorded complete; streams=%s", complete, n, summarizeStreamProtocols(store.Streams()))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func usk1188AssertNotEarly(t *testing.T, el time.Duration) {
	t.Helper()
	if el < usk1188Idle*2/3 {
		t.Errorf("idle GOAWAY after %v, want ~%v", el, usk1188Idle)
	}
}

// Test Plan #10: CONNECT + TLS MITM h2 (fresh dial, then the pool-hit fast
// path on a second CONNECT): each idle client connection gets
// GOAWAY(NO_ERROR, last=1) and is closed; the recorded streams stay
// complete; the upstream connection is reused.
func TestProxybuild_CONNECT_MITM_H2_ClientIdleTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	upAddr, accepts, upStop := startH2TLSUpstreamForPoolTest(t, "usk1188", gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		fmt.Fprintf(w, "h2 path=%s", r.URL.Path)
	}))
	defer upStop()
	store := &flowStoreCapture{}
	_, proxyAddr := startUSK1188Proxy(t, ctx, store, usk1188SetIdle)

	for i, path := range []string{"/fresh", "/pooled"} {
		c := usk1188MITMClient(t, proxyAddr, upAddr)
		c.get(1, upAddr, path)
		usk1188AssertNotEarly(t, c.awaitIdleGoAway(1))
		usk1188AwaitComplete(t, store, i+1)
		// Let the upstream Layer return to the pool before the next CONNECT.
		time.Sleep(200 * time.Millisecond)
	}
	if a := accepts(); a != 1 {
		t.Errorf("upstream accepts = %d, want 1 (second CONNECT did not take the pool-hit path)", a)
	}
}

// h2c site helpers ---------------------------------------------------------

// startUSK1188H2CForward adds a tcp_forwards entry (protocol http2) to mgr.
func startUSK1188H2CForward(t *testing.T, ctx context.Context, mgr *proxybuild.Manager, upAddr string) string {
	t.Helper()
	if err := mgr.StartTCPForwards(ctx, proxybuild.TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			"0": {Target: upAddr, Protocol: "http2"},
		},
	}); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}
	addr := mgr.TCPForwardAddrs()["0"]
	if addr == "" {
		t.Fatal("TCPForwardAddrs missing port 0")
	}
	return addr
}

// usk1188H2CClient returns a raw h2c client for one of the two cleartext
// sites: the tcp_forwards listener, or a CONNECT tunnel whose first inner
// bytes are the h2c preface.
func usk1188H2CClient(t *testing.T, site, proxyAddr, fwdAddr, upAddr string) *idleH2Client {
	t.Helper()
	switch site {
	case "tcp_forwards":
		conn, err := net.DialTimeout("tcp", fwdAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial forward: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return newIdleH2Client(t, conn, conn, "http")
	default:
		conn := usk1188Connect(t, proxyAddr, upAddr)
		return newIdleH2Client(t, conn, conn, "http")
	}
}

// Test Plan #11: the cleartext h2c sites (tcp_forwards protocol http2, and
// CONNECT with an h2c preface inside) close idle client connections with
// GOAWAY(NO_ERROR); with the bound disabled the connection stays open.
func TestProxybuild_H2C_ClientIdleTimeout(t *testing.T) {
	for _, site := range []string{"tcp_forwards", "CONNECT h2c"} {
		t.Run(site, func(t *testing.T) {
			for _, disabled := range []bool{false, true} {
				name := "enabled"
				if disabled {
					name = "disabled"
				}
				t.Run(name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					upAddr, upStop := h2cEchoUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
						fmt.Fprintf(w, "h2c path=%s", r.URL.Path)
					}))
					defer upStop()
					store := &flowStoreCapture{}
					mgr, proxyAddr := startUSK1188Proxy(t, ctx, store, func(m *proxybuild.Manager) {
						m.SetClientIdleTimeout(usk1188Idle)
						if disabled {
							m.DisableClientIdleTimeout()
						}
					})
					fwdAddr := startUSK1188H2CForward(t, ctx, mgr, upAddr)

					c := usk1188H2CClient(t, site, proxyAddr, fwdAddr, upAddr)
					c.get(1, upAddr, "/one")
					if disabled {
						c.expectStaysOpen(3 * usk1188Idle)
						c.get(3, upAddr, "/two")
						usk1188AwaitComplete(t, store, 2)
						return
					}
					usk1188AssertNotEarly(t, c.awaitIdleGoAway(1))
					usk1188AwaitComplete(t, store, 1)
				})
			}
		})
	}
}

// closeNotifyConn signals closed once a Read on it fails (the proxy closed
// the connection).
type closeNotifyConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *closeNotifyConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err != nil {
		c.once.Do(func() { close(c.closed) })
	}
	return n, err
}

// Test Plan #12: a real HTTP/2 client (x/net http2.Transport) whose idle
// connection is closed by the proxy's GOAWAY retries the next request on a
// new connection.
func TestProxybuild_TCPForward_H2C_ClientIdleTimeout_TransportRetries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	upAddr, upStop := h2cEchoUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		fmt.Fprintf(w, "h2c path=%s", r.URL.Path)
	}))
	defer upStop()
	store := &flowStoreCapture{}
	mgr, _ := startUSK1188Proxy(t, ctx, store, usk1188SetIdle)
	fwdAddr := startUSK1188H2CForward(t, ctx, mgr, upAddr)

	var dials atomic.Int32
	conns := make(chan *closeNotifyConn, 4)
	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			c, err := d.DialContext(ctx, network, fwdAddr)
			if err != nil {
				return nil, err
			}
			dials.Add(1)
			cn := &closeNotifyConn{Conn: c, closed: make(chan struct{})}
			conns <- cn
			return cn, nil
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	cli := &gohttp.Client{Transport: tr, Timeout: 10 * time.Second}

	do := func(path string) {
		t.Helper()
		req, err := gohttp.NewRequestWithContext(ctx, "GET", "http://"+fwdAddr+path, nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		resp, err := cli.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || string(body) != "h2c path="+path {
			t.Fatalf("GET %s = %d %q", path, resp.StatusCode, body)
		}
	}

	do("/first")
	first := <-conns
	select {
	case <-first.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not close the idle client connection")
	}
	do("/second")
	if n := dials.Load(); n != 2 {
		t.Errorf("dials = %d, want 2 (second request on a new connection)", n)
	}
	for {
		select {
		case c := <-conns:
			_ = c.Close()
			continue
		default:
		}
		break
	}
	_ = first.Close()
}
