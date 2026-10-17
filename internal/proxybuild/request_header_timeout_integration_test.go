//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"strings"
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

// USK-1162: request_timeout_ms bounds the client-side HTTP/1.x request head
// (request line + headers) on every request of a keep-alive connection,
// while leaving browser-normal behavior (idle keep-alive gaps, large
// headers, pipelining, slow bodies, upgraded connections) untouched.

const usk1162T = 300 * time.Millisecond

// newUSK1162Manager mirrors the mcpserver/init.go wiring: the Manager is
// bound to the shared BuildConfig and request_timeout_ms reaches it via
// Manager.SetRequestTimeout.
func newUSK1162Manager(t *testing.T, store flow.Writer, requestTimeout time.Duration) *proxybuild.Manager {
	t.Helper()
	logger := testutil.DiscardLogger()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
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
	mgr.SetRequestTimeout(requestTimeout)
	t.Cleanup(func() { _ = mgr.StopAll(context.Background()) })
	return mgr
}

// startUSK1162Proxy starts a plain-forward listener and returns its address.
func startUSK1162Proxy(t *testing.T, ctx context.Context, store flow.Writer) string {
	t.Helper()
	mgr := newUSK1162Manager(t, store, usk1162T)
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	running, addr := mgr.Status()
	if !running || addr == "" {
		t.Fatal("no listener address")
	}
	return addr
}

func startUSK1162Upstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "path=%s body=%s", r.URL.Path, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func usk1162Trickle(w net.Conn, b []byte, gap time.Duration, done <-chan struct{}) {
	for i := range b {
		select {
		case <-done:
			return
		case <-time.After(gap):
		}
		if _, err := w.Write(b[i : i+1]); err != nil {
			return
		}
	}
}

// usk1162AwaitClose reads conn until the proxy closes it, failing if it is
// still open after guard.
func usk1162AwaitClose(t *testing.T, r io.Reader, conn net.Conn, guard time.Duration) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(guard))
	var got strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		got.Write(buf[:n])
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatalf("connection still open after %v (read so far: %.120q)", guard, got.String())
			}
			return got.String()
		}
	}
}

// usk1162RoundTrip writes raw and reads one response off br.
func usk1162RoundTrip(t *testing.T, conn net.Conn, br *bufio.Reader, raw string) (int, string) {
	t.Helper()
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	return usk1162ReadResponse(t, conn, br)
}

func usk1162ReadResponse(t *testing.T, conn net.Conn, br *bufio.Reader) (int, string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	resp, err := gohttp.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return resp.StatusCode, string(body)
}

func usk1162Dial(t *testing.T, addr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn, bufio.NewReader(conn)
}

func usk1162Get(upstreamHost, path string) string {
	return "GET http://" + upstreamHost + path + " HTTP/1.1\r\nHost: " + upstreamHost + "\r\n\r\n"
}

// Test Plan #5: a keep-alive request trickled after a completed exchange
// is cut off by the header bound.
func TestProxybuild_PlainHTTP_KeepAliveSlowlorisSecondRequestClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	upstream := startUSK1162Upstream(t)
	host := strings.TrimPrefix(upstream.URL, "http://")
	store := &flowStoreCapture{}
	proxyAddr := startUSK1162Proxy(t, ctx, store)

	conn, br := usk1162Dial(t, proxyAddr)
	if code, body := usk1162RoundTrip(t, conn, br, usk1162Get(host, "/one")); code != 200 || body != "path=/one body=" {
		t.Fatalf("request 1 = %d %q", code, body)
	}
	// Settle request 1's recording first, so the post-timeout check below
	// cannot pass vacuously because recording had not happened yet.
	firstID := usk1162AwaitSingleComplete(t, store, 5*time.Second)

	done := make(chan struct{})
	defer close(done)
	slow := "GET http://" + host + "/two HTTP/1.1\r\nHost: " + host + "\r\nX-Pad: " + strings.Repeat("p", 200) + "\r\n\r\n"
	go usk1162Trickle(conn, []byte(slow), 50*time.Millisecond, done)

	if got := usk1162AwaitClose(t, br, conn, 3*time.Second); got != "" {
		t.Errorf("proxy replied to a trickled request: %.120q", got)
	}

	// Settled design: a request-head timeout records nothing. Watch the
	// store for a bounded window after the close: no second stream may
	// appear, and request 1's stream must not be re-finalised as error.
	watch := time.Now().Add(1 * time.Second)
	for {
		streams := store.Streams()
		if len(streams) != 1 {
			t.Fatalf("request-head timeout was recorded: want 1 stream (request 1), got %d: %s",
				len(streams), summarizeStreamProtocols(streams))
		}
		for _, u := range store.StreamUpdates(firstID) {
			if u.State != "complete" {
				t.Fatalf("request 1 stream re-finalised as %q after the request-head timeout (reason %q)",
					u.State, u.FailureReason)
			}
		}
		if time.Now().After(watch) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// usk1162AwaitSingleComplete waits until store holds exactly one stream
// whose updates include state "complete", and returns its ID.
func usk1162AwaitSingleComplete(t *testing.T, store *flowStoreCapture, guard time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(guard)
	for time.Now().Before(deadline) {
		if streams := store.Streams(); len(streams) == 1 {
			for _, u := range store.StreamUpdates(streams[0].ID) {
				if u.State == "complete" {
					return streams[0].ID
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("request 1 was not recorded as one complete stream within %v; streams=%s",
		guard, summarizeStreamProtocols(store.Streams()))
	return ""
}

// Test Plan #6(i): keep-alive requests spaced further apart than the header
// bound (but well under the 120s idle bound) all succeed.
func TestProxybuild_PlainHTTP_KeepAliveIdleGapsBeyondHeaderBoundSucceed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	upstream := startUSK1162Upstream(t)
	host := strings.TrimPrefix(upstream.URL, "http://")
	proxyAddr := startUSK1162Proxy(t, ctx, &flowStoreCapture{})

	conn, br := usk1162Dial(t, proxyAddr)
	for i, path := range []string{"/one", "/two", "/three"} {
		if i > 0 {
			time.Sleep(3 * usk1162T)
		}
		code, body := usk1162RoundTrip(t, conn, br, usk1162Get(host, path))
		if code != 200 || body != "path="+path+" body=" {
			t.Fatalf("request %d = %d %q", i+1, code, body)
		}
	}
}

// Test Plan #6(ii): a large header section (64 KiB Cookie + 9 KiB URL)
// delivered in several chunks within the header bound succeeds.
func TestProxybuild_PlainHTTP_LargeHeadersInChunksSucceed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	upstream := startUSK1162Upstream(t)
	host := strings.TrimPrefix(upstream.URL, "http://")
	proxyAddr := startUSK1162Proxy(t, ctx, &flowStoreCapture{})

	conn, br := usk1162Dial(t, proxyAddr)
	path := "/big?q=" + strings.Repeat("u", 9*1024)
	raw := "GET http://" + host + path + " HTTP/1.1\r\nHost: " + host +
		"\r\nCookie: c=" + strings.Repeat("c", 64*1024) + "\r\n\r\n"
	const chunks = 8
	step := len(raw)/chunks + 1
	for off := 0; off < len(raw); off += step {
		end := off + step
		if end > len(raw) {
			end = len(raw)
		}
		if _, err := conn.Write([]byte(raw[off:end])); err != nil {
			t.Fatalf("write chunk: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	code, body := usk1162ReadResponse(t, conn, br)
	if code != 200 || !strings.HasPrefix(body, "path=/big body=") {
		t.Fatalf("large-header request = %d %.80q", code, body)
	}
}

// Test Plan #6(iii): two pipelined requests in one write are both answered.
func TestProxybuild_PlainHTTP_PipelinedRequestsAnswered(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	upstream := startUSK1162Upstream(t)
	host := strings.TrimPrefix(upstream.URL, "http://")
	proxyAddr := startUSK1162Proxy(t, ctx, &flowStoreCapture{})

	conn, br := usk1162Dial(t, proxyAddr)
	if _, err := conn.Write([]byte(usk1162Get(host, "/p1") + usk1162Get(host, "/p2"))); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, path := range []string{"/p1", "/p2"} {
		code, body := usk1162ReadResponse(t, conn, br)
		if code != 200 || body != "path="+path+" body=" {
			t.Fatalf("pipelined %s = %d %q", path, code, body)
		}
	}
}

// Test Plan #7: the header bound does not cover the body. An
// Expect: 100-continue client that waits well past the bound before sending
// its body still completes, and the exchange is recorded complete.
func TestProxybuild_PlainHTTP_SlowBodyAfterExpectContinueCompletes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	upstream := startUSK1162Upstream(t)
	host := strings.TrimPrefix(upstream.URL, "http://")
	store := &flowStoreCapture{}
	proxyAddr := startUSK1162Proxy(t, ctx, store)

	conn, br := usk1162Dial(t, proxyAddr)
	head := "POST http://" + host + "/post HTTP/1.1\r\nHost: " + host +
		"\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n"
	if _, err := conn.Write([]byte(head)); err != nil {
		t.Fatalf("write head: %v", err)
	}
	time.Sleep(3 * usk1162T)
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write body: %v", err)
	}
	code, body := usk1162ReadResponse(t, conn, br)
	for code == 100 {
		code, body = usk1162ReadResponse(t, conn, br)
	}
	if code != 200 || body != "path=/post body=hello" {
		t.Fatalf("slow-body request = %d %q", code, body)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, st := range store.Streams() {
			for _, u := range store.StreamUpdates(st.ID) {
				if u.State == "complete" {
					return
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("slow-body exchange was not recorded complete; streams=%s", summarizeStreamProtocols(store.Streams()))
}

// startUSK1162Forward starts a TCP forward listener for protocol and
// returns its address.
func startUSK1162Forward(t *testing.T, ctx context.Context, store flow.Writer, target, protocol string) string {
	t.Helper()
	mgr := newUSK1162Manager(t, store, usk1162T)
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	if err := mgr.StartTCPForwards(ctx, proxybuild.TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			"0": {Target: target, Protocol: protocol},
		},
	}); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}
	fwdAddr := mgr.TCPForwardAddrs()["0"]
	if fwdAddr == "" {
		t.Fatal("TCPForwardAddrs missing port 0")
	}
	return fwdAddr
}

// Test Plan #10: tcp_forwards protocol http — a trickled request line is
// closed within the bound.
func TestProxybuild_TCPForward_HTTP_SlowlorisRequestLineClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	upstream := startUSK1162Upstream(t)
	host := strings.TrimPrefix(upstream.URL, "http://")
	fwdAddr := startUSK1162Forward(t, ctx, &flowStoreCapture{}, host, "http")

	conn, br := usk1162Dial(t, fwdAddr)
	done := make(chan struct{})
	defer close(done)
	slow := "GET /slow HTTP/1.1\r\nHost: " + host + "\r\nX-Pad: " + strings.Repeat("p", 200) + "\r\n\r\n"
	go usk1162Trickle(conn, []byte(slow), 50*time.Millisecond, done)

	if got := usk1162AwaitClose(t, br, conn, 3*time.Second); got != "" {
		t.Errorf("forward replied to a trickled request: %.120q", got)
	}
}

// Test Plan #8: once a connection is upgraded to WebSocket the header bound
// no longer applies — a WS connection idle for several bounds still relays.
func TestProxybuild_TCPForward_WS_IdleAfterUpgradeNotClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	hits := newWSEchoHitsUSK913()
	upstreamAddr, stopUpstream := startWSEchoUpstreamForUSK913(t, hits)
	defer stopUpstream()
	fwdAddr := startUSK1162Forward(t, ctx, &flowStoreCapture{}, upstreamAddr, "websocket")

	conn, br := usk1162Dial(t, fwdAddr)
	if err := writeWSClientHandshakeForUSK913(conn, "example.test"); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	if err := readWS101ForUSK913(br); err != nil {
		t.Fatalf("read 101: %v", err)
	}

	time.Sleep(4 * usk1162T)

	frame := &ws.Frame{Fin: true, Opcode: ws.OpcodeText, Masked: true, MaskKey: [4]byte{1, 2, 3, 4}, Payload: []byte("after-idle")}
	if err := ws.WriteFrame(conn, frame); err != nil {
		t.Fatalf("write frame after idle: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	echo, err := ws.ReadFrame(br)
	if err != nil {
		t.Fatalf("read echo after idle: %v", err)
	}
	if string(echo.Payload) != "after-idle" {
		t.Errorf("echo = %q, want after-idle", echo.Payload)
	}
}
