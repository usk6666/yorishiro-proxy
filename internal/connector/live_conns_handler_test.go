package connector

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// liveConnEcho is a TCP echo upstream that counts the bytes it received.
type liveConnEcho struct {
	ln       net.Listener
	received atomic.Int64
}

func startLiveConnEcho(t *testing.T) *liveConnEcho {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	e := &liveConnEcho{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						e.received.Add(int64(n))
						if _, werr := c.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return e
}

func (e *liveConnEcho) addr() string { return e.ln.Addr().String() }

// serveOneConn accepts one client connection on a fresh loopback listener
// and runs handler on it (wrapped in PeekConn, the way FullListener does).
// It returns the client side and a channel closed when handler returns.
func serveOneConn(t *testing.T, handler HandlerFunc) (net.Conn, <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		ctx := ContextWithConnID(context.Background(), "live-conn-test")
		ctx = ContextWithListenerName(ctx, "test-listener")
		_ = handler(ctx, NewPeekConn(c))
	}()
	client, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, done
}

func connectThrough(t *testing.T, client net.Conn, target string) {
	t.Helper()
	if _, err := io.WriteString(client, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(client)
	line, err := br.ReadString('\n')
	if err != nil || !strings.Contains(line, "200") {
		t.Fatalf("CONNECT response = %q, %v", line, err)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT headers: %v", err)
		}
		if l == "\r\n" {
			break
		}
	}
	if br.Buffered() != 0 {
		t.Fatalf("unexpected bytes after CONNECT response")
	}
	_ = client.SetReadDeadline(time.Time{})
}

func socks5Through(t *testing.T, client net.Conn, target string) {
	t.Helper()
	host, portStr, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portStr)
	ip := net.ParseIP(host).To4()
	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	sel := make([]byte, 2)
	if _, err := io.ReadFull(client, sel); err != nil || sel[1] != 0x00 {
		t.Fatalf("method selection = %x, %v", sel, err)
	}
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := client.Write(req); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(client, rep); err != nil || rep[1] != 0x00 {
		t.Fatalf("SOCKS5 reply = %x, %v", rep, err)
	}
	_ = client.SetReadDeadline(time.Time{})
}

// roundTrip writes msg and reads the echoed bytes back.
func roundTrip(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatalf("write %q: %v", msg, err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != msg {
		t.Fatalf("echo = %q, %v; want %q", buf, err, msg)
	}
	_ = c.SetReadDeadline(time.Time{})
}

// assertClosedWithin asserts the peer closed c within d: a read returns
// EOF / reset rather than timing out.
func assertClosedWithin(t *testing.T, c net.Conn, d time.Duration) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 64)
	for {
		_, err := c.Read(buf)
		if err == nil {
			continue
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("connection still open %v after the policy change", d)
		}
		return
	}
}

func denyHost(scope *TargetScope, host string) {
	scope.ReplacePolicyRules(nil, []TargetRule{{Hostname: host}}, PolicyOrigin{Source: "test"})
}

// T6 + AC1 at the connector seam: a CONNECT TLS-passthrough tunnel is
// tracked while open, closed by Reconcile once the target is denied, no
// byte sent afterwards reaches the upstream, and the entry is gone.
func TestCONNECTHandler_LiveConns_PassthroughCutOnReconcile(t *testing.T) {
	echo := startLiveConnEcho(t)
	scope := NewTargetScope()
	scope.SetPolicyRules(allowOnly("127.0.0.1"), nil)
	reg := NewLiveConns(newTestLogger())
	pl := NewPassthroughList()
	pl.Add("127.0.0.1")

	client, done := serveOneConn(t, NewCONNECTHandler(CONNECTHandlerConfig{
		Negotiator:      NewCONNECTNegotiator(newTestLogger()),
		Scope:           scope,
		LiveConns:       reg,
		PassthroughList: pl,
		Logger:          newTestLogger(),
	}))
	connectThrough(t, client, echo.addr())
	roundTrip(t, client, "before")
	if got := reg.Len(); got != 1 {
		t.Fatalf("registry Len with tunnel open = %d, want 1", got)
	}

	denyHost(scope, "127.0.0.1")
	if n := reg.Reconcile("test"); n != 1 {
		t.Errorf("Reconcile closed %d, want 1", n)
	}
	assertClosedWithin(t, client, 5*time.Second)
	before := echo.received.Load()
	_, _ = io.WriteString(client, "after")
	time.Sleep(100 * time.Millisecond)
	if got := echo.received.Load(); got != before {
		t.Errorf("upstream received %d more bytes after the cut", got-before)
	}
	<-done
	if got := reg.Len(); got != 0 {
		t.Errorf("registry Len after cut = %d, want 0", got)
	}
}

// T6: normal client close unregisters the entry.
func TestCONNECTHandler_LiveConns_UnregisterOnNormalClose(t *testing.T) {
	echo := startLiveConnEcho(t)
	scope := NewTargetScope()
	reg := NewLiveConns(newTestLogger())
	pl := NewPassthroughList()
	pl.Add("127.0.0.1")

	client, done := serveOneConn(t, NewCONNECTHandler(CONNECTHandlerConfig{
		Negotiator:      NewCONNECTNegotiator(newTestLogger()),
		Scope:           scope,
		LiveConns:       reg,
		PassthroughList: pl,
		Logger:          newTestLogger(),
	}))
	connectThrough(t, client, echo.addr())
	roundTrip(t, client, "hello")
	if got := reg.Len(); got != 1 {
		t.Fatalf("registry Len with tunnel open = %d, want 1", got)
	}
	_ = client.Close()
	<-done
	if got := reg.Len(); got != 0 {
		t.Errorf("registry Len after normal close = %d, want 0", got)
	}
}

// T6: a gate denial never registers anything.
func TestCONNECTHandler_LiveConns_DeniedNeverRegistered(t *testing.T) {
	scope := NewTargetScope()
	denyHost(scope, "127.0.0.1")
	reg := NewLiveConns(newTestLogger())
	client, done := serveOneConn(t, NewCONNECTHandler(CONNECTHandlerConfig{
		Negotiator: NewCONNECTNegotiator(newTestLogger()),
		Scope:      scope,
		LiveConns:  reg,
		Logger:     newTestLogger(),
	}))
	if _, err := io.WriteString(client, "CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("read CONNECT reply until EOF: %v (got %q)", err, got)
	}
	// USK-1246: a denied CONNECT is refused with 403, never 200.
	if want := string(forwardErrorResponse(403, "Forbidden", "yorishiro-proxy: target blocked by scope")); string(got) != want {
		t.Errorf("CONNECT reply = %q, want %q", got, want)
	}
	<-done
	if got := reg.Len(); got != 0 {
		t.Errorf("registry Len after denied CONNECT = %d, want 0", got)
	}
}

// AC2: a SOCKS5 passthrough tunnel is cut the same way, keyed on the
// SOCKS5 admission check (blank scheme).
func TestSOCKS5Handler_LiveConns_PassthroughCutOnReconcile(t *testing.T) {
	echo := startLiveConnEcho(t)
	scope := NewTargetScope()
	scope.SetPolicyRules(allowOnly("127.0.0.1"), nil)
	reg := NewLiveConns(newTestLogger())
	pl := NewPassthroughList()
	pl.Add("127.0.0.1")
	neg := NewSOCKS5Negotiator(newTestLogger())
	neg.Scope = scope

	client, done := serveOneConn(t, NewSOCKS5Handler(SOCKS5HandlerConfig{
		Negotiator:      neg,
		LiveConns:       reg,
		PassthroughList: pl,
		Logger:          newTestLogger(),
	}))
	socks5Through(t, client, echo.addr())
	roundTrip(t, client, "before")
	if got := reg.Len(); got != 1 {
		t.Fatalf("registry Len with tunnel open = %d, want 1", got)
	}

	denyHost(scope, "127.0.0.1")
	if n := reg.Reconcile("test"); n != 1 {
		t.Errorf("Reconcile closed %d, want 1", n)
	}
	assertClosedWithin(t, client, 5*time.Second)
	<-done
	if got := reg.Len(); got != 0 {
		t.Errorf("registry Len after cut = %d, want 0", got)
	}
}

// AC2 (bytechunk): the ctx handed to OnStack for a CONNECT whose inner
// bytes are neither TLS nor HTTP is the tracked one, so a cut cancels it
// with ErrTargetScopeRevoked. proxybuild's OnStack watcher closes the stack
// on ctx.Done (covered end-to-end in internal/mcptest).
func TestCONNECTHandler_LiveConns_BytechunkCtxCancelled(t *testing.T) {
	echo := startLiveConnEcho(t)
	scope := NewTargetScope()
	reg := NewLiveConns(newTestLogger())
	causeCh := make(chan error, 1)
	started := make(chan struct{})

	client, done := serveOneConn(t, NewCONNECTHandler(CONNECTHandlerConfig{
		Negotiator:       NewCONNECTNegotiator(newTestLogger()),
		BuildCfg:         &BuildConfig{},
		Scope:            scope,
		LiveConns:        reg,
		InnerPeekTimeout: 2 * time.Second,
		OnStack: func(ctx context.Context, stack *ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
			defer stack.Close()
			close(started)
			select {
			case <-ctx.Done():
				causeCh <- context.Cause(ctx)
			case <-time.After(10 * time.Second):
				causeCh <- errors.New("OnStack ctx never cancelled")
			}
		},
		Logger: newTestLogger(),
	}))
	connectThrough(t, client, echo.addr())
	if _, err := client.Write([]byte{0x00, 0x01, 'r', 'a', 'w'}); err != nil {
		t.Fatalf("write raw bytes: %v", err)
	}
	// Wait until the bytechunk stack reached OnStack: the tunnel is
	// registered before the inner peek, so checking Len alone would race
	// the cut against the upstream dial.
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("bytechunk stack never reached OnStack")
	}
	if got := reg.Len(); got != 1 {
		t.Fatalf("registry Len with bytechunk tunnel open = %d, want 1", got)
	}

	scope.SetPolicyRules(nil, []TargetRule{{Hostname: "127.0.0.1"}})
	if n := reg.Reconcile("test"); n != 1 {
		t.Errorf("Reconcile closed %d, want 1", n)
	}
	if cause := <-causeCh; !errors.Is(cause, ErrTargetScopeRevoked) {
		t.Errorf("OnStack ctx cause = %v, want ErrTargetScopeRevoked", cause)
	}
	<-done
	if got := reg.Len(); got != 0 {
		t.Errorf("registry Len after cut = %d, want 0", got)
	}
}

// Plain-HTTP forward: one entry per accepted client connection, keyed on
// the upstream target the handler dialed (the connection's upstream leg is
// bound to it for its whole life). A cut cancels the OnStack ctx.
func TestHTTP1ForwardHandler_LiveConns_CutOnReconcile(t *testing.T) {
	echo := startLiveConnEcho(t) // any listener works: the stack is not driven
	scope := NewTargetScope()
	reg := NewLiveConns(newTestLogger())
	causeCh := make(chan error, 1)
	targetCh := make(chan string, 1)

	client, done := serveOneConn(t, NewHTTP1ForwardHandler(HTTP1ForwardHandlerConfig{
		BuildCfg:  &BuildConfig{},
		Scope:     scope,
		LiveConns: reg,
		OnStack: func(ctx context.Context, stack *ConnectionStack, _, _ *envelope.TLSSnapshot, target string) {
			defer stack.Close()
			targetCh <- target
			select {
			case <-ctx.Done():
				causeCh <- context.Cause(ctx)
			case <-time.After(10 * time.Second):
				causeCh <- errors.New("OnStack ctx never cancelled")
			}
		},
		Logger: newTestLogger(),
	}))
	if _, err := io.WriteString(client, "GET http://"+echo.addr()+"/ HTTP/1.1\r\nHost: "+echo.addr()+"\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if got := <-targetCh; got != echo.addr() {
		t.Fatalf("OnStack target = %q, want %q", got, echo.addr())
	}
	if got := reg.Len(); got != 1 {
		t.Fatalf("registry Len with forward conn open = %d, want 1", got)
	}

	// Denying a different host cuts nothing.
	scope.SetPolicyRules(nil, []TargetRule{{Hostname: "other.test"}})
	if n := reg.Reconcile("test"); n != 0 {
		t.Errorf("Reconcile for an unrelated deny closed %d, want 0", n)
	}
	scope.SetPolicyRules(nil, []TargetRule{{Hostname: "127.0.0.1"}})
	if n := reg.Reconcile("test"); n != 1 {
		t.Errorf("Reconcile closed %d, want 1", n)
	}
	if cause := <-causeCh; !errors.Is(cause, ErrTargetScopeRevoked) {
		t.Errorf("OnStack ctx cause = %v, want ErrTargetScopeRevoked", cause)
	}
	<-done
	if got := reg.Len(); got != 0 {
		t.Errorf("registry Len after cut = %d, want 0", got)
	}
}

// A relay torn down by a live-connection cut reports the cancel cause, so
// the passthrough audit flow's error says why the proxy closed it rather
// than a bare "context canceled".
func TestRelayBidirectional_ReturnsCancelCause(t *testing.T) {
	a, b := net.Pipe()
	ctx, cancel := context.WithCancelCause(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- relayBidirectional(ctx, a, b) }()
	time.Sleep(50 * time.Millisecond)
	cancel(ErrTargetScopeRevoked)
	select {
	case err := <-errCh:
		if !errors.Is(err, ErrTargetScopeRevoked) {
			t.Errorf("relay err = %v, want ErrTargetScopeRevoked", err)
		}
		if isTunneledOutcome(err) {
			t.Errorf("a cut relay is classified as tunneled; want failed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not stop after cancel")
	}
}
