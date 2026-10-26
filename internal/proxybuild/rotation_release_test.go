package proxybuild

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// startRotationReleaseProxy runs a fake upstream HTTP proxy: it answers
// every CONNECT with 200, reports the Basic username it was offered, then
// answers the first tunneled request head with a Connection: close 200.
func startRotationReleaseProxy(t *testing.T) (addr string, users <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ch := make(chan string, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				br := bufio.NewReader(c)
				user := ""
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" {
						break
					}
					if v, ok := strings.CutPrefix(line, "Proxy-Authorization: Basic "); ok {
						dec, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
						user, _, _ = strings.Cut(string(dec), ":")
					}
				}
				ch <- user
				if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
					return
				}
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" {
						break
					}
				}
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			}(c)
		}
	}()
	return ln.Addr().String(), ch
}

// startRotationReleaseManager starts a Manager whose default listener has
// a per_connection rotation resolver pointing at proxyAddr. The Manager and
// its Stacks share one BuildConfig, as in production.
func startRotationReleaseManager(t *testing.T, ctx context.Context, proxyAddr string) (*Manager, *connector.RotationResolver, *testutil.CaptureLogger) {
	t.Helper()
	logs, logger := testutil.NewCaptureLogger()
	bc := newTestDeps(t).BuildConfig
	mgr, err := NewManager(ManagerConfig{
		Logger:      logger,
		BuildConfig: bc,
		StackFactory: func(_ context.Context, name, addr string) (*Stack, error) {
			d := newTestDeps(t)
			d.Logger = logger
			d.ListenerName = name
			d.ListenAddr = addr
			d.BuildConfig = bc
			return BuildLiveStack(context.Background(), d)
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { mgr.StopAll(context.Background()) })
	if err := mgr.SetUpstreamProxyRotationForListener(DefaultListenerName, &connector.RotationConfig{
		Template:     "http://session-§__nonce§:pass@" + proxyAddr,
		Policy:       connector.RotationPerConnection,
		ListenerName: DefaultListenerName,
	}); err != nil {
		t.Fatalf("SetUpstreamProxyRotationForListener: %v", err)
	}
	r := bc.RotationForListener(DefaultListenerName)
	if r == nil {
		t.Fatal("no rotation resolver installed")
	}
	return mgr, r, logs
}

// roundTripOverRotation sends one Connection: close request on a fresh
// connection to addr and checks the fake proxy's 200 comes back.
func roundTripOverRotation(t *testing.T, addr, request string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, request); err != nil {
		t.Fatalf("write: %v", err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if got := strings.TrimRight(line, "\r\n"); got != "HTTP/1.1 200 OK" {
		t.Fatalf("status line %q, want HTTP/1.1 200 OK", got)
	}
}

// waitClosedConnID waits for the per-connection "closed" Debug line msg
// and returns the conn_id it carries.
func waitClosedConnID(t *testing.T, logs *testutil.CaptureLogger, msg string) string {
	t.Helper()
	re := regexp.MustCompile(`msg="` + regexp.QuoteMeta(msg) + `".*?conn_id=(\S+)`)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if m := re.FindStringSubmatch(logs.Output()); m != nil {
			return m[1]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no %q log line with a conn_id:\n%s", msg, logs.Output())
	return ""
}

// assertPerConnReleased fails when the resolver still returns the URL the
// closed connection used for its conn ID, i.e. the per_connection entry
// outlived the client connection (USK-1278 review S-1).
func assertPerConnReleased(t *testing.T, r *connector.RotationResolver, connID, usedUser string) {
	t.Helper()
	u, err := r.Resolve(connector.ContextWithConnID(context.Background(), connID), DefaultListenerName, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := u.User.Username(); got == usedUser {
		t.Errorf("per_connection rotation entry for conn_id %s still cached after the connection closed (user %q)", connID, got)
	}
}

func receiveUser(t *testing.T, users <-chan string) string {
	t.Helper()
	select {
	case u := <-users:
		if !strings.HasPrefix(u, "session-") {
			t.Fatalf("upstream proxy saw user %q, want a session-<nonce> user", u)
		}
		return u
	case <-time.After(5 * time.Second):
		t.Fatal("upstream proxy saw no CONNECT")
		return ""
	}
}

// TestPerConnectionRotation_ReleasedAfterPlainHTTPForward: a plain-HTTP
// forward connection resolves its upstream proxy under the per_connection
// policy; once the client connection is over the entry is dropped.
func TestPerConnectionRotation_ReleasedAfterPlainHTTPForward(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxyAddr, users := startRotationReleaseProxy(t)
	mgr, r, logs := startRotationReleaseManager(t, ctx, proxyAddr)

	addr := mgr.Stack(DefaultListenerName).Listener.Addr()
	roundTripOverRotation(t, addr, "GET http://a.example/ HTTP/1.1\r\nHost: a.example\r\nConnection: close\r\n\r\n")
	used := receiveUser(t, users)
	connID := waitClosedConnID(t, logs, "connection closed")
	assertPerConnReleased(t, r, connID, used)
}

// TestPerConnectionRotation_ReleasedAfterTCPForward: the same for a raw
// tcp_forwards connection, which is not accepted by FullListener.
func TestPerConnectionRotation_ReleasedAfterTCPForward(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxyAddr, users := startRotationReleaseProxy(t)
	mgr, r, logs := startRotationReleaseManager(t, ctx, proxyAddr)

	port := freePortKey(t)
	if err := mgr.StartTCPForwards(ctx, TCPForwardParams{Forwards: map[string]*config.ForwardConfig{
		port: {Target: "b.example:80", Protocol: "raw"},
	}}); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}
	roundTripOverRotation(t, net.JoinHostPort("127.0.0.1", port), "GET / HTTP/1.1\r\nHost: b.example\r\nConnection: close\r\n\r\n")
	used := receiveUser(t, users)
	connID := waitClosedConnID(t, logs, "tcp forward connection closed")
	assertPerConnReleased(t, r, connID, used)
}
