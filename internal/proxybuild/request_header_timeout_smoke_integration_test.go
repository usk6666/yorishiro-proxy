//go:build e2e

package proxybuild_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// TestProxybuild_PlainHTTP_SlowlorisRequestHeadClosed_Smoke is the USK-1162
// merge-gate repro: a plain-HTTP forward client that sends enough of its
// request head to get past the 4000-byte target peek and then trickles the
// rest one byte at a time must be disconnected once request_timeout_ms
// (wired as in mcpserver/init.go: Manager bound to the shared BuildConfig +
// Manager.SetRequestTimeout) elapses, instead of holding the slot forever.
func TestProxybuild_PlainHTTP_SlowlorisRequestHeadClosed_Smoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Idle upstream: accepts and holds; the request never completes so it
	// must never be forwarded.
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	defer upLn.Close()
	go func() {
		for {
			c, err := upLn.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	upstream := upLn.Addr().String()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
	}
	logger := testutil.DiscardLogger()
	mgr, err := proxybuild.NewManager(proxybuild.ManagerConfig{
		Logger: logger,
		StackFactory: func(ctx context.Context, name, addr string) (*proxybuild.Stack, error) {
			return proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
				Logger:       logger,
				ListenerName: name,
				ListenAddr:   addr,
				BuildConfig:  buildCfg,
			})
		},
		BuildConfig: buildCfg,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer func() { _ = mgr.StopAll(context.Background()) }()
	mgr.SetRequestTimeout(300 * time.Millisecond)
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	_, proxyAddr := mgr.Status()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	head := "GET http://" + upstream + "/ HTTP/1.1\r\nHost: " + upstream + "\r\nX-Pad: " + strings.Repeat("a", 4100)
	if _, err := conn.Write([]byte(head)); err != nil {
		t.Fatalf("write head: %v", err)
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(50 * time.Millisecond):
			}
			if _, err := conn.Write([]byte("a")); err != nil {
				return
			}
		}
	}()

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	for {
		_, err := conn.Read(buf)
		if err == nil {
			continue
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatal("proxy still holds the trickling connection open after 3s; request head is unbounded")
		}
		return
	}
}
