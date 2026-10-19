//go:build e2e

// USK-1216 smoke: a tcp_forwards protocol=raw relay must deliver an
// upstream that speaks first (SMTP / MySQL / FTP / IMAP banner) to the
// client without the client sending anything. Before the fix the raw
// session published the upstream Channel only on the first client chunk,
// so both peers waited on each other forever.
//
// Smoke tier (plain `//go:build e2e`) so the deadlock regression is in the
// per-PR merge gate. Self-contained: the exhaustive-tier forward helpers
// (newForwardTestManager / flowStoreCapture) are not compiled under
// e2e_smoke.
package proxybuild_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// startBannerUpstreamUSK1216 runs a plaintext TCP upstream that writes
// banner as soon as it accepts a connection, then hands the connection
// to serve (nil: echo every byte back until EOF, then close).
func startBannerUpstreamUSK1216(t *testing.T, banner string, serve func(c net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if _, err := c.Write([]byte(banner)); err != nil {
					return
				}
				if serve != nil {
					serve(c)
					return
				}
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// startRawForwardUSK1216 starts a Manager with one tcp_forwards entry
// (protocol=raw) to target and returns the forward listener address.
// store may be nil (no recording); engine may be nil (no plugins).
func startRawForwardUSK1216(t *testing.T, ctx context.Context, store flow.Writer, engine *pluginv2.Engine, target string) string {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
	}
	mgr, err := proxybuild.NewManager(proxybuild.ManagerConfig{
		Logger: testutil.DiscardLogger(),
		StackFactory: func(ctx context.Context, name, addr string) (*proxybuild.Stack, error) {
			return proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
				Logger:         testutil.DiscardLogger(),
				ListenerName:   name,
				ListenAddr:     addr,
				FlowStore:      store,
				BuildConfig:    buildCfg,
				PluginV2Engine: engine,
			})
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.StopAll(context.Background()) })
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	if err := mgr.StartTCPForwards(ctx, proxybuild.TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			"0": {Target: target, Protocol: "raw"},
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

// TestProxybuild_TCPForward_Raw_ServerSpeaksFirst_BannerRelayed is the
// USK-1216 smoke acceptance test: connect, send nothing, and the
// upstream's banner must arrive within 2 s; the session then continues
// as a normal echo relay.
func TestProxybuild_TCPForward_Raw_ServerSpeaksFirst_BannerRelayed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const banner = "220 smtp.usk1216.test ESMTP ready\r\n"
	upstreamAddr := startBannerUpstreamUSK1216(t, banner, nil)
	fwdAddr := startRawForwardUSK1216(t, ctx, nil, nil, upstreamAddr)

	conn, err := net.DialTimeout("tcp", fwdAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, len(banner))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("server-first banner not relayed within 2s without a client send: %v (got %q)", err, got)
	}
	if string(got) != banner {
		t.Fatalf("banner = %q, want %q", got, banner)
	}

	const line = "EHLO client.test\r\n"
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(line)); err != nil {
		t.Fatalf("write: %v", err)
	}
	echo := make([]byte, len(line))
	if _, err := io.ReadFull(conn, echo); err != nil || string(echo) != line {
		t.Fatalf("echo = %q, %v; want %q", echo, err, line)
	}
}
