//go:build e2e && !e2e_smoke

// USK-1216 exhaustive tier: server-speaks-first raw relays — recording
// against a real SQLite store (FK enforced), FIN relay in both directions,
// (raw, on_chunk) plugin dispatch on a Receive-first chunk, and the
// CONNECT + TLS raw-passthrough arm.
package proxybuild_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
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

// openSQLiteStoreUSK1216 opens a real SQLite flow store (foreign_keys=ON)
// and registers its Close. Call it BEFORE starting the Manager: cleanups
// run LIFO, so the Manager is stopped before the store is closed.
func openSQLiteStoreUSK1216(t *testing.T, ctx context.Context) *flow.SQLiteStore {
	t.Helper()
	store, err := flow.NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "flows.db"), testutil.DiscardLogger())
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// waitRawStreamUSK1216 polls the store until exactly one raw Stream exists
// and has reached wantState, and returns it.
func waitRawStreamUSK1216(t *testing.T, ctx context.Context, store *flow.SQLiteStore, wantState string) *flow.Stream {
	t.Helper()
	var last []*flow.Stream
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		streams, err := store.ListStreams(ctx, flow.StreamListOptions{Protocol: "raw"})
		if err != nil {
			t.Fatalf("ListStreams: %v", err)
		}
		last = streams
		if len(streams) == 1 && streams[0].State == wantState {
			return streams[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	var seen []string
	for _, st := range last {
		seen = append(seen, st.ID+"="+st.State)
	}
	t.Fatalf("no single raw Stream reached state=%q within 5s (raw streams: %v)", wantState, seen)
	return nil
}

func findFlowUSK1216(flows []*flow.Flow, dir string, seq int) *flow.Flow {
	for _, f := range flows {
		if f.Direction == dir && f.Sequence == seq {
			return f
		}
	}
	return nil
}

func readExactlyUSK1216(t *testing.T, c net.Conn, n int, d time.Duration) (string, error) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(d))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	buf := make([]byte, n)
	got, err := io.ReadFull(c, buf)
	return string(buf[:got]), err
}

// TestProxybuild_TCPForward_Raw_ServerFirst_RecordedWithSQLite pins the
// recording half of USK-1216 against the real store: the banner the
// upstream sends before any client byte is recorded as the Stream's
// Receive seq 0 Flow (raw bytes intact, no flows.stream_id FK loss), the
// client's first line as Send seq 0, and the Stream completes once both
// peers close.
func TestProxybuild_TCPForward_Raw_ServerFirst_RecordedWithSQLite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const banner = "220 smtp.usk1216.test ESMTP\r\n"
	const ehlo = "EHLO client.test\r\n"
	const reply = "250 ok\r\n"
	upstreamAddr := startBannerUpstreamUSK1216(t, banner, func(c net.Conn) {
		buf := make([]byte, len(ehlo))
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		if _, err := c.Write([]byte(reply)); err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, c) // until the relayed FIN
	})
	store := openSQLiteStoreUSK1216(t, ctx)
	fwdAddr := startRawForwardUSK1216(t, ctx, store, nil, upstreamAddr)

	conn, err := net.DialTimeout("tcp", fwdAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	defer conn.Close()
	if got, err := readExactlyUSK1216(t, conn, len(banner), 2*time.Second); err != nil || got != banner {
		t.Fatalf("banner = %q, %v; want %q without a client send", got, err, banner)
	}
	if _, err := conn.Write([]byte(ehlo)); err != nil {
		t.Fatalf("write EHLO: %v", err)
	}
	if got, err := readExactlyUSK1216(t, conn, len(reply), 2*time.Second); err != nil || got != reply {
		t.Fatalf("reply = %q, %v; want %q", got, err, reply)
	}
	_ = conn.Close()

	st := waitRawStreamUSK1216(t, ctx, store, "complete")
	flows, err := store.GetFlows(ctx, st.ID, flow.FlowListOptions{})
	if err != nil {
		t.Fatalf("GetFlows: %v", err)
	}
	recv0 := findFlowUSK1216(flows, "receive", 0)
	if recv0 == nil {
		t.Fatalf("no Receive seq 0 Flow (banner) recorded; flows=%d", len(flows))
	}
	if string(recv0.RawBytes) != banner {
		t.Errorf("Receive seq 0 RawBytes = %q, want %q", recv0.RawBytes, banner)
	}
	send0 := findFlowUSK1216(flows, "send", 0)
	if send0 == nil {
		t.Fatalf("no Send seq 0 Flow (EHLO) recorded; flows=%d", len(flows))
	}
	if string(send0.RawBytes) != ehlo {
		t.Errorf("Send seq 0 RawBytes = %q, want %q", send0.RawBytes, ehlo)
	}
	recv1 := findFlowUSK1216(flows, "receive", 1)
	if recv1 == nil || string(recv1.RawBytes) != reply {
		t.Errorf("Receive seq 1 Flow = %v, want RawBytes %q", recv1, reply)
	}
}

// TestProxybuild_TCPForward_Raw_FINRelay pins the user-approved FIN relay
// on the tcp_forwards raw arm: a half-close on either side is relayed as
// a half-close, so the peer sees EOF exactly as it would on a direct TCP
// connection, and the other direction keeps flowing.
func TestProxybuild_TCPForward_Raw_FINRelay(t *testing.T) {
	t.Run("client closes without sending; upstream sees EOF and the Stream completes", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		const banner = "* OK idle server\r\n"
		upstreamRead := make(chan error, 1)
		upstreamAddr := startBannerUpstreamUSK1216(t, banner, func(c net.Conn) {
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			var one [1]byte
			_, err := c.Read(one[:])
			upstreamRead <- err
		})
		store := openSQLiteStoreUSK1216(t, ctx)
		fwdAddr := startRawForwardUSK1216(t, ctx, store, nil, upstreamAddr)

		conn, err := net.DialTimeout("tcp", fwdAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial forward: %v", err)
		}
		if got, err := readExactlyUSK1216(t, conn, len(banner), 2*time.Second); err != nil || got != banner {
			t.Fatalf("banner = %q, %v", got, err)
		}
		_ = conn.Close()

		select {
		case err := <-upstreamRead:
			if err != io.EOF {
				t.Fatalf("upstream read after client close = %v, want io.EOF (FIN relayed)", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("upstream read never returned")
		}
		waitRawStreamUSK1216(t, ctx, store, "complete")
	})

	t.Run("upstream sends banner and closes; client gets banner then EOF", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		const banner = "421 service not available\r\n"
		upstreamAddr := startBannerUpstreamUSK1216(t, banner, func(net.Conn) {})
		fwdAddr := startRawForwardUSK1216(t, ctx, nil, nil, upstreamAddr)

		conn, err := net.DialTimeout("tcp", fwdAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial forward: %v", err)
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		got, err := io.ReadAll(conn)
		if err != nil || string(got) != banner {
			t.Fatalf("client ReadAll = %q, %v; want %q then EOF", got, err, banner)
		}
	})

	t.Run("client half-close keeps the response flowing", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		const req = "whois example\n"
		const resp = "example: registered\n"
		upstreamAddr := startBannerUpstreamUSK1216(t, "", func(c net.Conn) {
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			in, err := io.ReadAll(c)
			if err != nil || string(in) != req {
				return
			}
			_, _ = c.Write([]byte(resp))
		})
		fwdAddr := startRawForwardUSK1216(t, ctx, nil, nil, upstreamAddr)

		conn, err := net.DialTimeout("tcp", fwdAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial forward: %v", err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte(req)); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatalf("CloseWrite: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		got, err := io.ReadAll(conn)
		if err != nil || string(got) != resp {
			t.Fatalf("client ReadAll = %q, %v; want %q then EOF", got, err, resp)
		}
	})
}

// TestProxybuild_TCPForward_Raw_ServerFirst_PluginOnChunkFires pins that
// the (raw, on_chunk) hook fires for a Receive-first chunk: the plugin
// rewrites the banner, and the client — which never sent a byte —
// receives the rewritten bytes.
func TestProxybuild_TCPForward_Raw_ServerFirst_PluginOnChunkFires(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const banner = "220 original\r\n"
	const rewritten = "220 rewritten-by-plugin\r\n"
	pluginPath := filepath.Join(t.TempDir(), "p.star")
	script := fmt.Sprintf(`
def on_chunk(msg, ctx):
    if msg["bytes"] == b%q:
        msg["bytes"] = b%q
    return None
register_hook("raw", "on_chunk", on_chunk)
`, banner, rewritten)
	if err := os.WriteFile(pluginPath, []byte(script), 0o600); err != nil {
		t.Fatalf("write plugin: %v", err)
	}
	engine := pluginv2.NewEngine(testutil.DiscardLogger())
	if err := engine.LoadPlugins(ctx, []pluginv2.PluginConfig{{Path: pluginPath, OnError: string(pluginv2.OnErrorAbort)}}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}

	upstreamAddr := startBannerUpstreamUSK1216(t, banner, nil)
	fwdAddr := startRawForwardUSK1216(t, ctx, nil, engine, upstreamAddr)

	conn, err := net.DialTimeout("tcp", fwdAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	defer conn.Close()
	got, err := readExactlyUSK1216(t, conn, len(rewritten), 2*time.Second)
	if err != nil || got != rewritten {
		t.Fatalf("client read = %q, %v; want the plugin-rewritten %q (on_chunk did not fire for the Receive-first chunk)", got, err, rewritten)
	}
}

// TestProxybuild_CONNECT_TLSRawPassthrough_ServerFirst_GreetingRelayed
// pins the CONNECT arm of USK-1216: a host listed in raw_passthrough_hosts
// is TLS-terminated by the proxy and relayed as bytechunk. An IMAPS-style
// upstream greets right after the TLS handshake, and the greeting must
// reach the client without any client send.
func TestProxybuild_CONNECT_TLSRawPassthrough_ServerFirst_GreetingRelayed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const greeting = "* OK IMAP4rev1 usk1216 ready\r\n"
	upstreamCA := &cert.CA{}
	if err := upstreamCA.Generate(); err != nil {
		t.Fatalf("upstream CA.Generate: %v", err)
	}
	upstreamCert, err := cert.NewIssuer(upstreamCA).GetCertificate("127.0.0.1")
	if err != nil {
		t.Fatalf("upstream GetCertificate: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*upstreamCert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
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
				if err := c.(*tls.Conn).Handshake(); err != nil {
					return
				}
				if _, err := c.Write([]byte(greeting)); err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()
	target := ln.Addr().String()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	stack, err := proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
		Logger:       testutil.DiscardLogger(),
		ListenerName: "usk-1216-connect",
		ListenAddr:   "127.0.0.1:0",
		BuildConfig: &connector.BuildConfig{
			ProxyConfig:        &config.ProxyConfig{RawPassthroughHosts: []string{target}},
			Issuer:             cert.NewIssuer(ca),
			InsecureSkipVerify: true,
		},
	})
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	go func() { _ = stack.Listener.Start(ctx) }()
	select {
	case <-stack.Listener.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("listener not ready")
	}

	conn, err := net.DialTimeout("tcp", stack.Listener.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || !strings.Contains(string(buf[:n]), " 200 ") {
		t.Fatalf("CONNECT response = %q, %v", buf[:n], err)
	}
	tc := tls.Client(conn, &tls.Config{ServerName: "127.0.0.1", InsecureSkipVerify: true}) //nolint:gosec // test client trusts the proxy's ephemeral MITM CA
	if err := tc.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	_ = conn.SetDeadline(time.Time{})

	_ = tc.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, len(greeting))
	if _, err := io.ReadFull(tc, got); err != nil {
		t.Fatalf("server-first greeting not relayed within 2s without a client send: %v (got %q)", err, got)
	}
	if string(got) != greeting {
		t.Fatalf("greeting = %q, want %q", got, greeting)
	}
}
