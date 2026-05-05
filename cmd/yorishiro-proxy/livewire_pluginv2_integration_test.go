//go:build e2e

package main

// livewire_pluginv2_integration_test.go — RFC-001 N9 (USK-691)
// Live-wire pluginv2 e2e parity tests for the proxybuild + pluginv2
// data path installed by USK-690 in cmd/yorishiro-proxy/main.go.
//
// USK-691 is the N9 deletion gate: before the next batch (USK-692…)
// removes legacy code, these tests prove that the new live data path
// actually fires the three pluginv2 lifecycle hooks specified by
// USK-681 AC 1.1 / 1.4 / 1.5 against real network traffic, and that
// loaded plugins reach the pluginv2_kv table through the store module.
//
// The proxybuild Listener does NOT wire OnHTTP1 / OnTCP forward-proxy
// handlers (see internal/proxybuild/builder.go:268-280 — "scaffold-
// deferred"). Live HTTP/1.x therefore travels INSIDE a CONNECT tunnel
// after MITM TLS termination, which is the production-relevant path
// for an HTTPS forward proxy. AC 1.1 ("HTTP/1.x request") is satisfied
// by the inner request frame.

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
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
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
	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	rulescommon "github.com/usk6666/yorishiro-proxy/internal/rules/common"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// liveProxy is the bundle returned by setupLiveProxy.
type liveProxy struct {
	addr       string
	manager    *proxybuild.Manager
	engine     *pluginv2.Engine
	store      *flow.SQLiteStore
	pluginName string
}

// setupLiveProxy wires together a pluginv2.Engine, an ephemeral CA, a
// SQLite flow store, and a proxybuild.Manager listening on a loopback
// port. The plugin script is materialised into t.TempDir() and loaded
// via initPluginV2Engine (the same code path runWithFlags uses in
// production, so the test exercises real config-driven plugin loading).
//
// Cleanup runs in t.Cleanup in this order: manager.StopAll → engine.Close
// → store.Close. This matches the deferred-LIFO ordering documented at
// cmd/yorishiro-proxy/main.go:336-345 (USK-690 S-2 fix) — listener
// teardown must finish before plugin scopes are zeroed so in-flight
// OnComplete callbacks observe a live store.
func setupLiveProxy(t *testing.T, pluginName, pluginScript string) *liveProxy {
	t.Helper()
	ctx := context.Background()
	logger := testutil.DiscardLogger()
	if v := os.Getenv("USK691_DEBUG_LOG"); v != "" {
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "live.db")
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	scriptPath := filepath.Join(dir, pluginName+".star")
	if err := os.WriteFile(scriptPath, []byte(pluginScript), 0o600); err != nil {
		store.Close()
		t.Fatalf("write plugin: %v", err)
	}

	cfg := config.Default()
	cfg.InsecureSkipVerify = true
	cfg.CAEphemeral = true
	proxyCfg := &config.ProxyConfig{
		Plugins: []pluginv2.PluginConfig{{
			Name:    pluginName,
			Path:    scriptPath,
			OnError: string(pluginv2.OnErrorAbort),
		}},
	}

	engine, err := initPluginV2Engine(ctx, store, proxyCfg, logger)
	if err != nil {
		store.Close()
		t.Fatalf("initPluginV2Engine: %v", err)
	}

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		engine.Close()
		store.Close()
		t.Fatalf("CA.Generate: %v", err)
	}
	issuer := cert.NewIssuer(ca)

	holdQueue := rulescommon.NewHoldQueue()
	httpInterceptEngine := httprules.NewInterceptEngine()
	wsInterceptEngine := wsrules.NewInterceptEngine()
	grpcInterceptEngine := grpcrules.NewInterceptEngine()
	httpTransformEngine := httprules.NewTransformEngine()
	buildCfg := newLiveBuildConfig(ctx, cfg, proxyCfg, issuer, engine, store, logger)

	mgr, err := newLiveManager(cfg, proxyCfg, store, issuer, engine, holdQueue,
		httpInterceptEngine, wsInterceptEngine, grpcInterceptEngine,
		httpTransformEngine,
		(*connector.PassthroughList)(nil), (*connector.RateLimiter)(nil),
		(*safety.Engine)(nil),
		buildCfg, logger)
	if err != nil {
		engine.Close()
		store.Close()
		t.Fatalf("newLiveManager: %v", err)
	}

	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		engine.Close()
		store.Close()
		t.Fatalf("Manager.Start: %v", err)
	}

	listener := mgr.Listener(proxybuild.DefaultListenerName)
	if listener == nil {
		t.Fatal("Manager.Listener: returned nil after Start")
	}
	addr := listener.Addr()
	if addr == "" {
		t.Fatal("Manager.Listener.Addr: empty after Start")
	}

	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = mgr.StopAll(stopCtx)
		_ = engine.Close()
		_ = store.Close()
	})

	return &liveProxy{
		addr:       addr,
		manager:    mgr,
		engine:     engine,
		store:      store,
		pluginName: pluginName,
	}
}

// dumpPluginKV prints every (key, value) row for plugin_name. Diagnostic
// helper — keep so failure messages distinguish "no rows" (engine
// didn't dispatch) from "wrong row" (engine dispatched a sibling event).
func dumpPluginKV(t *testing.T, db *sql.DB, pluginName string) {
	t.Helper()
	rows, err := db.Query(
		"SELECT key, value FROM pluginv2_kv WHERE plugin_name = ? ORDER BY key",
		pluginName,
	)
	if err != nil {
		t.Logf("dumpPluginKV: query: %v", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			t.Logf("dumpPluginKV: scan: %v", err)
			return
		}
		t.Logf("pluginv2_kv: plugin=%q %s=%q", pluginName, k, v)
	}
}

// waitForPluginKV polls the pluginv2_kv table until the (plugin_name, key)
// row exists with the expected value, or the deadline expires. The hook
// fires from a goroutine so the test cannot rely on synchronous ordering
// with the request completion. Polling avoids the brittleness of fixed
// time.Sleep durations under -race / loaded CI.
func waitForPluginKV(t *testing.T, db *sql.DB, pluginName, key, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var got string
		err := db.QueryRow(
			"SELECT value FROM pluginv2_kv WHERE plugin_name = ? AND key = ?",
			pluginName, key,
		).Scan(&got)
		if err == nil {
			if got != want {
				t.Fatalf("pluginv2_kv[%q,%q] = %q, want %q", pluginName, key, got, want)
			}
			return
		}
		if !errors.Is(err, sql.ErrNoRows) {
			t.Fatalf("query pluginv2_kv: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("pluginv2_kv row not written within deadline: plugin=%q key=%q", pluginName, key)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// --- Upstream stubs ----------------------------------------------------

// newLiveTestTLSConfig returns a self-signed TLS config for a test
// upstream server. The proxy dials with InsecureSkipVerify=true so the
// self-signed cert is acceptable as the dialed-side trust anchor.
func newLiveTestTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "live-upstream"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"live-upstream", "127.0.0.1", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  key,
		}},
	}
}

// startUpstreamHTTPSEcho starts a TLS server that reads a single HTTP/1.x
// request from each accepted connection and replies with a fixed
// 200 OK body. Returns the listener so caller can read Addr() and arrange
// shutdown via t.Cleanup.
func startUpstreamHTTPSEcho(t *testing.T) net.Listener {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", newLiveTestTLSConfig(t))
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				br := bufio.NewReader(c)
				// Drain request headers (fixed: no body expected).
				for {
					line, err := br.ReadBytes('\n')
					if err != nil {
						return
					}
					if bytes.Equal(line, []byte("\r\n")) {
						break
					}
				}
				resp := "HTTP/1.1 200 OK\r\n" +
					"Content-Type: text/plain\r\n" +
					"Content-Length: 19\r\n" +
					"Connection: close\r\n" +
					"\r\n" +
					"hello from upstream"
				_, _ = c.Write([]byte(resp))
			}(conn)
		}
	}()
	return ln
}

// startUpstreamHTTPSWS starts a TLS server that performs a minimal WS
// handshake (HTTP/1.x Upgrade → 101) and then echoes WebSocket frames
// back to the client until OpcodeClose is seen. The handshake response
// hard-codes a fake Sec-WebSocket-Accept value, which the proxy passes
// through faithfully (no normalization principle); the test client
// likewise does not validate the accept token.
func startUpstreamHTTPSWS(t *testing.T) net.Listener {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", newLiveTestTLSConfig(t))
	if err != nil {
		t.Fatalf("tls.Listen ws: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleUpstreamWSEcho(conn)
		}
	}()
	return ln
}

func handleUpstreamWSEcho(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)

	// Read HTTP upgrade request.
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return
		}
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}
	}

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: dummy-accept-key\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		return
	}

	for {
		fr, err := ws.ReadFrame(br)
		if err != nil {
			return
		}
		if fr.Opcode == ws.OpcodeClose {
			closeFrame := &ws.Frame{Fin: true, Opcode: ws.OpcodeClose, Payload: fr.Payload}
			_ = ws.WriteFrame(conn, closeFrame)
			return
		}
		echo := &ws.Frame{Fin: true, Opcode: fr.Opcode, Payload: fr.Payload}
		if err := ws.WriteFrame(conn, echo); err != nil {
			return
		}
	}
}

// --- Client helpers ----------------------------------------------------

// dialMITM connects to the proxy, sends CONNECT for target, reads the
// 200 Connection Established line, and performs a TLS handshake against
// the proxy-issued cert. Returns the *tls.Conn ready for application
// data on the inner stream.
func dialMITM(t *testing.T, proxyAddr, target string) *tls.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		t.Fatalf("write CONNECT: %v", err)
	}

	buf := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		t.Fatalf("read CONNECT response: %v", err)
	}
	if got := string(buf[:n]); !strings.HasPrefix(got, "HTTP/1.1 200") {
		conn.Close()
		t.Fatalf("CONNECT response = %q, want 200", got)
	}
	conn.SetReadDeadline(time.Time{})

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		t.Fatalf("inner TLS handshake: %v", err)
	}
	return tlsConn
}

// --- Tests --------------------------------------------------------------

// TestLiveWire_PluginV2_HTTPOnRequestPrePipeline covers USK-681 AC 1.1.
// A pluginv2 plugin loaded from config registers ("http","on_request",
// pre_pipeline). After a single HTTPS-via-CONNECT GET round-trip through
// the live proxybuild stack, the test asserts that:
//   - The plugin's pre_pipeline hook fired (pluginv2_kv row written via
//     store.set, also satisfying the store-module-reachability check).
//   - Stream + Flow recordings landed with canonical Protocol="http".
//   - Flow.RawBytes is populated for both directions (L4-capable +
//     wire-fidelity principles).
func TestLiveWire_PluginV2_HTTPOnRequestPrePipeline(t *testing.T) {
	const pluginName = "ac11_http_on_request"
	script := `
def on_request(msg, ctx):
    store.set("hook:fired", "true")
    store.set("ac:http_on_request_pre", "1")

register_hook("http", "on_request", on_request, phase="pre_pipeline")
`
	lp := setupLiveProxy(t, pluginName, script)
	upstream := startUpstreamHTTPSEcho(t)

	tlsConn := dialMITM(t, lp.addr, upstream.Addr().String())
	defer tlsConn.Close()

	req := "GET /ac11 HTTP/1.1\r\n" +
		"Host: " + upstream.Addr().String() + "\r\n" +
		"User-Agent: usk-691-livewire/1.0\r\n" +
		"Accept: */*\r\n" +
		"Connection: close\r\n" +
		"\r\n"
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respBytes, err := io.ReadAll(tlsConn)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("read response: %v", err)
	}
	resp := string(respBytes)
	if !strings.Contains(resp, "200 OK") {
		t.Fatalf("response did not contain 200 OK: %q", resp)
	}
	if !strings.Contains(resp, "hello from upstream") {
		t.Fatalf("response body missing: %q", resp)
	}
	tlsConn.Close()

	// Plugin hook fired and store reachability proven.
	waitForPluginKV(t, lp.store.DB(), pluginName, "hook:fired", "true")
	waitForPluginKV(t, lp.store.DB(), pluginName, "ac:http_on_request_pre", "1")

	// Recording landed with canonical http Protocol and wire-fidelity raw.
	assertHTTPStreamRecorded(t, lp.store, "http")
}

// TestLiveWire_PluginV2_WSOnMessage covers USK-681 AC 1.4. The proxy
// MITM-decrypts a CONNECT tunnel, observes the WS upgrade, swaps in the
// WS Layer (session.runUpgradeWS), and then delivers a client→server WS
// frame to the pipeline. PluginStepPre dispatches it as ("ws",
// "on_message"). The test confirms the pluginv2_kv row landed.
func TestLiveWire_PluginV2_WSOnMessage(t *testing.T) {
	const pluginName = "ac14_ws_on_message"
	// Register (ws, on_upgrade) too so the test can distinguish "pipeline
	// never ran on this connection" from "pipeline ran but post-swap
	// dispatch never fired". on_upgrade is observational only — the real
	// AC 1.4 assertion is the on_message key.
	script := `
def on_ws_upgrade(msg, ctx):
    # Increment so we can distinguish "request reached pipeline but 101
    # didn't" (count=1) from "both sides reached" (count=2). Plain int
    # cast through string is fine — store.set accepts string only.
    cur = store.get("debug:ws_on_upgrade_count")
    n = int(cur) if cur else 0
    store.set("debug:ws_on_upgrade_count", str(n + 1))

def on_ws_message(msg, ctx):
    store.set("ac:ws_on_message", "1")

register_hook("ws", "on_upgrade", on_ws_upgrade)
register_hook("ws", "on_message", on_ws_message)
`
	lp := setupLiveProxy(t, pluginName, script)
	upstream := startUpstreamHTTPSWS(t)

	tlsConn := dialMITM(t, lp.addr, upstream.Addr().String())
	defer tlsConn.Close()

	req := "GET /ws HTTP/1.1\r\n" +
		"Host: " + upstream.Addr().String() + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}

	br := bufio.NewReader(tlsConn)
	tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read 101 status: %v", err)
	}
	if !strings.Contains(statusLine, "101") {
		t.Fatalf("upgrade status = %q, want 101", statusLine)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read upgrade headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	tlsConn.SetReadDeadline(time.Time{})

	// USK-701: production WS unblock — session.upstreamToClient fires
	// http1.channel.Interrupt() right after Send(101), so the proxy's
	// parked client-side http1 parser wakes on os.ErrDeadlineExceeded and
	// runUpgradeWS proceeds with DetachStream (which resets the deadline)
	// + ws.New. No test-only sacrificial bytes or settle sleep needed —
	// the swap + recursive RunStackSession run on the proxy side while we
	// proceed to write the WS frame here. Frame bytes land in the kernel
	// buffer of the proxy's client-side conn and are picked up by the new
	// ws.Layer's read goroutine once it spawns.
	//
	// Write a real masked text frame (RFC 6455 §5.3 — client→server frames
	// must be masked). The upstream echo on br (read below) is the natural
	// synchronization point — it cannot arrive until the proxy has fully
	// swapped both sides and round-tripped the frame.
	frame := &ws.Frame{
		Fin:     true,
		Opcode:  ws.OpcodeText,
		Masked:  true,
		MaskKey: [4]byte{0xa1, 0xb2, 0xc3, 0xd4},
		Payload: []byte("usk-691"),
	}
	if err := ws.WriteFrame(tlsConn, frame); err != nil {
		t.Fatalf("write ws frame: %v", err)
	}

	// Best-effort drain of the upstream's echo so the upstream goroutine
	// can finish cleanly. We don't assert content — the AC is hook-firing.
	tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = ws.ReadFrame(br)
	tlsConn.Close()

	// Diagnostic: dump pluginv2_kv before strict assertion so failures
	// distinguish "pipeline never ran" (no rows) from "ran but layer swap
	// missed on_message" (debug:ws_on_upgrade present, ac:ws_on_message
	// absent).
	dumpPluginKV(t, lp.store.DB(), pluginName)

	waitForPluginKV(t, lp.store.DB(), pluginName, "ac:ws_on_message", "1")
}

// TestLiveWire_WSUpgrade_ProductionUnblock_NoSacrificialBytes is the
// dedicated USK-701 AC-1 deliverable: a real WebSocket client (RFC 6455
// §4.1 compliant — write Upgrade, read 101, then write frames with no
// test-only \x00\x00\x00\x00\r\n\r\n unblock sequence) must complete a
// frame round-trip through proxybuild.Manager AND the WS Stream + Flow
// records must land in the SQLite store.
//
// Distinct from TestLiveWire_PluginV2_WSOnMessage: that test exercises
// hook firing and best-effort drains the echo without assertion. This
// one focuses on the production unblock path (no plugin interference)
// and asserts the round-trip payload matches AND the recording shape.
//
// Pre-USK-701 this test would either time out (the proxy's parked http1
// parser never returns ErrUpgradePending) or lose the WS frame bytes to
// the failing parse. Post-USK-701, session.upstreamToClient fires
// http1.channel.Interrupt() right after Send(101), the parker wakes on
// os.ErrDeadlineExceeded, runUpgradeWS performs DetachStream + ws.New,
// and the WS frame round-trip completes naturally.
func TestLiveWire_WSUpgrade_ProductionUnblock_NoSacrificialBytes(t *testing.T) {
	// Empty plugin script — we do not depend on hooks for this test.
	const pluginName = "usk701_ws_unblock_noplugin"
	script := `
def on_noop(msg, ctx):
    pass

register_hook("http", "on_request", on_noop, phase="post_pipeline")
`
	lp := setupLiveProxy(t, pluginName, script)
	upstream := startUpstreamHTTPSWS(t)

	tlsConn := dialMITM(t, lp.addr, upstream.Addr().String())
	defer tlsConn.Close()

	// RFC 6455 §4.1 compliant client sequence: write Upgrade, read 101,
	// then send WS frames. No test-only sacrificial bytes.
	req := "GET /ws HTTP/1.1\r\n" +
		"Host: " + upstream.Addr().String() + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		t.Fatalf("write upgrade: %v", err)
	}

	br := bufio.NewReader(tlsConn)
	tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read 101 status: %v", err)
	}
	if !strings.Contains(statusLine, "101") {
		t.Fatalf("upgrade status = %q, want 101", statusLine)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read upgrade headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	tlsConn.SetReadDeadline(time.Time{})

	// Write a real masked WS text frame. The proxy's swap orchestrator
	// (session.upstreamToClient) has already fired Interrupt against the
	// parked client-side http1 parser; the swap is happening concurrently
	// while we proceed here. Frame bytes land in the proxy's kernel buffer
	// and the post-swap ws.Layer picks them up.
	const wantPayload = "usk-701-roundtrip"
	frame := &ws.Frame{
		Fin:     true,
		Opcode:  ws.OpcodeText,
		Masked:  true,
		MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78},
		Payload: []byte(wantPayload),
	}
	if err := ws.WriteFrame(tlsConn, frame); err != nil {
		t.Fatalf("write ws frame: %v", err)
	}

	// Read the upstream echo. This is the natural synchronization point —
	// the echo cannot arrive until the proxy has fully completed both
	// Layer swaps and round-tripped the frame.
	tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	echo, err := ws.ReadFrame(br)
	if err != nil {
		t.Fatalf("read ws echo: %v", err)
	}
	if echo.Opcode != ws.OpcodeText {
		t.Errorf("echo opcode = %v, want OpcodeText", echo.Opcode)
	}
	if string(echo.Payload) != wantPayload {
		t.Errorf("echo payload = %q, want %q", echo.Payload, wantPayload)
	}

	// Send a Close frame so the upstream returns cleanly. (Server-→client
	// close payload is unmasked per RFC 6455 §5.5.1.)
	closeFrame := &ws.Frame{
		Fin:     true,
		Opcode:  ws.OpcodeClose,
		Masked:  true,
		MaskKey: [4]byte{0xab, 0xcd, 0xef, 0x01},
	}
	_ = ws.WriteFrame(tlsConn, closeFrame)
	tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = ws.ReadFrame(br) // best-effort drain of close echo
	tlsConn.Close()

	// Recording assertion: a WS Stream lands with State=complete and at
	// least one Send + one Receive WS Flow with non-empty RawBytes. The
	// canonical Protocol label for WebSocket Streams is "ws".
	assertHTTPStreamRecorded(t, lp.store, "ws")
}

// TestLiveWire_PluginV2_ConnectionOnConnect covers USK-681 AC 1.5. The
// proxybuild Listener wraps OnCONNECT (and OnSOCKS5) with an interposed
// HandlerFunc that fires connection.on_connect after protocol detection
// (see internal/proxybuild/listener.go:117-141 — documented compromise).
// Any successfully-negotiated CONNECT through the live listener
// therefore satisfies AC 1.5.
func TestLiveWire_PluginV2_ConnectionOnConnect(t *testing.T) {
	const pluginName = "ac15_connection_on_connect"
	script := `
def on_connect(msg, ctx):
    store.set("ac:connection_on_connect", "1")

register_hook("connection", "on_connect", on_connect)
`
	lp := setupLiveProxy(t, pluginName, script)
	upstream := startUpstreamHTTPSEcho(t)

	tlsConn := dialMITM(t, lp.addr, upstream.Addr().String())
	// Issue a trivial inner request so the proxy completes a full session
	// (otherwise teardown can race with the on_connect hook goroutine).
	_, _ = tlsConn.Write([]byte("GET /probe HTTP/1.1\r\nHost: " +
		upstream.Addr().String() + "\r\nConnection: close\r\n\r\n"))
	io.Copy(io.Discard, tlsConn)
	tlsConn.Close()

	waitForPluginKV(t, lp.store.DB(), pluginName, "ac:connection_on_connect", "1")
}

// --- Recording assertions ----------------------------------------------

// assertHTTPStreamRecorded queries the SQLite store for the most recent
// Stream and confirms its Protocol matches the canonical HTTP label, its
// State has progressed to "complete", and at least one Send + one Receive
// Flow with non-empty RawBytes are present.
func assertHTTPStreamRecorded(t *testing.T, store *flow.SQLiteStore, wantProtocol string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for {
		streams, err := store.ListStreams(ctx, flow.StreamListOptions{})
		if err != nil {
			t.Fatalf("ListStreams: %v", err)
		}
		for _, s := range streams {
			if s.Protocol != wantProtocol {
				continue
			}
			if s.State != "complete" {
				continue
			}
			flows, err := store.GetFlows(ctx, s.ID, flow.FlowListOptions{})
			if err != nil {
				t.Fatalf("GetFlows: %v", err)
			}
			haveSend, haveRecv := false, false
			for _, f := range flows {
				if len(f.RawBytes) == 0 {
					continue
				}
				switch f.Direction {
				case "send":
					haveSend = true
				case "receive":
					haveRecv = true
				}
			}
			if haveSend && haveRecv {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no http stream with state=complete + send+receive raw flows found in time")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
