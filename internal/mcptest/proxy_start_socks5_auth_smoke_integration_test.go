//go:build e2e

// USK-770: smoke coverage for the MCP `proxy_start socks5_auth=password`
// path. The bug surfaced when MCP callers passed
// `proxy_start socks5_auth=password ...` and the call always failed with
// "socks5_auth: SOCKS5 handler is not initialized" because the
// mcpserver → proxybuild → connector dependency chain did not pass the
// SOCKS5Negotiator through (USK-690 rewire residue). These tests exercise
// the JSON-RPC harness end-to-end so a regression trips merge CI rather
// than nightly.
//
// Each test boots the production wiring via mcptest.StartHarness and
// drives a real SOCKS5 client against the proxy listener:
//
//   - TestE2E_ProxyStart_SOCKS5Auth_PasswordRejectsAndAllows asserts AC1
//     (good creds accepted, no creds rejected after `proxy_start
//     socks5_auth=password`).
//   - TestE2E_Configure_SOCKS5Auth_AppliesWithoutRestart asserts AC2 (the
//     configure tool mutates the running listener's auth without
//     restarting it).
//   - TestE2E_ProxyStart_SOCKS5Auth_NoneToPasswordToNone asserts AC3 (auth
//     is cleared when proxy_stop / proxy_start cycles without
//     socks5_auth).
package mcptest_test

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_ProxyStart_SOCKS5Auth_PasswordRejectsAndAllows boots the proxy,
// asks `proxy_start socks5_auth=password` to install creds, and then
// drives two SOCKS5 clients at the listener — one with valid creds (must
// reach the upstream test server) and one with no creds (must fail at
// method selection).
func TestE2E_ProxyStart_SOCKS5Auth_PasswordRejectsAndAllows(t *testing.T) {
	const wantUser, wantPass = "alice", "s3cret"

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		UpstreamProto: "http/1.1",
	})

	startRes := h.MustOK(t, "proxy_start", map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"socks5_auth":     "password",
		"socks5_username": wantUser,
		"socks5_password": wantPass,
	})
	proxyAddr, ok := startRes.Decoded["listen_addr"].(string)
	if !ok || proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %+v", startRes.Decoded)
	}

	// Sub-case 1: NO_AUTH greeting must be rejected (negotiator picks
	// 0xFF because USERNAME_PASSWORD is required).
	t.Run("no_auth_rejected", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		defer conn.Close()
		// VER=5, NMETHODS=1, METHOD=NO_AUTH(0x00)
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			t.Fatalf("write greeting: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp := make([]byte, 2)
		if _, err := io.ReadFull(conn, resp); err != nil {
			t.Fatalf("read method selection: %v", err)
		}
		if resp[0] != 0x05 || resp[1] != 0xFF {
			t.Errorf("method selection = %x, want 05 FF (no acceptable)", resp)
		}
	})

	// Sub-case 2: USERNAME_PASSWORD with valid creds must complete
	// the handshake and bridge to the upstream test server.
	t.Run("password_accepted", func(t *testing.T) {
		upstreamHost, upstreamPort := splitHostPort(t, h.UpstreamTLS.URL)
		bridge := socks5DialAuth(t, proxyAddr, wantUser, wantPass, upstreamHost, upstreamPort)
		defer bridge.Close()
	})

	// Sub-case 3: USERNAME_PASSWORD with wrong creds must fail at
	// the sub-negotiation step.
	t.Run("password_wrong_creds_rejected", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		defer conn.Close()
		// VER=5, NMETHODS=1, METHOD=USERNAME_PASSWORD(0x02)
		if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
			t.Fatalf("write greeting: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		resp := make([]byte, 2)
		if _, err := io.ReadFull(conn, resp); err != nil {
			t.Fatalf("read method selection: %v", err)
		}
		if resp[1] != 0x02 {
			t.Fatalf("method selection = %x, want USERNAME_PASSWORD", resp)
		}
		// Sub-negotiation: VER=1, ULEN, USER, PLEN, PASS — wrong password.
		const badUser = "alice"
		const badPass = "wrong"
		sub := []byte{0x01, byte(len(badUser))}
		sub = append(sub, []byte(badUser)...)
		sub = append(sub, byte(len(badPass)))
		sub = append(sub, []byte(badPass)...)
		if _, err := conn.Write(sub); err != nil {
			t.Fatalf("write sub-negotiation: %v", err)
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			t.Fatalf("read sub-negotiation reply: %v", err)
		}
		if authResp[1] == 0x00 {
			t.Errorf("auth STATUS = 0x00 (success); want failure")
		}
	})

	// AC5: query(status).socks5_enabled must reflect the actual auth
	// presence (true while password is set).
	t.Run("status_reflects_socks5_enabled", func(t *testing.T) {
		statusRes := h.MustOK(t, "query", map[string]any{"resource": "status"})
		var status struct {
			SOCKS5Enabled bool `json:"socks5_enabled"`
		}
		if err := json.Unmarshal([]byte(statusRes.Text), &status); err != nil {
			t.Fatalf("decode status: %v", err)
		}
		if !status.SOCKS5Enabled {
			t.Errorf("query(status).socks5_enabled = false; want true after socks5_auth=password")
		}
	})
}

// TestE2E_Configure_SOCKS5Auth_AppliesWithoutRestart starts the proxy with
// no auth, then uses the `configure` tool to install password auth at
// runtime. The next SOCKS5 handshake must require USERNAME_PASSWORD —
// proving the mutator reaches the in-flight negotiator without a
// listener restart (AC2).
func TestE2E_Configure_SOCKS5Auth_AppliesWithoutRestart(t *testing.T) {
	const wantUser, wantPass = "bob", "h3llo"

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		UpstreamProto: "http/1.1",
	})

	startRes := h.MustOK(t, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	proxyAddr, ok := startRes.Decoded["listen_addr"].(string)
	if !ok || proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr: %+v", startRes.Decoded)
	}

	// Confirm NO_AUTH currently works.
	upstreamHost, upstreamPort := splitHostPort(t, h.UpstreamTLS.URL)
	bridgePre := socks5DialNoAuth(t, proxyAddr, upstreamHost, upstreamPort)
	bridgePre.Close()

	// Mutate at runtime.
	h.MustOK(t, "configure", map[string]any{
		"socks5_auth": map[string]any{
			"method":   "password",
			"username": wantUser,
			"password": wantPass,
		},
	})

	// Now NO_AUTH must be rejected.
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if resp[1] != 0xFF {
		t.Errorf("after configure: NO_AUTH method selection = %x, want 0xFF", resp[1])
	}
	conn.Close()

	// And USERNAME_PASSWORD with the new creds must succeed.
	bridgePost := socks5DialAuth(t, proxyAddr, wantUser, wantPass, upstreamHost, upstreamPort)
	bridgePost.Close()
}

// TestE2E_ProxyStart_SOCKS5Auth_NoneToPasswordToNone exercises the
// USK-402 reset-on-restart contract: proxy_start without socks5_auth
// after a previous run with auth installed must clear the auth state.
// The lifecycle is: start (none) → stop → start (password) → stop →
// start (none). The final NO_AUTH handshake must succeed.
func TestE2E_ProxyStart_SOCKS5Auth_NoneToPasswordToNone(t *testing.T) {
	const wantUser, wantPass = "carol", "p4ss"

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		UpstreamProto: "http/1.1",
	})

	upstreamHost, upstreamPort := splitHostPort(t, h.UpstreamTLS.URL)

	// Phase 1: no auth.
	startRes := h.MustOK(t, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start (no auth): missing listen_addr: %+v", startRes.Decoded)
	}
	bridge := socks5DialNoAuth(t, proxyAddr, upstreamHost, upstreamPort)
	bridge.Close()
	h.MustOK(t, "proxy_stop", map[string]any{})

	// Phase 2: password auth.
	startRes = h.MustOK(t, "proxy_start", map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"socks5_auth":     "password",
		"socks5_username": wantUser,
		"socks5_password": wantPass,
	})
	proxyAddr, _ = startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start (password): missing listen_addr: %+v", startRes.Decoded)
	}
	bridge = socks5DialAuth(t, proxyAddr, wantUser, wantPass, upstreamHost, upstreamPort)
	bridge.Close()
	h.MustOK(t, "proxy_stop", map[string]any{})

	// Phase 3: no auth again — auth must be cleared by the omit
	// (USK-402 contract). NO_AUTH client must succeed.
	startRes = h.MustOK(t, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	proxyAddr, _ = startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start (reset): missing listen_addr: %+v", startRes.Decoded)
	}
	bridge = socks5DialNoAuth(t, proxyAddr, upstreamHost, upstreamPort)
	bridge.Close()

	// query(status).socks5_enabled must reflect the cleared state.
	statusRes := h.MustOK(t, "query", map[string]any{"resource": "status"})
	var status struct {
		SOCKS5Enabled bool `json:"socks5_enabled"`
	}
	if err := json.Unmarshal([]byte(statusRes.Text), &status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if status.SOCKS5Enabled {
		t.Errorf("query(status).socks5_enabled = true after clear; want false")
	}
}

// --- helpers ---

// splitHostPort parses an "https://host:port[/...]" URL string into host
// and port, t.Fatal'ing on any malformed input. Tailored for
// HarnessOptions.UpstreamProto="http/1.1" which always returns a TLS URL
// with explicit port.
func splitHostPort(t *testing.T, raw string) (string, int) {
	t.Helper()
	u, err := parseTestURL(raw)
	if err != nil {
		t.Fatalf("parse upstream URL %q: %v", raw, err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split host port %q: %v", u.Host, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port %q: %v", portStr, err)
	}
	return host, port
}

// parseTestURL is a tiny indirection so the test does not import net/url
// at the package top-level (it already pulls heavy transports). Inlines
// the standard library helper.
func parseTestURL(raw string) (*urlLite, error) {
	// Only need scheme://host:port for our purposes.
	const httpsPrefix = "https://"
	if !startsWith(raw, httpsPrefix) {
		return nil, fmt.Errorf("expected https:// prefix")
	}
	rest := raw[len(httpsPrefix):]
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' {
			return &urlLite{Host: rest[:i]}, nil
		}
	}
	return &urlLite{Host: rest}, nil
}

type urlLite struct {
	Host string
}

func startsWith(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}

// socks5DialNoAuth performs a SOCKS5 NO_AUTH handshake + CONNECT through
// proxyAddr to host:port and returns the bridged tunnel conn (raw bytes;
// caller is responsible for any TLS handshake on top). Test fatals on
// any wire-level error.
func socks5DialNoAuth(t *testing.T, proxyAddr, host string, port int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	// VER=5, NMETHODS=1, METHOD=NO_AUTH(0x00)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		t.Fatalf("write greeting: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		t.Fatalf("read method selection: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		conn.Close()
		t.Fatalf("method selection = %x, want NO_AUTH", resp)
	}
	socks5Connect(t, conn, host, port)
	return conn
}

// socks5DialAuth performs a SOCKS5 USERNAME_PASSWORD handshake +
// sub-negotiation + CONNECT through proxyAddr to host:port using the
// supplied credentials. Returns the bridged tunnel conn.
func socks5DialAuth(t *testing.T, proxyAddr, user, pass, host string, port int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	// VER=5, NMETHODS=1, METHOD=USERNAME_PASSWORD(0x02)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		conn.Close()
		t.Fatalf("write greeting: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	mResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, mResp); err != nil {
		conn.Close()
		t.Fatalf("read method selection: %v", err)
	}
	if mResp[1] != 0x02 {
		conn.Close()
		t.Fatalf("method selection = %x, want USERNAME_PASSWORD", mResp)
	}
	// Sub-negotiation.
	sub := []byte{0x01, byte(len(user))}
	sub = append(sub, []byte(user)...)
	sub = append(sub, byte(len(pass)))
	sub = append(sub, []byte(pass)...)
	if _, err := conn.Write(sub); err != nil {
		conn.Close()
		t.Fatalf("write sub-negotiation: %v", err)
	}
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		conn.Close()
		t.Fatalf("read sub-negotiation reply: %v", err)
	}
	if authResp[1] != 0x00 {
		conn.Close()
		t.Fatalf("sub-negotiation status = %x, want success", authResp[1])
	}
	socks5Connect(t, conn, host, port)
	return conn
}

// socks5Connect issues the CONNECT request on conn and reads the reply.
// The atyp argument is hardcoded to DOMAIN(0x03) for the test upstream
// (which is reachable via "127.0.0.1" or via a hostname; the upstream
// test server's host portion is always a literal IPv4, but DOMAIN is
// universally accepted by the negotiator and avoids a parsing branch).
func socks5Connect(t *testing.T, conn net.Conn, host string, port int) {
	t.Helper()
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(port))
	req = append(req, portBytes...)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read CONNECT reply: %v", err)
	}
	if reply[0] != 0x05 {
		t.Fatalf("CONNECT reply VER = %x", reply[0])
	}
	if reply[1] != 0x00 {
		t.Fatalf("CONNECT reply REP = %x, want success", reply[1])
	}
	// Reset deadline so the bridge phase is open-ended.
	_ = conn.SetReadDeadline(time.Time{})
}
