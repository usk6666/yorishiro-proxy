//go:build e2e

package testconnector_test

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/testutil/testconnector"
)

// TestSOCKS5NoAuthToHTTPS drives an HTTPS GET through the connector via a
// SOCKS5 NO_AUTH handshake, proving that SOCKS5 → TunnelHandler → HTTPS MITM
// shares the same downstream path as CONNECT (Q3 proof).
func TestSOCKS5NoAuthToHTTPS(t *testing.T) {
	h := testconnector.Start(t)

	// Same TunnelHandler instance must back both protocols — we prove this
	// behaviorally: a SOCKS5 request lands in the same Store via RecordStep
	// as a CONNECT request would.
	resp := socks5HTTPSRoundTrip(t, h, "", "")
	if !strings.Contains(resp, " 200 ") {
		t.Fatalf("expected 200 via SOCKS5, got: %s", firstLine(resp))
	}
	if !strings.Contains(resp, "ok") {
		t.Fatalf("expected body ok, got: %s", resp)
	}
	waitForFlows(t, h.Store, "HTTP/1.x", 2, 3*time.Second)
}

// TestSOCKS5UsernamePasswordToHTTPS verifies the RFC 1929 sub-negotiation
// path with a correct credential pair.
func TestSOCKS5UsernamePasswordToHTTPS(t *testing.T) {
	auth := connector.NewStaticAuthenticator(map[string]string{"alice": "secret"})
	h := testconnector.Start(t, testconnector.WithAuthenticator(auth))

	resp := socks5HTTPSRoundTrip(t, h, "alice", "secret")
	if !strings.Contains(resp, " 200 ") {
		t.Fatalf("expected 200 via SOCKS5 userpass, got: %s", firstLine(resp))
	}
}

// TestSOCKS5AuthFailureReply verifies that a wrong credential pair triggers
// an RFC 1929 failure status and closes the tunnel without reaching the
// TunnelHandler.
func TestSOCKS5AuthFailureReply(t *testing.T) {
	auth := connector.NewStaticAuthenticator(map[string]string{"alice": "secret"})
	h := testconnector.Start(t, testconnector.WithAuthenticator(auth))

	conn, err := net.DialTimeout("tcp", h.ClientAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Greeting: offer username/password.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if sel[1] != 0x02 {
		t.Fatalf("method selection=%x, want 0x02", sel[1])
	}

	// Subnegotiation: bad password.
	authReq := []byte{0x01, 5}
	authReq = append(authReq, []byte("alice")...)
	authReq = append(authReq, 5)
	authReq = append(authReq, []byte("wrong")...)
	if _, err := conn.Write(authReq); err != nil {
		t.Fatalf("write auth: %v", err)
	}
	authReply := make([]byte, 2)
	if _, err := io.ReadFull(conn, authReply); err != nil {
		t.Fatalf("read auth reply: %v", err)
	}
	if authReply[0] != 0x01 || authReply[1] != 0x01 {
		t.Fatalf("expected auth failure (0x01 0x01), got %x %x", authReply[0], authReply[1])
	}
}

// TestSOCKS5TargetScopeBlockReply verifies that TargetScope denies produce
// a REP=0x02 reply and fire the OnBlock callback.
func TestSOCKS5TargetScopeBlockReply(t *testing.T) {
	denies := []connector.TargetRule{{Hostname: "127.0.0.1"}}
	h := testconnector.Start(t, testconnector.WithScopePolicy(nil, denies))

	conn, err := net.DialTimeout("tcp", h.ClientAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// NO_AUTH handshake.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		t.Fatalf("read selection: %v", err)
	}

	// Build CONNECT request to a blocked host.
	upstreamIP, upstreamPort, _ := net.SplitHostPort(h.UpstreamAddr)
	ip := net.ParseIP(upstreamIP).To4()
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip...)
	portNum := 0
	fmt.Sscanf(upstreamPort, "%d", &portNum)
	req = append(req, byte(portNum>>8), byte(portNum))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Expect REP=0x02 (connection not allowed).
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x02 {
		t.Fatalf("expected REP=0x02, got ver=0x%02x rep=0x%02x", reply[0], reply[1])
	}

	// OnBlock should have fired with the SOCKS5 protocol tag.
	select {
	case info := <-h.BlockCh:
		if info.Protocol != "SOCKS5" {
			t.Fatalf("block protocol=%q want SOCKS5", info.Protocol)
		}
		if info.Reason != "target_scope" {
			t.Fatalf("block reason=%q want target_scope", info.Reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for OnBlock callback")
	}
}

// socks5HTTPSRoundTrip runs a SOCKS5 handshake (with optional auth) against
// the connector, then performs a TLS handshake through the returned tunnel
// and sends a raw GET. Returns the full response.
func socks5HTTPSRoundTrip(t *testing.T, h *testconnector.Harness, user, password string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", h.ClientAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	if user == "" {
		if err := socks5HandshakeNoAuth(conn, h.UpstreamAddr); err != nil {
			conn.Close()
			t.Fatalf("socks5 no-auth: %v", err)
		}
	} else {
		if err := socks5HandshakeUserPass(conn, h.UpstreamAddr, user, password); err != nil {
			conn.Close()
			t.Fatalf("socks5 userpass: %v", err)
		}
	}

	// After a successful CONNECT reply, the tunnel is raw. Do a client TLS
	// handshake trusting the harness MITM CA, then drive an HTTP GET.
	host, _, _ := net.SplitHostPort(h.UpstreamAddr)
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: host,
		RootCAs:    h.CAPool,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	defer tlsConn.Close()

	req := fmt.Sprintf("GET /socks5 HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", h.UpstreamAddr)
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, _ := io.ReadAll(tlsConn)
	return string(resp)
}

func socks5HandshakeNoAuth(conn net.Conn, target string) error {
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		return fmt.Errorf("method selection=%x", buf)
	}
	return socks5WriteConnect(conn, target)
}

func socks5HandshakeUserPass(conn net.Conn, target, user, password string) error {
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		return err
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		return err
	}
	if sel[0] != 0x05 || sel[1] != 0x02 {
		return fmt.Errorf("method selection=%x", sel)
	}
	authReq := []byte{0x01, byte(len(user))}
	authReq = append(authReq, []byte(user)...)
	authReq = append(authReq, byte(len(password)))
	authReq = append(authReq, []byte(password)...)
	if _, err := conn.Write(authReq); err != nil {
		return err
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(conn, rep); err != nil {
		return err
	}
	if rep[1] != 0x00 {
		return fmt.Errorf("auth failure status=%x", rep[1])
	}
	return socks5WriteConnect(conn, target)
}

func socks5WriteConnect(conn net.Conn, target string) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	portNum := 0
	fmt.Sscanf(port, "%d", &portNum)
	ip := net.ParseIP(host)
	var req []byte
	if ip4 := ip.To4(); ip4 != nil {
		req = []byte{0x05, 0x01, 0x00, 0x01}
		req = append(req, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		req = []byte{0x05, 0x01, 0x00, 0x04}
		req = append(req, ip6...)
	} else {
		req = []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(portNum>>8), byte(portNum))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("connect reply=%x", reply[1])
	}
	// Skip BND.ADDR.
	switch reply[3] {
	case 0x01:
		skip := make([]byte, 4+2)
		_, _ = io.ReadFull(conn, skip)
	case 0x03:
		lenBuf := make([]byte, 1)
		_, _ = io.ReadFull(conn, lenBuf)
		skip := make([]byte, int(lenBuf[0])+2)
		_, _ = io.ReadFull(conn, skip)
	case 0x04:
		skip := make([]byte, 16+2)
		_, _ = io.ReadFull(conn, skip)
	}
	return nil
}

// firstLine returns the first line of a response string, for error messages.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// unused import guard for bufio if needed later.
var _ = bufio.NewReader
