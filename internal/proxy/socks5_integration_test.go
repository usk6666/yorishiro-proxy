//go:build e2e

package proxy_test

import (
	"context"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	protosocks5 "github.com/usk6666/yorishiro-proxy/internal/protocol/socks5"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// socks5Connect performs a SOCKS5 CONNECT handshake without authentication.
func socks5Connect(conn net.Conn, targetAddr string) error {
	// 1. Greeting: version=5, 1 method, method=0 (no auth).
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fmt.Errorf("write greeting: %w", err)
	}

	// 2. Read server method selection.
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("read method selection: %w", err)
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		return fmt.Errorf("unexpected method selection: %x %x", buf[0], buf[1])
	}

	// 3. CONNECT request using IPv4 address type.
	host, port, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fmt.Errorf("split host port: %w", err)
	}
	portNum := 0
	fmt.Sscanf(port, "%d", &portNum)

	ip := net.ParseIP(host)
	var req []byte
	if ip4 := ip.To4(); ip4 != nil {
		// Use ATYP=1 (IPv4).
		req = []byte{0x05, 0x01, 0x00, 0x01}
		req = append(req, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		// Use ATYP=4 (IPv6).
		req = []byte{0x05, 0x01, 0x00, 0x04}
		req = append(req, ip6...)
	} else {
		// Use ATYP=3 (domain name).
		req = []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(portNum>>8), byte(portNum))
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("write connect request: %w", err)
	}

	// 4. Read reply.
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("read reply header: %w", err)
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("SOCKS5 CONNECT failed with reply code %d", reply[1])
	}

	// Skip the bind address based on address type.
	switch reply[3] {
	case 0x01: // IPv4
		skip := make([]byte, 4+2)
		io.ReadFull(conn, skip)
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		io.ReadFull(conn, lenBuf)
		skip := make([]byte, int(lenBuf[0])+2)
		io.ReadFull(conn, skip)
	case 0x04: // IPv6
		skip := make([]byte, 16+2)
		io.ReadFull(conn, skip)
	}

	return nil
}

// socks5ConnectWithAuth performs a SOCKS5 CONNECT handshake with username/password.
func socks5ConnectWithAuth(conn net.Conn, targetAddr, username, password string) error {
	// 1. Greeting: version=5, 1 method, method=2 (username/password).
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		return fmt.Errorf("write greeting: %w", err)
	}

	// 2. Read server method selection.
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("read method selection: %w", err)
	}
	if buf[0] != 0x05 || buf[1] != 0x02 {
		return fmt.Errorf("unexpected method selection: %x %x", buf[0], buf[1])
	}

	// 3. Username/password subnegotiation (RFC 1929).
	authReq := []byte{0x01, byte(len(username))}
	authReq = append(authReq, []byte(username)...)
	authReq = append(authReq, byte(len(password)))
	authReq = append(authReq, []byte(password)...)
	if _, err := conn.Write(authReq); err != nil {
		return fmt.Errorf("write auth request: %w", err)
	}

	// 4. Read auth reply.
	authReply := make([]byte, 2)
	if _, err := io.ReadFull(conn, authReply); err != nil {
		return fmt.Errorf("read auth reply: %w", err)
	}
	if authReply[1] != 0x00 {
		return fmt.Errorf("SOCKS5 auth failed with status %d", authReply[1])
	}

	// 5. CONNECT request using IPv4 address type.
	host, port, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fmt.Errorf("split host port: %w", err)
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
		return fmt.Errorf("write connect request: %w", err)
	}

	// 6. Read reply.
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("read reply header: %w", err)
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("SOCKS5 CONNECT failed with reply code %d", reply[1])
	}

	switch reply[3] {
	case 0x01:
		skip := make([]byte, 4+2)
		io.ReadFull(conn, skip)
	case 0x03:
		lenBuf := make([]byte, 1)
		io.ReadFull(conn, lenBuf)
		skip := make([]byte, int(lenBuf[0])+2)
		io.ReadFull(conn, skip)
	case 0x04:
		skip := make([]byte, 16+2)
		io.ReadFull(conn, skip)
	}

	return nil
}

func TestIntegration_SOCKS5_HTTPThroughProxy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start a test upstream HTTP server.
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &gohttp.Server{
		Handler: gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
			w.WriteHeader(gohttp.StatusOK)
			fmt.Fprintf(w, "hello from socks5 upstream")
		}),
	}
	go upstream.Serve(upstreamLn)
	defer upstream.Close()

	// Create store.
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// Start proxy with SOCKS5 handler.
	httpHandler := protohttp.NewHandler(store, nil, logger)
	socks5Handler := protosocks5.NewHandler(logger)
	detector := protocol.NewDetector(socks5Handler, httpHandler)
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:        "127.0.0.1:0",
		Detector:    detector,
		Logger:      logger,
		PeekTimeout: 2 * time.Second,
	})

	proxyCtx, proxyCancel := context.WithCancel(ctx)
	defer proxyCancel()
	go listener.Start(proxyCtx)
	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not become ready")
	}

	// Connect to proxy via SOCKS5.
	conn, err := net.DialTimeout("tcp", listener.Addr(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// SOCKS5 handshake to target upstream.
	if err := socks5Connect(conn, upstreamLn.Addr().String()); err != nil {
		t.Fatalf("socks5 connect: %v", err)
	}

	// Send HTTP request through the SOCKS5 tunnel.
	httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
		upstreamLn.Addr().String())
	if _, err := conn.Write([]byte(httpReq)); err != nil {
		t.Fatalf("write HTTP request: %v", err)
	}

	// Read HTTP response.
	respBytes, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	respStr := string(respBytes)

	if len(respStr) == 0 {
		t.Fatal("empty response")
	}
	if !strings.Contains(respStr, "200 OK") {
		t.Errorf("expected 200 OK in response, got: %s", respStr[:min(len(respStr), 100)])
	}
	if !strings.Contains(respStr, "hello from socks5 upstream") {
		t.Errorf("expected body in response, got: %s", respStr)
	}

	// Verify flow recording — SOCKS5 handler doesn't record flows directly,
	// but the post-handshake or relay should. Check for any recorded flow.
	conn.Close()
	var flows []*flow.Flow
	for i := 0; i < 30; i++ {
		time.Sleep(100 * time.Millisecond)
		flows, err = store.ListFlows(ctx, flow.ListOptions{Limit: 10})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(flows) > 0 {
			break
		}
	}
	if len(flows) == 0 {
		t.Errorf("expected flows to be recorded after SOCKS5 session, got 0")
	}
}

func TestIntegration_SOCKS5_WithAuth(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start TCP echo upstream.
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamLn.Close()

	go func() {
		for {
			conn, err := upstreamLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	// Create store.
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// SOCKS5 handler with authentication.
	socks5Handler := protosocks5.NewHandler(logger)
	socks5Handler.SetAuthenticator(staticAuth{"testuser", "testpass"})

	httpHandler := protohttp.NewHandler(store, nil, logger)
	detector := protocol.NewDetector(socks5Handler, httpHandler)
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:        "127.0.0.1:0",
		Detector:    detector,
		Logger:      logger,
		PeekTimeout: 2 * time.Second,
	})

	proxyCtx, proxyCancel := context.WithCancel(ctx)
	defer proxyCancel()
	go listener.Start(proxyCtx)
	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("proxy did not become ready")
	}

	// Test valid credentials.
	t.Run("valid_auth", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", listener.Addr(), 5*time.Second)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		defer conn.Close()

		if err := socks5ConnectWithAuth(conn, upstreamLn.Addr().String(), "testuser", "testpass"); err != nil {
			t.Fatalf("socks5 auth connect: %v", err)
		}

		// Send data through tunnel.
		msg := []byte("authenticated data")
		conn.Write(msg)

		buf := make([]byte, len(msg))
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read echo: %v", err)
		}
		if string(buf) != string(msg) {
			t.Errorf("echo = %q, want %q", buf, msg)
		}
	})

	// Test invalid credentials.
	t.Run("invalid_auth", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", listener.Addr(), 5*time.Second)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		defer conn.Close()

		err = socks5ConnectWithAuth(conn, upstreamLn.Addr().String(), "wrong", "creds")
		if err == nil {
			t.Fatal("expected auth failure, got nil")
		}
		if !strings.Contains(err.Error(), "auth failed") {
			t.Errorf("error = %v, want auth failure", err)
		}
	})
}

// staticAuth implements protosocks5.Authenticator for testing.
type staticAuth struct {
	username string
	password string
}

func (a staticAuth) Authenticate(username, password string) bool {
	return username == a.username && password == a.password
}
