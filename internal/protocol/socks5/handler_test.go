package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

func TestDetect(t *testing.T) {
	h := NewHandler(slog.Default())

	tests := []struct {
		name   string
		peek   []byte
		expect bool
	}{
		{"socks5 version", []byte{0x05, 0x01, 0x00}, true},
		{"socks4 version", []byte{0x04, 0x01, 0x00}, false},
		{"http GET", []byte("GET / HTTP/1.1"), false},
		{"empty", []byte{}, false},
		{"single byte socks5", []byte{0x05}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := h.Detect(tt.peek)
			if got != tt.expect {
				t.Fatalf("Detect(%v) = %v, want %v", tt.peek, got, tt.expect)
			}
		})
	}
}

func TestName(t *testing.T) {
	h := NewHandler(slog.Default())
	if h.Name() != "SOCKS5" {
		t.Fatalf("expected SOCKS5, got %s", h.Name())
	}
}

func TestHandle_FullConnect_NoAuth(t *testing.T) {
	// Start an echo server as the upstream target.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer echoLn.Close()

	go func() {
		conn, err := echoLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn) // echo
	}()

	h := NewHandler(slog.Default())
	// Use a dialer that always connects to our echo server.
	h.SetDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.DialTimeout("tcp", echoLn.Addr().String(), 5*time.Second)
	})

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Handle(ctx, server)
	}()

	// 1. Method negotiation (NO AUTH).
	client.Write([]byte{0x05, 0x01, 0x00})
	resp := make([]byte, 2)
	io.ReadFull(client, resp)
	if resp[1] != methodNoAuth {
		t.Fatalf("expected NO AUTH, got 0x%02x", resp[1])
	}

	// 2. CONNECT request to example.com:80.
	domain := "example.com"
	req := []byte{0x05, cmdConnect, 0x00, atypDomain, byte(len(domain))}
	req = append(req, []byte(domain)...)
	req = append(req, 0x00, 0x50) // port 80
	client.Write(req)

	// 3. Read success reply (10 bytes minimum for IPv4).
	reply := make([]byte, 10)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != replySuccess {
		t.Fatalf("expected success reply, got 0x%02x", reply[1])
	}

	// 4. Test data relay (echo).
	testData := []byte("hello socks5")
	client.Write(testData)

	echoBuf := make([]byte, len(testData))
	if _, err := io.ReadFull(client, echoBuf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(echoBuf, testData) {
		t.Fatalf("expected %q, got %q", testData, echoBuf)
	}

	client.Close()
	<-errCh
}

func TestHandle_FullConnect_WithAuth(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer echoLn.Close()

	go func() {
		conn, err := echoLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	}()

	h := NewHandler(slog.Default())
	h.SetAuthenticator(&mockAuth{validUser: "user", validPass: "pass"})
	h.SetDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.DialTimeout("tcp", echoLn.Addr().String(), 5*time.Second)
	})

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Handle(ctx, server)
	}()

	// 1. Method negotiation.
	client.Write([]byte{0x05, 0x01, 0x02}) // Only USERNAME/PASSWORD
	resp := make([]byte, 2)
	io.ReadFull(client, resp)
	if resp[1] != methodUsernamePassword {
		t.Fatalf("expected USERNAME/PASSWORD, got 0x%02x", resp[1])
	}

	// 2. Authentication.
	authReq := []byte{0x01, 0x04}
	authReq = append(authReq, []byte("user")...)
	authReq = append(authReq, 0x04)
	authReq = append(authReq, []byte("pass")...)
	client.Write(authReq)

	authResp := make([]byte, 2)
	io.ReadFull(client, authResp)
	if authResp[1] != authSuccess {
		t.Fatalf("expected auth success, got 0x%02x", authResp[1])
	}

	// 3. CONNECT.
	connectReq := []byte{0x05, cmdConnect, 0x00, atypIPv4, 127, 0, 0, 1, 0x00, 0x50}
	client.Write(connectReq)

	reply := make([]byte, 10)
	io.ReadFull(client, reply)
	if reply[1] != replySuccess {
		t.Fatalf("expected success reply, got 0x%02x", reply[1])
	}

	// 4. Test echo.
	testData := []byte("authenticated echo")
	client.Write(testData)
	echoBuf := make([]byte, len(testData))
	io.ReadFull(client, echoBuf)
	if !bytes.Equal(echoBuf, testData) {
		t.Fatalf("expected %q, got %q", testData, echoBuf)
	}

	client.Close()
	<-errCh
}

func TestHandle_TargetScopeBlocked(t *testing.T) {
	h := NewHandler(slog.Default())

	scope := proxy.NewTargetScope()
	scope.SetPolicyRules(
		[]proxy.TargetRule{{Hostname: "allowed.example.com"}},
		nil,
	)
	h.SetTargetScope(scope)
	h.SetDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, fmt.Errorf("should not be called")
	})

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Handle(ctx, server)
	}()

	// 1. Method negotiation.
	client.Write([]byte{0x05, 0x01, 0x00})
	resp := make([]byte, 2)
	io.ReadFull(client, resp)

	// 2. CONNECT to blocked host.
	domain := "blocked.example.com"
	req := []byte{0x05, cmdConnect, 0x00, atypDomain, byte(len(domain))}
	req = append(req, []byte(domain)...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, 443)
	req = append(req, portBuf...)
	client.Write(req)

	// 3. Should receive connection not allowed.
	reply := make([]byte, 10)
	io.ReadFull(client, reply)
	if reply[1] != replyConnectionNotAllowed {
		t.Fatalf("expected connection not allowed (0x02), got 0x%02x", reply[1])
	}

	err := <-errCh
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandle_PostHandshakeFunc(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer echoLn.Close()

	go func() {
		conn, err := echoLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	}()

	var capturedTarget string
	postHandshakeDone := make(chan struct{})
	h := NewHandler(slog.Default())
	h.SetDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.DialTimeout("tcp", echoLn.Addr().String(), 5*time.Second)
	})
	h.SetPostHandshake(func(ctx context.Context, clientConn, upstreamConn net.Conn, target string) error {
		capturedTarget = target
		close(postHandshakeDone)
		// Return immediately; the caller (Handle) will close upstream.
		return nil
	})

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Handle(ctx, server)
	}()

	// Handshake.
	client.Write([]byte{0x05, 0x01, 0x00})
	resp := make([]byte, 2)
	io.ReadFull(client, resp)

	domain := "target.example.com"
	req := []byte{0x05, cmdConnect, 0x00, atypDomain, byte(len(domain))}
	req = append(req, []byte(domain)...)
	req = append(req, 0x01, 0xBB) // port 443
	client.Write(req)

	reply := make([]byte, 10)
	io.ReadFull(client, reply)
	if reply[1] != replySuccess {
		t.Fatalf("expected success, got 0x%02x", reply[1])
	}

	// Wait for post-handshake to be called.
	select {
	case <-postHandshakeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("post-handshake not called within timeout")
	}

	<-errCh

	if capturedTarget != "target.example.com:443" {
		t.Fatalf("expected target target.example.com:443, got %s", capturedTarget)
	}
}

func TestHandle_AuthFailure(t *testing.T) {
	h := NewHandler(slog.Default())
	h.SetAuthenticator(&mockAuth{validUser: "user", validPass: "pass"})

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Handle(ctx, server)
	}()

	// Method negotiation.
	client.Write([]byte{0x05, 0x01, 0x02})
	resp := make([]byte, 2)
	io.ReadFull(client, resp)

	// Auth with wrong credentials.
	authReq := []byte{0x01, 0x05}
	authReq = append(authReq, []byte("wrong")...)
	authReq = append(authReq, 0x05)
	authReq = append(authReq, []byte("creds")...)
	client.Write(authReq)

	// Read auth failure response.
	authResp := make([]byte, 2)
	io.ReadFull(client, authResp)
	if authResp[1] != authFailure {
		t.Fatalf("expected auth failure, got 0x%02x", authResp[1])
	}

	err := <-errCh
	if err == nil {
		t.Fatal("expected error from auth failure")
	}
}

func TestHandle_DialFailure(t *testing.T) {
	h := NewHandler(slog.Default())
	h.SetDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, fmt.Errorf("connection refused")
	})

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Handle(ctx, server)
	}()

	// Handshake.
	client.Write([]byte{0x05, 0x01, 0x00})
	resp := make([]byte, 2)
	io.ReadFull(client, resp)

	// CONNECT.
	req := []byte{0x05, cmdConnect, 0x00, atypIPv4, 10, 0, 0, 1, 0x00, 0x50}
	client.Write(req)

	// Should get host unreachable reply.
	reply := make([]byte, 10)
	io.ReadFull(client, reply)
	if reply[1] != replyHostUnreachable {
		t.Fatalf("expected host unreachable (0x04), got 0x%02x", reply[1])
	}

	err := <-errCh
	if err == nil {
		t.Fatal("expected error from dial failure")
	}
}

func TestHandle_ContextCancellation(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer echoLn.Close()

	go func() {
		conn, err := echoLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	}()

	h := NewHandler(slog.Default())
	h.SetDialer(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.DialTimeout("tcp", echoLn.Addr().String(), 5*time.Second)
	})

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- h.Handle(ctx, server)
	}()

	// Complete handshake.
	client.Write([]byte{0x05, 0x01, 0x00})
	resp := make([]byte, 2)
	io.ReadFull(client, resp)

	req := []byte{0x05, cmdConnect, 0x00, atypIPv4, 127, 0, 0, 1, 0x00, 0x50}
	client.Write(req)

	reply := make([]byte, 10)
	io.ReadFull(client, reply)

	// Cancel context to trigger shutdown.
	cancel()

	err = <-errCh
	if err != nil && err != context.Canceled {
		t.Fatalf("expected nil or context.Canceled, got %v", err)
	}
}
