package socks5

import (
	"io"
	"log/slog"
	"net"
	"testing"
)

// mockAuth implements Authenticator for testing.
type mockAuth struct {
	validUser string
	validPass string
}

func (m *mockAuth) Authenticate(username, password string) bool {
	return username == m.validUser && password == m.validPass
}

func TestNegotiateMethod_NoAuth(t *testing.T) {
	h := NewHandler(slog.Default())

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var clientResp [2]byte
	done := make(chan error, 1)
	go func() {
		if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			done <- err
			return
		}
		_, err := client.Read(clientResp[:])
		done <- err
	}()

	method, err := h.negotiateMethod(server)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if method != methodNoAuth {
		t.Fatalf("expected NO AUTH (0x00), got 0x%02x", method)
	}

	if err := <-done; err != nil {
		t.Fatalf("client goroutine error: %v", err)
	}
	if clientResp[0] != 0x05 || clientResp[1] != 0x00 {
		t.Fatalf("expected [0x05, 0x00], got %v", clientResp)
	}
}

func TestNegotiateMethod_UsernamePassword(t *testing.T) {
	h := NewHandler(slog.Default())
	h.SetAuthenticator(&mockAuth{validUser: "user", validPass: "pass"})

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var clientResp [2]byte
	done := make(chan error, 1)
	go func() {
		if _, err := client.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			done <- err
			return
		}
		_, err := client.Read(clientResp[:])
		done <- err
	}()

	method, err := h.negotiateMethod(server)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if method != methodUsernamePassword {
		t.Fatalf("expected USERNAME/PASSWORD (0x02), got 0x%02x", method)
	}

	if err := <-done; err != nil {
		t.Fatalf("client goroutine error: %v", err)
	}
	if clientResp[0] != 0x05 || clientResp[1] != 0x02 {
		t.Fatalf("expected [0x05, 0x02], got %v", clientResp)
	}
}

func TestNegotiateMethod_AuthRequiredButNotOffered(t *testing.T) {
	h := NewHandler(slog.Default())
	h.SetAuthenticator(&mockAuth{validUser: "user", validPass: "pass"})

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Drain response in a separate goroutine to avoid pipe deadlock.
	go func() { io.Copy(io.Discard, client) }()
	go func() {
		client.Write([]byte{0x05, 0x01, 0x00})
	}()

	_, err := h.negotiateMethod(server)
	if err == nil {
		t.Fatal("expected error for no acceptable method")
	}
}

func TestNegotiateMethod_UnsupportedVersion(t *testing.T) {
	h := NewHandler(slog.Default())

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() { io.Copy(io.Discard, client) }()
	go func() {
		client.Write([]byte{0x04, 0x01, 0x00})
	}()

	_, err := h.negotiateMethod(server)
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestNegotiateMethod_ZeroMethods(t *testing.T) {
	h := NewHandler(slog.Default())

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() { io.Copy(io.Discard, client) }()
	go func() {
		client.Write([]byte{0x05, 0x00})
	}()

	_, err := h.negotiateMethod(server)
	if err == nil {
		t.Fatal("expected error for zero methods")
	}
}

func TestAuthenticateUserPass_Success(t *testing.T) {
	h := NewHandler(slog.Default())
	h.SetAuthenticator(&mockAuth{validUser: "admin", validPass: "secret"})

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var authResp [2]byte
	done := make(chan error, 1)
	go func() {
		req := []byte{0x01, 0x05}
		req = append(req, []byte("admin")...)
		req = append(req, 0x06)
		req = append(req, []byte("secret")...)
		if _, err := client.Write(req); err != nil {
			done <- err
			return
		}
		_, err := client.Read(authResp[:])
		done <- err
	}()

	err := h.authenticateUserPass(server)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("client goroutine error: %v", err)
	}
	if authResp[0] != authVersion || authResp[1] != authSuccess {
		t.Fatalf("expected [0x01, 0x00], got %v", authResp)
	}
}

func TestAuthenticateUserPass_Failure(t *testing.T) {
	h := NewHandler(slog.Default())
	h.SetAuthenticator(&mockAuth{validUser: "admin", validPass: "secret"})

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() { io.Copy(io.Discard, client) }()
	go func() {
		req := []byte{0x01, 0x05}
		req = append(req, []byte("admin")...)
		req = append(req, 0x05)
		req = append(req, []byte("wrong")...)
		client.Write(req)
	}()

	err := h.authenticateUserPass(server)
	if err == nil {
		t.Fatal("expected authentication failure")
	}
}

func TestAuthenticateUserPass_BadVersion(t *testing.T) {
	h := NewHandler(slog.Default())
	h.SetAuthenticator(&mockAuth{validUser: "admin", validPass: "secret"})

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() { io.Copy(io.Discard, client) }()
	go func() {
		req := []byte{0x02, 0x05}
		req = append(req, []byte("admin")...)
		req = append(req, 0x06)
		req = append(req, []byte("secret")...)
		client.Write(req)
	}()

	err := h.authenticateUserPass(server)
	if err == nil {
		t.Fatal("expected error for bad auth version")
	}
}

func TestAuthenticateUserPass_EmptyUsername(t *testing.T) {
	h := NewHandler(slog.Default())
	h.SetAuthenticator(&mockAuth{validUser: "admin", validPass: "secret"})

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() { io.Copy(io.Discard, client) }()
	go func() {
		req := []byte{0x01, 0x00, 0x06}
		req = append(req, []byte("secret")...)
		client.Write(req)
	}()

	err := h.authenticateUserPass(server)
	if err == nil {
		t.Fatal("expected error for empty username")
	}
}

func TestAuthenticateUserPass_EmptyPassword(t *testing.T) {
	h := NewHandler(slog.Default())
	h.SetAuthenticator(&mockAuth{validUser: "admin", validPass: ""})

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	var authResp [2]byte
	done := make(chan error, 1)
	go func() {
		req := []byte{0x01, 0x05}
		req = append(req, []byte("admin")...)
		req = append(req, 0x00)
		if _, err := client.Write(req); err != nil {
			done <- err
			return
		}
		_, err := client.Read(authResp[:])
		done <- err
	}()

	err := h.authenticateUserPass(server)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("client goroutine error: %v", err)
	}
	if authResp[1] != authSuccess {
		t.Fatalf("expected auth success, got 0x%02x", authResp[1])
	}
}
