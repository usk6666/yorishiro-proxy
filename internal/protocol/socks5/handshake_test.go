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

// --- Per-listener auth tests ---

func TestSetListenerAuthenticator_PerListenerOverride(t *testing.T) {
	h := NewHandler(slog.Default())

	// No default auth, no listener auth => getAuthForListener returns nil.
	if auth := h.getAuthForListener("listener1"); auth != nil {
		t.Fatal("expected nil auth for unknown listener")
	}

	// Set per-listener auth.
	mock := &mockAuth{validUser: "user1", validPass: "pass1"}
	h.SetListenerAuthenticator("listener1", mock)

	// getAuthForListener should return per-listener auth.
	if auth := h.getAuthForListener("listener1"); auth != mock {
		t.Fatal("expected per-listener auth")
	}

	// Different listener should fall back to default (nil).
	if auth := h.getAuthForListener("listener2"); auth != nil {
		t.Fatal("expected nil auth for different listener")
	}

	// Empty listener name should return default (nil).
	if auth := h.getAuthForListener(""); auth != nil {
		t.Fatal("expected nil auth for empty listener name")
	}
}

func TestSetListenerAuthenticator_FallbackToDefault(t *testing.T) {
	h := NewHandler(slog.Default())
	defaultAuth := &mockAuth{validUser: "default", validPass: "default"}
	h.SetAuthenticator(defaultAuth)

	// No per-listener override => falls back to default.
	if auth := h.getAuthForListener("listener1"); auth != defaultAuth {
		t.Fatal("expected default auth for listener without override")
	}

	// Set per-listener auth, should take precedence.
	listenerAuth := &mockAuth{validUser: "listener", validPass: "listener"}
	h.SetListenerAuthenticator("listener1", listenerAuth)
	if auth := h.getAuthForListener("listener1"); auth != listenerAuth {
		t.Fatal("expected per-listener auth to take precedence")
	}

	// Clear per-listener auth, should fall back to default.
	h.SetListenerAuthenticator("listener1", nil)
	if auth := h.getAuthForListener("listener1"); auth != defaultAuth {
		t.Fatal("expected fallback to default after clearing per-listener auth")
	}
}

func TestNegotiateMethodForListener_IndependentAuth(t *testing.T) {
	h := NewHandler(slog.Default())

	// Set auth only for listener1.
	h.SetListenerAuthenticator("listener1", &mockAuth{validUser: "u", validPass: "p"})

	// listener1 should require USERNAME/PASSWORD.
	client1, server1 := net.Pipe()
	defer client1.Close()
	defer server1.Close()

	done1 := make(chan struct{})
	go func() {
		defer close(done1)
		client1.Write([]byte{0x05, 0x02, 0x00, 0x02})
		resp := make([]byte, 2)
		client1.Read(resp)
	}()

	method, err := h.negotiateMethodForListener(server1, "listener1")
	if err != nil {
		t.Fatalf("listener1: unexpected error: %v", err)
	}
	if method != methodUsernamePassword {
		t.Fatalf("listener1: expected USERNAME/PASSWORD, got 0x%02x", method)
	}
	<-done1

	// listener2 (no auth override, no default) should allow NO AUTH.
	client2, server2 := net.Pipe()
	defer client2.Close()
	defer server2.Close()

	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		client2.Write([]byte{0x05, 0x01, 0x00})
		resp := make([]byte, 2)
		client2.Read(resp)
	}()

	method, err = h.negotiateMethodForListener(server2, "listener2")
	if err != nil {
		t.Fatalf("listener2: unexpected error: %v", err)
	}
	if method != methodNoAuth {
		t.Fatalf("listener2: expected NO AUTH, got 0x%02x", method)
	}
	<-done2
}

func TestAuthenticateUserPassForListener(t *testing.T) {
	h := NewHandler(slog.Default())

	// Set different auth for two listeners.
	h.SetListenerAuthenticator("listener1", &mockAuth{validUser: "user1", validPass: "pass1"})
	h.SetListenerAuthenticator("listener2", &mockAuth{validUser: "user2", validPass: "pass2"})

	// Test listener1 auth succeeds with its own credentials.
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan error, 1)
	go func() {
		req := []byte{0x01, 0x05}
		req = append(req, []byte("user1")...)
		req = append(req, 0x05)
		req = append(req, []byte("pass1")...)
		if _, err := client.Write(req); err != nil {
			done <- err
			return
		}
		resp := make([]byte, 2)
		_, err := client.Read(resp)
		done <- err
	}()

	username, err := h.authenticateUserPassForListener(server, "listener1")
	if err != nil {
		t.Fatalf("listener1 auth failed: %v", err)
	}
	if username != "user1" {
		t.Errorf("username = %q, want %q", username, "user1")
	}
	if err := <-done; err != nil {
		t.Fatalf("client error: %v", err)
	}

	// Test listener1 auth fails with listener2's credentials.
	client2, server2 := net.Pipe()
	defer client2.Close()
	defer server2.Close()

	go func() {
		io.Copy(io.Discard, client2)
	}()
	go func() {
		req := []byte{0x01, 0x05}
		req = append(req, []byte("user2")...)
		req = append(req, 0x05)
		req = append(req, []byte("pass2")...)
		client2.Write(req)
	}()

	_, err = h.authenticateUserPassForListener(server2, "listener1")
	if err == nil {
		t.Fatal("expected auth failure with wrong listener's credentials")
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
