//go:build e2e

package mcp

import (
	"context"
	"encoding/json"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// mockSOCKS5AuthSetter is a test double for the socks5AuthSetter interface.
type mockSOCKS5AuthSetter struct {
	passwordAuthCalled         bool
	clearAuthCalled            bool
	lastUsername               string
	lastPassword               string
	listenerPasswordAuthCalled bool
	listenerClearAuthCalled    bool
	lastListenerName           string
	lastListenerUsername       string
	lastListenerPassword       string
}

func (m *mockSOCKS5AuthSetter) SetPasswordAuth(username, password string) {
	m.passwordAuthCalled = true
	m.lastUsername = username
	m.lastPassword = password
}

func (m *mockSOCKS5AuthSetter) ClearAuth() {
	m.clearAuthCalled = true
}

func (m *mockSOCKS5AuthSetter) SetPasswordAuthForListener(listenerName, username, password string) {
	m.listenerPasswordAuthCalled = true
	m.lastListenerName = listenerName
	m.lastListenerUsername = username
	m.lastListenerPassword = password
}

func (m *mockSOCKS5AuthSetter) ClearAuthForListener(listenerName string) {
	m.listenerClearAuthCalled = true
	m.lastListenerName = listenerName
}

// setupSOCKS5TestSession creates an MCP client session with a SOCKS5 auth setter.
func setupSOCKS5TestSession(t *testing.T, manager *proxy.Manager, socks5Auth socks5AuthSetter) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	var opts []ServerOption
	if socks5Auth != nil {
		opts = append(opts, WithSOCKS5Handler(socks5Auth))
	}

	s := NewServer(ctx, nil, nil, manager, opts...)
	ct, st := gomcp.NewInMemoryTransports()

	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)

	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs
}

// --- SOCKS5 in validProtocols ---

func TestValidateProtocols_SOCKS5(t *testing.T) {
	err := validateProtocols([]string{"SOCKS5"})
	if err != nil {
		t.Errorf("validateProtocols(SOCKS5) returned error: %v", err)
	}
}

func TestValidateProtocols_AllIncludingSOCKS5(t *testing.T) {
	err := validateProtocols([]string{"HTTP/1.x", "HTTPS", "WebSocket", "HTTP/2", "gRPC", "SOCKS5", "TCP"})
	if err != nil {
		t.Errorf("validateProtocols(all) returned error: %v", err)
	}
}

// --- proxy_start SOCKS5 auth ---

func TestProxyStart_WithSOCKS5AuthPassword(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)
	mock := &mockSOCKS5AuthSetter{}
	cs := setupSOCKS5TestSession(t, manager, mock)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"socks5_auth":     "password",
		"socks5_username": "testuser",
		"socks5_password": "testpass",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %v", result.Content)
	}

	if !mock.listenerPasswordAuthCalled {
		t.Error("expected SetPasswordAuthForListener to be called")
	}
	if mock.lastListenerName != "default" {
		t.Errorf("listener name = %q, want %q", mock.lastListenerName, "default")
	}
	if mock.lastListenerUsername != "testuser" {
		t.Errorf("username = %q, want %q", mock.lastListenerUsername, "testuser")
	}
	if mock.lastListenerPassword != "testpass" {
		t.Errorf("password = %q, want %q", mock.lastListenerPassword, "testpass")
	}
}

func TestProxyStart_WithSOCKS5AuthNone(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)
	mock := &mockSOCKS5AuthSetter{}
	cs := setupSOCKS5TestSession(t, manager, mock)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
		"socks5_auth": "none",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %v", result.Content)
	}

	if !mock.listenerClearAuthCalled {
		t.Error("expected ClearAuthForListener to be called for 'none' auth")
	}
	if mock.lastListenerName != "default" {
		t.Errorf("listener name = %q, want %q", mock.lastListenerName, "default")
	}
}

func TestProxyStart_WithSOCKS5AuthPasswordMissingUsername(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)
	mock := &mockSOCKS5AuthSetter{}
	cs := setupSOCKS5TestSession(t, manager, mock)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"socks5_auth":     "password",
		"socks5_password": "testpass",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error when username is missing")
	}
}

func TestProxyStart_WithSOCKS5AuthPasswordMissingPassword(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)
	mock := &mockSOCKS5AuthSetter{}
	cs := setupSOCKS5TestSession(t, manager, mock)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"socks5_auth":     "password",
		"socks5_username": "testuser",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error when password is missing")
	}
}

func TestProxyStart_WithSOCKS5AuthInvalidMethod(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)
	mock := &mockSOCKS5AuthSetter{}
	cs := setupSOCKS5TestSession(t, manager, mock)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
		"socks5_auth": "kerberos",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for invalid auth method")
	}
}

func TestProxyStart_WithSOCKS5AuthPasswordNoHandler(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)
	// No SOCKS5 handler registered.
	cs := setupSOCKS5TestSession(t, manager, nil)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"socks5_auth":     "password",
		"socks5_username": "user",
		"socks5_password": "pass",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error when SOCKS5 handler is not initialized")
	}
}

// --- configure SOCKS5 auth ---

func TestConfigure_SOCKS5Auth_SetPassword(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)
	mock := &mockSOCKS5AuthSetter{}

	ctx := context.Background()
	s := NewServer(ctx, nil, nil, manager, WithSOCKS5Handler(mock))
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "configure",
		Arguments: map[string]any{
			"socks5_auth": map[string]any{
				"method":   "password",
				"username": "admin",
				"password": "secret",
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %v", result.Content)
	}

	if !mock.passwordAuthCalled {
		t.Error("expected SetPasswordAuth to be called")
	}
	if mock.lastUsername != "admin" {
		t.Errorf("username = %q, want %q", mock.lastUsername, "admin")
	}
	if mock.lastPassword != "secret" {
		t.Errorf("password = %q, want %q", mock.lastPassword, "secret")
	}

	// Verify the result contains socks5_auth.
	if len(result.Content) == 0 {
		t.Fatal("expected non-empty content")
	}
	text, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected *TextContent, got %T", result.Content[0])
	}
	var out configureResult
	if err := json.Unmarshal([]byte(text.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.SOCKS5Auth == nil {
		t.Fatal("expected socks5_auth in result")
	}
	if out.SOCKS5Auth.Method != "password" {
		t.Errorf("method = %q, want %q", out.SOCKS5Auth.Method, "password")
	}
}

func TestConfigure_SOCKS5Auth_ClearToNone(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)
	mock := &mockSOCKS5AuthSetter{}

	ctx := context.Background()
	s := NewServer(ctx, nil, nil, manager, WithSOCKS5Handler(mock))
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "configure",
		Arguments: map[string]any{
			"socks5_auth": map[string]any{
				"method": "none",
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %v", result.Content)
	}

	if !mock.clearAuthCalled {
		t.Error("expected ClearAuth to be called for 'none' auth")
	}
}

// --- query status and config with SOCKS5 ---

func TestQueryStatus_SOCKS5Enabled(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)
	mock := &mockSOCKS5AuthSetter{}

	ctx := context.Background()
	s := NewServer(ctx, nil, nil, manager, WithSOCKS5Handler(mock))
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name:      "query",
		Arguments: map[string]any{"resource": "status"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %v", result.Content)
	}

	text, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected *TextContent, got %T", result.Content[0])
	}
	var status queryStatusResult
	if err := json.Unmarshal([]byte(text.Text), &status); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !status.SOCKS5Enabled {
		t.Error("expected socks5_enabled to be true")
	}
}

func TestQueryStatus_SOCKS5NotEnabled(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)

	ctx := context.Background()
	// No SOCKS5 handler.
	s := NewServer(ctx, nil, nil, manager)
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name:      "query",
		Arguments: map[string]any{"resource": "status"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %v", result.Content)
	}

	text, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected *TextContent, got %T", result.Content[0])
	}
	var status queryStatusResult
	if err := json.Unmarshal([]byte(text.Text), &status); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if status.SOCKS5Enabled {
		t.Error("expected socks5_enabled to be false when no handler is registered")
	}
}

func TestQueryConfig_SOCKS5Enabled(t *testing.T) {
	logger := testutil.DiscardLogger()
	detector := &stubDetector{}
	manager := proxy.NewManager(detector, logger)
	mock := &mockSOCKS5AuthSetter{}

	ctx := context.Background()
	s := NewServer(ctx, nil, nil, manager, WithSOCKS5Handler(mock))
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name:      "query",
		Arguments: map[string]any{"resource": "config"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %v", result.Content)
	}

	text, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected *TextContent, got %T", result.Content[0])
	}
	var cfg queryConfigResult
	if err := json.Unmarshal([]byte(text.Text), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !cfg.SOCKS5Enabled {
		t.Error("expected socks5_enabled to be true in config")
	}
}

// --- protocol detection: SOCKS5 byte detection ---

func TestDetector_SOCKS5ByteDetection(t *testing.T) {
	// The SOCKS5 handler's Detect method recognizes 0x05 as first byte.
	// This is tested in the socks5 package, but we verify here that
	// SOCKS5 is a valid protocol name.
	if !validProtocols["SOCKS5"] {
		t.Error("SOCKS5 should be in validProtocols map")
	}
}

// --- applySOCKS5Auth unit tests ---

func TestApplySOCKS5Auth_None(t *testing.T) {
	mock := &mockSOCKS5AuthSetter{}
	s := &Server{deps: &deps{socks5AuthSetter: mock}}

	if err := s.applySOCKS5Auth("none", "", "", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.clearAuthCalled {
		t.Error("expected ClearAuth to be called")
	}
}

func TestApplySOCKS5Auth_NoneForListener(t *testing.T) {
	mock := &mockSOCKS5AuthSetter{}
	s := &Server{deps: &deps{socks5AuthSetter: mock}}

	if err := s.applySOCKS5Auth("none", "", "", "listener1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.listenerClearAuthCalled {
		t.Error("expected ClearAuthForListener to be called")
	}
	if mock.lastListenerName != "listener1" {
		t.Errorf("listener name = %q, want %q", mock.lastListenerName, "listener1")
	}
}

func TestApplySOCKS5Auth_Password(t *testing.T) {
	mock := &mockSOCKS5AuthSetter{}
	s := &Server{deps: &deps{socks5AuthSetter: mock}}

	if err := s.applySOCKS5Auth("password", "u", "p", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.passwordAuthCalled {
		t.Error("expected SetPasswordAuth to be called")
	}
}

func TestApplySOCKS5Auth_PasswordForListener(t *testing.T) {
	mock := &mockSOCKS5AuthSetter{}
	s := &Server{deps: &deps{socks5AuthSetter: mock}}

	if err := s.applySOCKS5Auth("password", "u", "p", "listener2"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mock.listenerPasswordAuthCalled {
		t.Error("expected SetPasswordAuthForListener to be called")
	}
	if mock.lastListenerName != "listener2" {
		t.Errorf("listener name = %q, want %q", mock.lastListenerName, "listener2")
	}
	if mock.lastListenerUsername != "u" {
		t.Errorf("username = %q, want %q", mock.lastListenerUsername, "u")
	}
	if mock.lastListenerPassword != "p" {
		t.Errorf("password = %q, want %q", mock.lastListenerPassword, "p")
	}
}

func TestApplySOCKS5Auth_PasswordMissingUsername(t *testing.T) {
	mock := &mockSOCKS5AuthSetter{}
	s := &Server{deps: &deps{socks5AuthSetter: mock}}

	err := s.applySOCKS5Auth("password", "", "p", "")
	if err == nil {
		t.Fatal("expected error for missing username")
	}
}

func TestApplySOCKS5Auth_PasswordMissingPassword(t *testing.T) {
	mock := &mockSOCKS5AuthSetter{}
	s := &Server{deps: &deps{socks5AuthSetter: mock}}

	err := s.applySOCKS5Auth("password", "u", "", "")
	if err == nil {
		t.Fatal("expected error for missing password")
	}
}

func TestApplySOCKS5Auth_PasswordNoHandler(t *testing.T) {
	s := &Server{deps: &deps{}}

	err := s.applySOCKS5Auth("password", "u", "p", "")
	if err == nil {
		t.Fatal("expected error when handler is nil")
	}
}

func TestApplySOCKS5Auth_InvalidMethod(t *testing.T) {
	mock := &mockSOCKS5AuthSetter{}
	s := &Server{deps: &deps{socks5AuthSetter: mock}}

	err := s.applySOCKS5Auth("gssapi", "", "", "")
	if err == nil {
		t.Fatal("expected error for invalid method")
	}
}
