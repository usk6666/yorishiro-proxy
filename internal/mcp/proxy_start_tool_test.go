package mcp

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/connector/transport"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// setupProxyStartTestSession creates an MCP client flow with Manager and
// PassthroughList for testing the proxy_start tool.
func setupProxyStartTestSession(t *testing.T, manager proxyManager, pl *connector.PassthroughList) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	var opts []ServerOption
	if pl != nil {
		opts = append(opts, WithPassthroughList(pl))
	}

	s := newServer(ctx, nil, nil, manager, opts...)
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

// callProxyStart invokes the proxy_start tool with the given arguments.
func callProxyStart(t *testing.T, cs *gomcp.ClientSession, args map[string]any) (*gomcp.CallToolResult, error) {
	t.Helper()
	return cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "proxy_start",
		Arguments: args,
	})
}

// unmarshalProxyStartResult extracts the proxyStartResult from a CallToolResult.
func unmarshalProxyStartResult(t *testing.T, result *gomcp.CallToolResult) proxyStartResult {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("expected non-empty content")
	}
	text, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected *TextContent, got %T", result.Content[0])
	}
	var out proxyStartResult
	if err := json.Unmarshal([]byte(text.Text), &out); err != nil {
		t.Fatalf("unmarshal proxyStartResult: %v", err)
	}
	return out
}

func TestProxyStart_WithListenAddr(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupProxyStartTestSession(t, manager, nil)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	out := unmarshalProxyStartResult(t, result)
	if out.Status != "running" {
		t.Errorf("status = %q, want %q", out.Status, "running")
	}
	if out.ListenAddr == "" {
		t.Error("expected non-empty listen_addr")
	}
}

func TestProxyStart_DefaultAddr(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupProxyStartTestSession(t, manager, nil)

	// Call without listen_addr to use default.
	result, err := callProxyStart(t, cs, nil)
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	if result.IsError {
		// Port 127.0.0.1:8080 might be in use; skip the test.
		t.Skipf("proxy_start with default addr failed (port likely in use): %v", result.Content)
	}

	out := unmarshalProxyStartResult(t, result)
	if out.Status != "running" {
		t.Errorf("status = %q, want %q", out.Status, "running")
	}
}

func TestProxyStart_AlreadyRunning(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupProxyStartTestSession(t, manager, nil)

	// First start.
	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("first CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected first start to succeed: %v", result.Content)
	}

	// Second start should fail.
	result, err = callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("second CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for double start")
	}
}

func TestProxyStart_NilManager(t *testing.T) {
	cs := setupProxyStartTestSession(t, nil, nil)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for nil manager")
	}
}

func TestProxyStart_NonLoopbackAddr(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupProxyStartTestSession(t, manager, nil)

	tests := []struct {
		name string
		addr string
	}{
		{name: "public IP", addr: "192.168.1.1:8080"},
		{name: "all interfaces", addr: "0.0.0.0:8080"},
		{name: "public IPv6", addr: "[::]:8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := callProxyStart(t, cs, map[string]any{
				"listen_addr": tt.addr,
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if !result.IsError {
				t.Fatalf("expected error for non-loopback address %q", tt.addr)
			}
		})
	}
}

func TestProxyStart_InvalidAddr(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupProxyStartTestSession(t, manager, nil)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": "not-a-valid-address",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for invalid address format")
	}
}

func TestProxyStart_WithTLSPassthrough(t *testing.T) {
	manager := newTestProxybuildManager(t)

	pl := connector.NewPassthroughList()
	cs := setupProxyStartTestSession(t, manager, pl)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"tls_passthrough": []any{"pinned-service.com", "*.googleapis.com"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	out := unmarshalProxyStartResult(t, result)
	if out.Status != "running" {
		t.Errorf("status = %q, want %q", out.Status, "running")
	}

	// Verify passthrough patterns were applied.
	if pl.Len() != 2 {
		t.Errorf("passthrough len = %d, want 2", pl.Len())
	}
	if !pl.Contains("pinned-service.com") {
		t.Error("expected passthrough to contain pinned-service.com")
	}
	if !pl.Contains("sub.googleapis.com") {
		t.Error("expected passthrough to match sub.googleapis.com via *.googleapis.com")
	}
}

func TestProxyStart_WithTLSPassthrough_EmptyPattern(t *testing.T) {
	manager := newTestProxybuildManager(t)

	pl := connector.NewPassthroughList()
	cs := setupProxyStartTestSession(t, manager, pl)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"tls_passthrough": []any{"valid.com", ""},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for empty passthrough pattern")
	}
}

func TestProxyStart_WithTLSPassthrough_NilPassthrough(t *testing.T) {
	manager := newTestProxybuildManager(t)

	// No passthrough configured on server.
	cs := setupProxyStartTestSession(t, manager, nil)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"tls_passthrough": []any{"example.com"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error when passthrough is not initialized")
	}
}

func TestProxyStart_WithAllConfig(t *testing.T) {
	manager := newTestProxybuildManager(t)

	pl := connector.NewPassthroughList()
	cs := setupProxyStartTestSession(t, manager, pl)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"tls_passthrough": []any{"pinned-service.com", "*.googleapis.com"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	out := unmarshalProxyStartResult(t, result)
	if out.Status != "running" {
		t.Errorf("status = %q, want %q", out.Status, "running")
	}
	if out.ListenAddr == "" {
		t.Error("expected non-empty listen_addr")
	}

	// Verify passthrough was applied.
	if pl.Len() != 2 {
		t.Errorf("passthrough len = %d, want 2", pl.Len())
	}
}

func TestProxyStart_LoopbackAddresses(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{name: "IPv4 loopback", addr: "127.0.0.1:0", wantErr: false},
		{name: "localhost", addr: "localhost:0", wantErr: false},
		{name: "IPv6 loopback", addr: "[::1]:0", wantErr: false},
		{name: "empty host", addr: ":0", wantErr: true},
		{name: "public IPv4", addr: "10.0.0.1:8080", wantErr: true},
		{name: "all interfaces IPv4", addr: "0.0.0.0:8080", wantErr: true},
		{name: "all interfaces IPv6", addr: "[::]:8080", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := newTestProxybuildManager(t)
			t.Cleanup(func() { manager.Stop(context.Background()) })

			cs := setupProxyStartTestSession(t, manager, nil)

			result, err := callProxyStart(t, cs, map[string]any{
				"listen_addr": tt.addr,
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}

			if tt.wantErr && !result.IsError {
				t.Fatalf("expected error for addr %q", tt.addr)
			}
			if !tt.wantErr && result.IsError {
				t.Fatalf("expected success for addr %q, got error: %v", tt.addr, result.Content)
			}
		})
	}
}

func TestProxyStart_PassthroughAppliedBeforeStart(t *testing.T) {
	// If passthrough validation fails, proxy should NOT start.
	manager := newTestProxybuildManager(t)

	pl := connector.NewPassthroughList()
	cs := setupProxyStartTestSession(t, manager, pl)

	// Empty passthrough pattern should prevent proxy from starting.
	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"tls_passthrough": []any{"valid.com", ""},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for empty passthrough pattern")
	}

	// Verify proxy did NOT start.
	running, _ := manager.Status()
	if running {
		t.Error("proxy should not be running after passthrough validation failure")
		manager.Stop(context.Background())
	}
}

// mockTCPHandler satisfies the tcpForwardHandler interface for testing.
type mockTCPHandler struct {
	forwards map[string]*config.ForwardConfig
}

func (h *mockTCPHandler) Name() string         { return "TCP" }
func (h *mockTCPHandler) Detect(_ []byte) bool { return true }
func (h *mockTCPHandler) Handle(_ context.Context, conn net.Conn) error {
	// Simple echo for testing.
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n > 0 {
		conn.Write(buf[:n])
	}
	return nil
}
func (h *mockTCPHandler) SetForwards(forwards map[string]*config.ForwardConfig) {
	if h.forwards == nil {
		h.forwards = make(map[string]*config.ForwardConfig)
	}
	for k, v := range forwards {
		h.forwards[k] = v
	}
}

func TestProxyStart_WithTCPForwards(t *testing.T) {
	manager := newTestProxybuildManager(t)

	// USK-711: the live data path no longer routes TCP forwards through the
	// legacy tcpForwardHandler interface — proxybuild.Manager owns the
	// per-port net.Listener and dispatches via the parent Stack's Pipeline.
	// We still attach a mock handler so the legacy connector wiring path
	// is exercised (no-op SetForwards call); the assertions below cover
	// the new path: TCPForwardAddrs reports a bound address and the
	// listener accepts a TCP dial.
	//
	// The forward target is a local listener (not 127.0.0.1:9999) so the
	// proxy's upstream dial succeeds — when the upstream is unreachable the
	// proxy closes the client conn immediately after accept, and a fast
	// kernel may surface that as ECONNRESET on the client's Dial. Using a
	// real reachable target keeps the assertion stable.
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	defer upstreamLn.Close()
	go func() {
		for {
			c, accErr := upstreamLn.Accept()
			if accErr != nil {
				return
			}
			// Hold the conn idle so the proxy session stays alive long
			// enough for the test's Dial+Close to complete.
			go func(c net.Conn) {
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				c.Close()
			}(c)
		}
	}()

	tcpHandler := &mockTCPHandler{}
	cs := setupProxyStartTestSessionWithTCPHandler(t, manager, nil, tcpHandler)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
		"tcp_forwards": map[string]any{
			"0": upstreamLn.Addr().String(),
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	out := unmarshalProxyStartResult(t, result)
	if out.Status != "running" {
		t.Errorf("status = %q, want %q", out.Status, "running")
	}
	if len(out.TCPForwards) == 0 {
		t.Error("expected non-empty tcp_forwards in result")
	}

	// Verify the forward listener is accessible (proxybuild.Manager bound
	// a real net.Listener for port "0").
	addrs := manager.TCPForwardAddrs()
	if addrs == nil {
		t.Fatal("expected non-nil TCPForwardAddrs")
	}
	fwdAddr := addrs["0"]
	if fwdAddr == "" {
		t.Fatal("expected non-empty forward address for port 0")
	}

	// Verify we can connect to the forward listener.
	conn, dialErr := net.DialTimeout("tcp", fwdAddr, 2*time.Second)
	if dialErr != nil {
		t.Fatalf("dial tcp forward: %v", dialErr)
	}
	conn.Close()
}

func TestProxyStart_WithTCPForwards_NilHandler(t *testing.T) {
	// USK-711: the live data path no longer needs an externally-supplied TCP
	// handler. proxybuild.Manager binds the per-port listener itself and
	// dispatches via the parent Stack's Pipeline. proxy_start with
	// tcp_forwards must therefore succeed even when no tcpForwardHandler is
	// wired into the MCP server (the previous "expected error" assertion
	// was a legacy-path constraint).
	manager := newTestProxybuildManager(t)

	// No TCP handler configured.
	cs := setupProxyStartTestSession(t, manager, nil)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
		"tcp_forwards": map[string]any{
			"0": "127.0.0.1:9999",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success without TCP handler, got error: %v", result.Content)
	}

	// Forward addr must be exposed via the manager.
	addrs := manager.TCPForwardAddrs()
	if addrs == nil || addrs["0"] == "" {
		t.Fatalf("expected TCPForwardAddrs[%q] non-empty after proxy_start, got %v", "0", addrs)
	}
}

func TestProxyStart_WithTCPForwards_InvalidTarget(t *testing.T) {
	manager := newTestProxybuildManager(t)

	tcpHandler := &mockTCPHandler{}
	cs := setupProxyStartTestSessionWithTCPHandler(t, manager, nil, tcpHandler)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
		"tcp_forwards": map[string]any{
			"0": "invalid-target", // missing port
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for invalid tcp_forwards target")
	}
}

// setupProxyStartTestSessionWithTCPHandler creates an MCP client flow with Manager,
// PassthroughList, and TCP handler for testing the proxy_start tool.
func setupProxyStartTestSessionWithTCPHandler(t *testing.T, manager proxyManager, pl *connector.PassthroughList, tcpHandler tcpForwardHandler) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	var opts []ServerOption
	if pl != nil {
		opts = append(opts, WithPassthroughList(pl))
	}
	if tcpHandler != nil {
		opts = append(opts, WithTCPHandler(tcpHandler))
	}

	s := newServer(ctx, nil, nil, manager, opts...)
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

func TestValidateLoopbackAddr(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		wantErr bool
	}{
		{name: "valid loopback", addr: "127.0.0.1:8080", wantErr: false},
		{name: "localhost", addr: "localhost:8080", wantErr: false},
		{name: "IPv6 loopback", addr: "[::1]:8080", wantErr: false},
		{name: "empty host", addr: ":8080", wantErr: true},
		{name: "public IP", addr: "192.168.1.1:8080", wantErr: true},
		{name: "all interfaces", addr: "0.0.0.0:8080", wantErr: true},
		{name: "invalid format", addr: "not-an-address", wantErr: true},
		{name: "missing port", addr: "127.0.0.1", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLoopbackAddr(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateLoopbackAddr(%q) error = %v, wantErr %v", tt.addr, err, tt.wantErr)
			}
		})
	}
}

// --- Tests for max_connections, peek_timeout_ms, request_timeout_ms ---

func TestProxyStart_WithMaxConnections(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupProxyStartTestSession(t, manager, nil)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"max_connections": 500,
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	out := unmarshalProxyStartResult(t, result)
	if out.Status != "running" {
		t.Errorf("status = %q, want %q", out.Status, "running")
	}

	// Verify max connections was set on the manager.
	if got := manager.MaxConnections(); got != 500 {
		t.Errorf("MaxConnections = %d, want 500", got)
	}
}

func TestProxyStart_WithPeekTimeoutMs(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupProxyStartTestSession(t, manager, nil)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"peek_timeout_ms": 5000,
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	if got := manager.PeekTimeout(); got != 5*time.Second {
		t.Errorf("PeekTimeout = %v, want 5s", got)
	}
}

func TestProxyStart_WithRequestTimeoutMs(t *testing.T) {
	manager := newTestProxybuildManager(t)

	// Create a mock request timeout setter to verify propagation.
	setter := &mockRequestTimeoutSetter{}
	cs := setupProxyStartTestSessionWithOptions(t, manager, nil,
		WithRequestTimeoutSetters(setter),
	)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr":        "127.0.0.1:0",
		"request_timeout_ms": 10000,
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	// Verify request timeout was propagated to the setter.
	if got := setter.RequestTimeout(); got != 10*time.Second {
		t.Errorf("RequestTimeout = %v, want 10s", got)
	}
}

func TestProxyStart_MaxConnections_Validation(t *testing.T) {
	tests := []struct {
		name    string
		value   int
		wantErr bool
	}{
		{name: "minimum valid", value: 1, wantErr: false},
		{name: "normal value", value: 1024, wantErr: false},
		{name: "maximum valid", value: 100000, wantErr: false},
		{name: "below minimum", value: 0, wantErr: true},
		{name: "negative", value: -1, wantErr: true},
		{name: "above maximum", value: 100001, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := newTestProxybuildManager(t)
			t.Cleanup(func() { manager.Stop(context.Background()) })

			cs := setupProxyStartTestSession(t, manager, nil)

			result, err := callProxyStart(t, cs, map[string]any{
				"listen_addr":     "127.0.0.1:0",
				"max_connections": tt.value,
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}

			if tt.wantErr && !result.IsError {
				t.Fatalf("expected error for max_connections=%d", tt.value)
			}
			if !tt.wantErr && result.IsError {
				t.Fatalf("expected success for max_connections=%d, got error: %v", tt.value, result.Content)
			}
		})
	}
}

func TestProxyStart_PeekTimeoutMs_Validation(t *testing.T) {
	tests := []struct {
		name    string
		value   int
		wantErr bool
	}{
		{name: "minimum valid", value: 100, wantErr: false},
		{name: "normal value", value: 30000, wantErr: false},
		{name: "maximum valid", value: 600000, wantErr: false},
		{name: "below minimum", value: 99, wantErr: true},
		{name: "zero", value: 0, wantErr: true},
		{name: "negative", value: -1, wantErr: true},
		{name: "above maximum", value: 600001, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := newTestProxybuildManager(t)
			t.Cleanup(func() { manager.Stop(context.Background()) })

			cs := setupProxyStartTestSession(t, manager, nil)

			result, err := callProxyStart(t, cs, map[string]any{
				"listen_addr":     "127.0.0.1:0",
				"peek_timeout_ms": tt.value,
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}

			if tt.wantErr && !result.IsError {
				t.Fatalf("expected error for peek_timeout_ms=%d", tt.value)
			}
			if !tt.wantErr && result.IsError {
				t.Fatalf("expected success for peek_timeout_ms=%d, got error: %v", tt.value, result.Content)
			}
		})
	}
}

func TestProxyStart_RequestTimeoutMs_Validation(t *testing.T) {
	tests := []struct {
		name    string
		value   int
		wantErr bool
	}{
		{name: "minimum valid", value: 100, wantErr: false},
		{name: "normal value", value: 60000, wantErr: false},
		{name: "maximum valid", value: 600000, wantErr: false},
		{name: "below minimum", value: 99, wantErr: true},
		{name: "zero", value: 0, wantErr: true},
		{name: "negative", value: -1, wantErr: true},
		{name: "above maximum", value: 600001, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := newTestProxybuildManager(t)
			t.Cleanup(func() { manager.Stop(context.Background()) })

			setter := &mockRequestTimeoutSetter{}
			cs := setupProxyStartTestSessionWithOptions(t, manager, nil,
				WithRequestTimeoutSetters(setter),
			)

			result, err := callProxyStart(t, cs, map[string]any{
				"listen_addr":        "127.0.0.1:0",
				"request_timeout_ms": tt.value,
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}

			if tt.wantErr && !result.IsError {
				t.Fatalf("expected error for request_timeout_ms=%d", tt.value)
			}
			if !tt.wantErr && result.IsError {
				t.Fatalf("expected success for request_timeout_ms=%d, got error: %v", tt.value, result.Content)
			}
		})
	}
}

func TestProxyStart_AllLimitsAndTimeouts(t *testing.T) {
	manager := newTestProxybuildManager(t)

	setter := &mockRequestTimeoutSetter{}
	cs := setupProxyStartTestSessionWithOptions(t, manager, nil,
		WithRequestTimeoutSetters(setter),
	)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr":        "127.0.0.1:0",
		"max_connections":    2048,
		"peek_timeout_ms":    15000,
		"request_timeout_ms": 90000,
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	out := unmarshalProxyStartResult(t, result)
	if out.Status != "running" {
		t.Errorf("status = %q, want %q", out.Status, "running")
	}

	if got := manager.MaxConnections(); got != 2048 {
		t.Errorf("MaxConnections = %d, want 2048", got)
	}
	if got := manager.PeekTimeout(); got != 15*time.Second {
		t.Errorf("PeekTimeout = %v, want 15s", got)
	}
	if got := setter.RequestTimeout(); got != 90*time.Second {
		t.Errorf("RequestTimeout = %v, want 90s", got)
	}
}

func TestProxyStart_InvalidMaxConnections_DoesNotStartProxy(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupProxyStartTestSession(t, manager, nil)

	// Invalid max_connections should prevent proxy from starting.
	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"max_connections": 0,
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for invalid max_connections")
	}

	// Verify proxy did NOT start.
	running, _ := manager.Status()
	if running {
		t.Error("proxy should not be running after validation failure")
		manager.Stop(context.Background())
	}
}

// setupProxyStartTestSessionWithOptions creates an MCP client session with
// arbitrary ServerOption values for testing.
func setupProxyStartTestSessionWithOptions(t *testing.T, manager proxyManager, pl *connector.PassthroughList, extraOpts ...ServerOption) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	var opts []ServerOption
	if pl != nil {
		opts = append(opts, WithPassthroughList(pl))
	}
	opts = append(opts, extraOpts...)

	s := newServer(ctx, nil, nil, manager, opts...)
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

func TestApplyTLSPassthrough(t *testing.T) {
	tests := []struct {
		name     string
		pl       *connector.PassthroughList
		patterns []string
		wantErr  bool
		wantLen  int
	}{
		{
			name:     "nil passthrough returns error",
			pl:       nil,
			patterns: []string{"example.com"},
			wantErr:  true,
		},
		{
			name:     "valid patterns",
			pl:       connector.NewPassthroughList(),
			patterns: []string{"example.com", "*.googleapis.com"},
			wantLen:  2,
		},
		{
			name:     "empty pattern returns error",
			pl:       connector.NewPassthroughList(),
			patterns: []string{"valid.com", ""},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mkServerFromLegacyDeps(legacyDeps{passthrough: tt.pl})
			err := s.applyTLSPassthrough(tt.patterns)
			if (err != nil) != tt.wantErr {
				t.Errorf("applyTLSPassthrough() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.pl != nil {
				if tt.pl.Len() != tt.wantLen {
					t.Errorf("passthrough len = %d, want %d", tt.pl.Len(), tt.wantLen)
				}
			}
		})
	}
}

// TestApplyTLSFingerprint_Vocabulary covers the shared fingerprint vocabulary
// at the MCP entry point (USK-1032). proxy_start / configure now accept the
// same spellings as the config file and the -tls-fingerprint CLI flag:
// case-insensitive, surrounding whitespace trimmed. The empty string stays
// rejected — both callers only reach here for an explicit override.
func TestApplyTLSFingerprint_Vocabulary(t *testing.T) {
	tests := []struct {
		name        string
		profile     string
		wantErr     bool
		wantUTLS    bool
		wantProfile transport.BrowserProfile
	}{
		{name: "firefox", profile: "firefox", wantUTLS: true, wantProfile: transport.ProfileFirefox},
		{name: "padded mixed case", profile: "  FireFox  ", wantUTLS: true, wantProfile: transport.ProfileFirefox},
		{name: "none opts out of uTLS", profile: "none"},
		{name: "padded none opts out of uTLS", profile: " none "},
		{name: "typo is rejected", profile: "firefx", wantErr: true},
		{name: "padded typo is rejected", profile: "  firefx  ", wantErr: true},
		{name: "empty is rejected", profile: "", wantErr: true},
		{name: "whitespace only is rejected", profile: "   ", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mkServerFromLegacyDeps(legacyDeps{})
			err := s.applyTLSFingerprint(tt.profile)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("applyTLSFingerprint(%q) = nil, want error", tt.profile)
				}
				if !strings.Contains(err.Error(), "invalid tls_fingerprint") {
					t.Errorf("error = %q, want substring %q", err, "invalid tls_fingerprint")
				}
				if !strings.Contains(err.Error(), config.TLSFingerprintNamesList()) {
					t.Errorf("error = %q, want it to enumerate %q", err, config.TLSFingerprintNamesList())
				}
				return
			}
			if err != nil {
				t.Fatalf("applyTLSFingerprint(%q): %v", tt.profile, err)
			}
			switch tr := s.connector.tlsTransport.(type) {
			case *transport.UTLSTransport:
				if !tt.wantUTLS {
					t.Fatalf("transport = UTLSTransport(%s), want StandardTransport", tr.Profile)
				}
				if tr.Profile != tt.wantProfile {
					t.Errorf("uTLS profile = %s, want %s", tr.Profile, tt.wantProfile)
				}
			case *transport.StandardTransport:
				if tt.wantUTLS {
					t.Fatal("transport = StandardTransport, want UTLSTransport")
				}
			default:
				t.Fatalf("unexpected transport type %T", tr)
			}
		})
	}
}

// Tests for proxy config file default merging via applyProxyDefaults.

func TestApplyProxyDefaults_NilDefaults(t *testing.T) {
	s := mkServerFromLegacyDeps(legacyDeps{proxyDefaults: nil})
	input := proxyStartInput{ListenAddr: "127.0.0.1:0"}

	s.applyProxyDefaults(&input)

	// Should not modify anything when no defaults are set.
	if input.ListenAddr != "127.0.0.1:0" {
		t.Errorf("ListenAddr = %q, want %q", input.ListenAddr, "127.0.0.1:0")
	}
}

func TestApplyProxyDefaults_ListenAddr(t *testing.T) {
	s := mkServerFromLegacyDeps(legacyDeps{
		proxyDefaults: &config.ProxyConfig{
			ListenAddr: "127.0.0.1:9090",
		},
	})

	t.Run("uses default when not specified", func(t *testing.T) {
		input := proxyStartInput{}
		s.applyProxyDefaults(&input)
		if input.ListenAddr != "127.0.0.1:9090" {
			t.Errorf("ListenAddr = %q, want %q", input.ListenAddr, "127.0.0.1:9090")
		}
	})

	t.Run("caller value takes precedence", func(t *testing.T) {
		input := proxyStartInput{ListenAddr: "127.0.0.1:7070"}
		s.applyProxyDefaults(&input)
		if input.ListenAddr != "127.0.0.1:7070" {
			t.Errorf("ListenAddr = %q, want %q", input.ListenAddr, "127.0.0.1:7070")
		}
	})
}

func TestApplyProxyDefaults_TLSPassthrough(t *testing.T) {
	s := mkServerFromLegacyDeps(legacyDeps{
		proxyDefaults: &config.ProxyConfig{
			TLSPassthrough: []string{"pinned.com", "*.googleapis.com"},
		},
	})

	t.Run("uses default when not specified", func(t *testing.T) {
		input := proxyStartInput{}
		s.applyProxyDefaults(&input)
		if len(input.TLSPassthrough) != 2 {
			t.Fatalf("TLSPassthrough = %v, want 2 entries", input.TLSPassthrough)
		}
		if input.TLSPassthrough[0] != "pinned.com" {
			t.Errorf("TLSPassthrough[0] = %q, want %q", input.TLSPassthrough[0], "pinned.com")
		}
	})

	t.Run("caller value takes precedence", func(t *testing.T) {
		input := proxyStartInput{TLSPassthrough: []string{"custom.com"}}
		s.applyProxyDefaults(&input)
		if len(input.TLSPassthrough) != 1 || input.TLSPassthrough[0] != "custom.com" {
			t.Errorf("TLSPassthrough = %v, want [custom.com]", input.TLSPassthrough)
		}
	})
}

func TestApplyProxyDefaults_TCPForwards(t *testing.T) {
	s := mkServerFromLegacyDeps(legacyDeps{
		proxyDefaults: &config.ProxyConfig{
			TCPForwards: map[string]*config.ForwardConfig{"3306": {Target: "db.example.com:3306", Protocol: "raw"}},
		},
	})

	t.Run("uses default when not specified", func(t *testing.T) {
		input := proxyStartInput{}
		s.applyProxyDefaults(&input)
		parsed, err := parseTCPForwardsAny(input.TCPForwards)
		if err != nil {
			t.Fatalf("parseTCPForwardsAny: %v", err)
		}
		fc := parsed["3306"]
		if fc == nil || fc.Target != "db.example.com:3306" {
			t.Errorf("TCPForwards[3306] = %v, want target db.example.com:3306", fc)
		}
	})

	t.Run("caller value takes precedence", func(t *testing.T) {
		input := proxyStartInput{
			TCPForwards: map[string]any{"5432": "pg.example.com:5432"},
		}
		s.applyProxyDefaults(&input)
		if _, ok := input.TCPForwards["3306"]; ok {
			t.Error("default TCPForwards[3306] should not be applied when caller specifies forwards")
		}
		parsed, err := parseTCPForwardsAny(input.TCPForwards)
		if err != nil {
			t.Fatalf("parseTCPForwardsAny: %v", err)
		}
		fc := parsed["5432"]
		if fc == nil || fc.Target != "pg.example.com:5432" {
			t.Errorf("TCPForwards[5432] = %v, want target pg.example.com:5432", fc)
		}
	})
}

// TestParseTCPForwardsAny_UpstreamTLS verifies the MCP input parser
// extracts the upstream_tls boolean field independently of the existing
// tls field, covering all four (tls, upstream_tls) combinations. USK-911.
func TestParseTCPForwardsAny_UpstreamTLS(t *testing.T) {
	cases := []struct {
		name     string
		input    map[string]any
		wantTLS  bool
		wantUTLS bool
	}{
		{
			name: "neither flag set",
			input: map[string]any{
				"9000": map[string]any{"target": "h:9000", "protocol": "raw"},
			},
			wantTLS:  false,
			wantUTLS: false,
		},
		{
			name: "tls only",
			input: map[string]any{
				"9000": map[string]any{"target": "h:9000", "protocol": "http", "tls": true},
			},
			wantTLS:  true,
			wantUTLS: false,
		},
		{
			name: "upstream_tls only",
			input: map[string]any{
				"9000": map[string]any{"target": "h:9000", "protocol": "http", "upstream_tls": true},
			},
			wantTLS:  false,
			wantUTLS: true,
		},
		{
			name: "both flags",
			input: map[string]any{
				"9000": map[string]any{"target": "h:9000", "protocol": "http", "tls": true, "upstream_tls": true},
			},
			wantTLS:  true,
			wantUTLS: true,
		},
		{
			name: "upstream_tls non-bool is ignored (defensive: field stays false)",
			input: map[string]any{
				"9000": map[string]any{"target": "h:9000", "protocol": "http", "upstream_tls": "yes"},
			},
			wantTLS:  false,
			wantUTLS: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := parseTCPForwardsAny(tc.input)
			if err != nil {
				t.Fatalf("parseTCPForwardsAny: %v", err)
			}
			fc := parsed["9000"]
			if fc == nil {
				t.Fatal("parsed[9000] is nil")
			}
			if fc.TLS != tc.wantTLS {
				t.Errorf("TLS = %v, want %v", fc.TLS, tc.wantTLS)
			}
			if fc.UpstreamTLS != tc.wantUTLS {
				t.Errorf("UpstreamTLS = %v, want %v", fc.UpstreamTLS, tc.wantUTLS)
			}
		})
	}
}

// TestParseTCPForwardsAny_UpstreamInsecureSkipVerify verifies the
// MCP input parser extracts the USK-918 tri-state
// `upstream_insecure_skip_verify` field from the
// map[string]any branch (the live MCP path), preserving the
// nil/true/false distinction and defensively ignoring non-bool input.
// The default-branch JSON round-trip path is already covered by
// TestForwardConfig_UnmarshalJSON_UpstreamInsecureSkipVerify in
// internal/config; this test pins the explicit field-extraction branch
// in parseTCPForwardsAny that the MCP go-sdk currently feeds.
func TestParseTCPForwardsAny_UpstreamInsecureSkipVerify(t *testing.T) {
	cases := []struct {
		name     string
		input    map[string]any
		wantNil  bool
		wantBool bool
	}{
		{
			// Field omitted → nil (inherit global default).
			name: "omitted -> nil (inherit global)",
			input: map[string]any{
				"9000": map[string]any{"target": "h:9000", "protocol": "http", "upstream_tls": true},
			},
			wantNil: true,
		},
		{
			// USK-918 motivating shape: explicit true → *true (skip verify).
			name: "true -> *true (skip verify)",
			input: map[string]any{
				"9000": map[string]any{
					"target": "h:9000", "protocol": "http",
					"upstream_tls": true, "upstream_insecure_skip_verify": true,
				},
			},
			wantNil:  false,
			wantBool: true,
		},
		{
			// Explicit false must survive parsing — distinguishes
			// "explicitly enforce" from "inherit global" (which may itself be true).
			name: "false -> *false (enforce verify)",
			input: map[string]any{
				"9000": map[string]any{
					"target": "h:9000", "protocol": "http",
					"upstream_tls": true, "upstream_insecure_skip_verify": false,
				},
			},
			wantNil:  false,
			wantBool: false,
		},
		{
			// Defensive: non-bool input is silently ignored (field stays nil),
			// matching the sibling upstream_tls non-bool behavior above.
			name: "non-bool is ignored -> nil",
			input: map[string]any{
				"9000": map[string]any{
					"target": "h:9000", "protocol": "http",
					"upstream_tls": true, "upstream_insecure_skip_verify": "yes",
				},
			},
			wantNil: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := parseTCPForwardsAny(tc.input)
			if err != nil {
				t.Fatalf("parseTCPForwardsAny: %v", err)
			}
			fc := parsed["9000"]
			if fc == nil {
				t.Fatal("parsed[9000] is nil")
			}
			if tc.wantNil {
				if fc.UpstreamInsecureSkipVerify != nil {
					t.Errorf("UpstreamInsecureSkipVerify = %v (non-nil), want nil",
						*fc.UpstreamInsecureSkipVerify)
				}
				return
			}
			if fc.UpstreamInsecureSkipVerify == nil {
				t.Fatal("UpstreamInsecureSkipVerify = nil, want non-nil")
			}
			if *fc.UpstreamInsecureSkipVerify != tc.wantBool {
				t.Errorf("UpstreamInsecureSkipVerify = %v, want %v",
					*fc.UpstreamInsecureSkipVerify, tc.wantBool)
			}
		})
	}
}

func TestApplyProxyDefaults_InterceptRules(t *testing.T) {
	rulesJSON := json.RawMessage(`[{
		"id": "default-rule",
		"enabled": true,
		"direction": "request",
		"conditions": {"host_pattern": ".*"}
	}]`)
	s := mkServerFromLegacyDeps(legacyDeps{
		proxyDefaults: &config.ProxyConfig{
			InterceptRules: rulesJSON,
		},
	})

	t.Run("uses default when not specified", func(t *testing.T) {
		input := proxyStartInput{}
		s.applyProxyDefaults(&input)
		if len(input.InterceptRules) != 1 {
			t.Fatalf("InterceptRules = %d, want 1", len(input.InterceptRules))
		}
		if input.InterceptRules[0].ID != "default-rule" {
			t.Errorf("InterceptRules[0].ID = %q, want %q", input.InterceptRules[0].ID, "default-rule")
		}
	})

	t.Run("caller value takes precedence", func(t *testing.T) {
		input := proxyStartInput{
			InterceptRules: []interceptRuleInput{{ID: "custom-rule"}},
		}
		s.applyProxyDefaults(&input)
		if len(input.InterceptRules) != 1 || input.InterceptRules[0].ID != "custom-rule" {
			t.Error("InterceptRules should not be overridden by defaults")
		}
	})
}

func TestApplyProxyDefaults_AutoTransform(t *testing.T) {
	transformJSON := json.RawMessage(`[{
		"id": "default-transform",
		"enabled": true,
		"priority": 1,
		"direction": "request",
		"conditions": {},
		"action": {"type": "set_header", "header": "X-Default", "value": "true"}
	}]`)
	s := mkServerFromLegacyDeps(legacyDeps{
		proxyDefaults: &config.ProxyConfig{
			AutoTransform: transformJSON,
		},
	})

	t.Run("uses default when not specified", func(t *testing.T) {
		input := proxyStartInput{}
		s.applyProxyDefaults(&input)
		if len(input.AutoTransform) != 1 {
			t.Fatalf("AutoTransform = %d, want 1", len(input.AutoTransform))
		}
		if input.AutoTransform[0].ID != "default-transform" {
			t.Errorf("AutoTransform[0].ID = %q, want %q", input.AutoTransform[0].ID, "default-transform")
		}
	})

	t.Run("caller value takes precedence", func(t *testing.T) {
		input := proxyStartInput{
			AutoTransform: []transformRuleInput{{ID: "custom-transform"}},
		}
		s.applyProxyDefaults(&input)
		if len(input.AutoTransform) != 1 || input.AutoTransform[0].ID != "custom-transform" {
			t.Error("AutoTransform should not be overridden by defaults")
		}
	})
}

func TestApplyProxyDefaults_InvalidJSON(t *testing.T) {
	// Invalid JSON in defaults should be silently ignored (not crash).
	s := mkServerFromLegacyDeps(legacyDeps{
		proxyDefaults: &config.ProxyConfig{
			InterceptRules: json.RawMessage(`[{invalid`),
			AutoTransform:  json.RawMessage(`[{invalid`),
		},
	})

	input := proxyStartInput{}
	s.applyProxyDefaults(&input)

	// All fields should remain at zero values.
	if len(input.InterceptRules) != 0 {
		t.Error("InterceptRules should be empty for invalid default JSON")
	}
	if len(input.AutoTransform) != 0 {
		t.Error("AutoTransform should be empty for invalid default JSON")
	}
}

func TestProxyStart_WithConfigDefaults_Integration(t *testing.T) {
	// Integration test: verify that config defaults are applied when proxy_start
	// is called without arguments via the MCP protocol.
	manager := newTestProxybuildManager(t)

	pl := connector.NewPassthroughList()

	proxyCfg := &config.ProxyConfig{
		ListenAddr:     "127.0.0.1:0",
		TLSPassthrough: []string{"default-pinned.com"},
	}

	ctx := context.Background()
	s := newServer(ctx, nil, nil, manager,
		WithPassthroughList(pl),
		WithProxyDefaults(proxyCfg),
	)

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

	// Call proxy_start without any arguments — defaults from config should apply.
	result, err := callProxyStart(t, cs, nil)
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	out := unmarshalProxyStartResult(t, result)
	if out.Status != "running" {
		t.Errorf("status = %q, want %q", out.Status, "running")
	}

	// Verify TLS passthrough defaults were applied.
	if pl.Len() != 1 {
		t.Errorf("passthrough len = %d, want 1", pl.Len())
	}
	if !pl.Contains("default-pinned.com") {
		t.Error("expected passthrough to contain default-pinned.com from config defaults")
	}
}

func TestProxyStart_CallerOverridesConfigDefaults_Integration(t *testing.T) {
	// Integration test: verify that caller arguments override config file defaults.
	manager := newTestProxybuildManager(t)

	pl := connector.NewPassthroughList()

	proxyCfg := &config.ProxyConfig{
		ListenAddr:     "127.0.0.1:0",
		TLSPassthrough: []string{"default-pinned.com"},
	}

	ctx := context.Background()
	s := newServer(ctx, nil, nil, manager,
		WithPassthroughList(pl),
		WithProxyDefaults(proxyCfg),
	)

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

	// Call proxy_start WITH explicit tls_passthrough — should override config defaults.
	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"tls_passthrough": []any{"caller-pinned.com"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	// Verify caller's passthrough was applied, NOT the default.
	if pl.Len() != 1 {
		t.Errorf("passthrough len = %d, want 1", pl.Len())
	}
	if !pl.Contains("caller-pinned.com") {
		t.Error("expected passthrough to contain caller-pinned.com")
	}
	if pl.Contains("default-pinned.com") {
		t.Error("default-pinned.com from config should not be applied when caller specifies passthrough")
	}
}

// TestProxyStart_ResetsSettingsOnRestart verifies that proxy_stop → proxy_start
// resets all configuration to defaults when the new proxy_start omits parameters.
// This is the regression test for USK-407.
func TestProxyStart_ResetsSettingsOnRestart(t *testing.T) {
	manager := newTestProxybuildManager(t)

	pl := connector.NewPassthroughList()

	cs := setupProxyStartTestSessionWithOptions(t, manager, pl)

	// Step 1: Start proxy with tls_passthrough configured.
	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"tls_passthrough": []any{"pinned.example.com"},
	})
	if err != nil {
		t.Fatalf("CallTool (first start): %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error on first start: %v", result.Content)
	}

	// Verify settings were applied.
	if pl.Len() == 0 {
		t.Fatal("expected passthrough list to be non-empty after first start")
	}

	// Step 2: Stop the proxy.
	stopResult, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_stop",
	})
	if err != nil {
		t.Fatalf("CallTool (proxy_stop): %v", err)
	}
	if stopResult.IsError {
		t.Fatalf("unexpected error on proxy_stop: %v", stopResult.Content)
	}

	// Step 3: Restart proxy without tls_passthrough.
	result, err = callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("CallTool (second start): %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error on second start: %v", result.Content)
	}

	// Step 4: Verify all settings were reset to defaults.
	if pl.Len() != 0 {
		t.Errorf("passthrough list length = %d, want 0 (reset to default) after restart without tls_passthrough", pl.Len())
	}
}

// TestProxyStart_ResetsInterceptAndTransformOnRestart verifies that intercept rules
// and auto-transform rules are cleared on proxy_start.
func TestProxyStart_ResetsInterceptAndTransformOnRestart(t *testing.T) {
	manager := newTestProxybuildManager(t)

	pl := connector.NewPassthroughList()
	httpInterceptEng := httprules.NewInterceptEngine()
	transformEng := httprules.NewTransformEngine()

	cs := setupProxyStartTestSessionWithOptions(t, manager, pl,
		WithHTTPInterceptEngine(httpInterceptEng),
		WithHTTPTransformEngine(transformEng),
	)

	// Step 1: Start proxy with intercept rules and transform rules.
	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
		"intercept_rules": []any{
			map[string]any{
				"id":        "rule-1",
				"enabled":   true,
				"protocol":  "http",
				"direction": "request",
				"http": map[string]any{
					"host_pattern": ".*\\.example\\.com",
				},
			},
		},
		"auto_transform": []any{
			map[string]any{
				"id":           "transform-1",
				"enabled":      true,
				"priority":     1,
				"direction":    "request",
				"host_pattern": ".*\\.example\\.com",
				"action_type":  "add_header",
				"header_name":  "X-Test",
				"header_value": "1",
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool (first start): %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error on first start: %v", result.Content)
	}

	// Verify rules were applied.
	if len(httpInterceptEng.Rules()) == 0 {
		t.Fatal("expected http intercept engine to have rules after first start")
	}
	if len(transformEng.Rules()) == 0 {
		t.Fatal("expected transform engine to have rules after first start")
	}

	// Step 2: Stop and restart without rules.
	stopResult, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_stop",
	})
	if err != nil {
		t.Fatalf("CallTool (proxy_stop): %v", err)
	}
	if stopResult.IsError {
		t.Fatalf("unexpected error on proxy_stop: %v", stopResult.Content)
	}

	result, err = callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("CallTool (second start): %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error on second start: %v", result.Content)
	}

	// Verify rules were cleared.
	if rs := httpInterceptEng.Rules(); len(rs) != 0 {
		t.Errorf("http intercept engine rule count = %d, want 0 after restart", len(rs))
	}
	if rs := transformEng.Rules(); len(rs) != 0 {
		t.Errorf("transform engine rule count = %d, want 0 after restart", len(rs))
	}
}

// TestProxyStart_ResetsLimitsAndTimeoutsOnRestart verifies that connection limits
// and timeouts are reset to defaults when proxy_start omits them.
func TestProxyStart_ResetsLimitsAndTimeoutsOnRestart(t *testing.T) {
	manager := newTestProxybuildManager(t)

	mockTimeout := &mockRequestTimeoutSetter{}

	cs := setupProxyStartTestSessionWithOptions(t, manager, nil,
		WithRequestTimeoutSetters(mockTimeout),
	)

	// Step 1: Start proxy with custom limits.
	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr":        "127.0.0.1:0",
		"max_connections":    256,
		"peek_timeout_ms":    5000,
		"request_timeout_ms": 10000,
	})
	if err != nil {
		t.Fatalf("CallTool (first start): %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error on first start: %v", result.Content)
	}

	// Verify custom values were set.
	if got := manager.MaxConnections(); got != 256 {
		t.Errorf("max_connections after first start = %d, want 256", got)
	}
	if got := mockTimeout.timeout; got != 10*time.Second {
		t.Errorf("request_timeout after first start = %v, want 10s", got)
	}

	// Step 2: Stop and restart without limits.
	stopResult, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_stop",
	})
	if err != nil {
		t.Fatalf("CallTool (proxy_stop): %v", err)
	}
	if stopResult.IsError {
		t.Fatalf("unexpected error on proxy_stop: %v", stopResult.Content)
	}

	result, err = callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("CallTool (second start): %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error on second start: %v", result.Content)
	}

	// Verify defaults were restored.
	if got := manager.MaxConnections(); got != 128 {
		t.Errorf("max_connections after restart = %d, want 128 (default)", got)
	}
	if got := manager.PeekTimeout(); got != 30*time.Second {
		t.Errorf("peek_timeout after restart = %v, want 30s (default)", got)
	}
	if got := mockTimeout.timeout; got != 60*time.Second {
		t.Errorf("request_timeout after restart = %v, want 60s (default)", got)
	}
}

// TestProxyStart_ResetsTLSFingerprintOnRestart verifies that TLS fingerprint
// is reset to "firefox" (default, USK-1013) when proxy_start omits
// tls_fingerprint. Start from chrome to prove the reset moves the profile back
// to the firefox default.
func TestProxyStart_ResetsTLSFingerprintOnRestart(t *testing.T) {
	manager := newTestProxybuildManager(t)

	mockFP := &mockTLSFingerprintSetter{}

	cs := setupProxyStartTestSessionWithOptions(t, manager, nil,
		WithTLSFingerprintSetter(mockFP),
	)

	// Step 1: Start proxy with custom fingerprint.
	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"tls_fingerprint": "chrome",
	})
	if err != nil {
		t.Fatalf("CallTool (first start): %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error on first start: %v", result.Content)
	}
	if mockFP.profile != "chrome" {
		t.Errorf("tls_fingerprint after first start = %q, want %q", mockFP.profile, "chrome")
	}

	// Step 2: Stop and restart without fingerprint.
	stopResult, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_stop",
	})
	if err != nil {
		t.Fatalf("CallTool (proxy_stop): %v", err)
	}
	if stopResult.IsError {
		t.Fatalf("unexpected error on proxy_stop: %v", stopResult.Content)
	}

	result, err = callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("CallTool (second start): %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error on second start: %v", result.Content)
	}

	// Verify fingerprint was reset to default.
	if mockFP.profile != "firefox" {
		t.Errorf("tls_fingerprint after restart = %q, want %q (default)", mockFP.profile, "firefox")
	}
}

// --- USK-861: tcp_forwards / listen_addr port collision ---

// TestValidateTCPForwardsAgainstListenAddr is a unit test for the
// cross-field collision check helper. It exercises the boundary cases
// directly — the MCP-level integration tests below cover the wired path.
func TestValidateTCPForwardsAgainstListenAddr(t *testing.T) {
	tests := []struct {
		name       string
		listenAddr string
		forwards   map[string]any
		wantErr    bool
		errSubstr  string
	}{
		{
			name:       "self-collision rejected",
			listenAddr: "127.0.0.1:9999",
			forwards:   map[string]any{"9999": "httpbin.org:80"},
			wantErr:    true,
			errSubstr:  "9999",
		},
		{
			name:       "self-collision error mentions listen_addr",
			listenAddr: "127.0.0.1:8080",
			forwards:   map[string]any{"8080": "upstream:443"},
			wantErr:    true,
			errSubstr:  "127.0.0.1:8080",
		},
		{
			name:       "non-colliding ports accepted",
			listenAddr: "127.0.0.1:8080",
			forwards:   map[string]any{"9999": "upstream:443"},
			wantErr:    false,
		},
		{
			name:       "multiple forwards one collides",
			listenAddr: "127.0.0.1:8080",
			forwards:   map[string]any{"9999": "a:1", "8080": "b:2"},
			wantErr:    true,
			errSubstr:  "8080",
		},
		{
			name:       "empty listen_addr short-circuits",
			listenAddr: "",
			forwards:   map[string]any{"8080": "upstream:443"},
			wantErr:    false,
		},
		{
			name:       "empty forwards short-circuits",
			listenAddr: "127.0.0.1:8080",
			forwards:   nil,
			wantErr:    false,
		},
		{
			name:       "ipv6 loopback collision",
			listenAddr: "[::1]:9999",
			forwards:   map[string]any{"9999": "upstream:80"},
			wantErr:    true,
			errSubstr:  "9999",
		},
		{
			name:       "malformed listen_addr defers to validateLoopbackAddr",
			listenAddr: "not-a-host-port",
			forwards:   map[string]any{"8080": "upstream:443"},
			wantErr:    false, // helper short-circuits; validateLoopbackAddr already rejected
		},
		{
			name:       "ephemeral listen_addr and ephemeral forward do not collide",
			listenAddr: "127.0.0.1:0",
			forwards:   map[string]any{"0": "upstream:443"},
			wantErr:    false, // kernel assigns distinct ephemeral ports
		},
		{
			name:       "ephemeral listen_addr with fixed forward port",
			listenAddr: "127.0.0.1:0",
			forwards:   map[string]any{"9999": "upstream:443"},
			wantErr:    false,
		},
		{
			name:       "fixed listen_addr with ephemeral forward port",
			listenAddr: "127.0.0.1:8080",
			forwards:   map[string]any{"0": "upstream:443"},
			wantErr:    false,
		},
		{
			// USK-861 F-1: non-canonical port literal with leading
			// zero must NOT bypass the collision check via string
			// inequality against the canonical "8080".
			name:       "leading-zero forward port still collides",
			listenAddr: "127.0.0.1:8080",
			forwards:   map[string]any{"08080": "upstream:443"},
			wantErr:    true,
			errSubstr:  "8080",
		},
		{
			// USK-861 F-1: explicit "+" sign on a forward port must
			// not bypass the check (strconv.Atoi parses "+8080" as
			// 8080).
			name:       "leading-plus forward port still collides",
			listenAddr: "127.0.0.1:8080",
			forwards:   map[string]any{"+8080": "upstream:443"},
			wantErr:    true,
			errSubstr:  "8080",
		},
		{
			// Non-integer port keys are deferred to
			// validateTCPForwardsConfig (via validatePortNumber);
			// the collision helper must NOT fabricate its own error
			// for malformed input.
			name:       "non-integer forward port deferred to format check",
			listenAddr: "127.0.0.1:8080",
			forwards:   map[string]any{"abc": "upstream:443"},
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTCPForwardsAgainstListenAddr(tt.listenAddr, tt.forwards)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateTCPForwardsAgainstListenAddr(%q, %v) error = %v, wantErr %v",
					tt.listenAddr, tt.forwards, err, tt.wantErr)
			}
			if tt.wantErr && tt.errSubstr != "" && err != nil {
				if !contains(err.Error(), tt.errSubstr) {
					t.Errorf("error %q does not contain expected substring %q", err.Error(), tt.errSubstr)
				}
			}
		})
	}
}

// TestProxyStart_TCPForwardSelfCollision_FailsFast verifies that proxy_start
// rejects an invocation whose tcp_forwards port equals the listen_addr port,
// before the listener is registered. The original footgun (USK-861) was that
// the listener got registered before the forward bind failure was surfaced,
// leaving a phantom entry that blocked recreating the listener under the
// same name.
func TestProxyStart_TCPForwardSelfCollision_FailsFast(t *testing.T) {
	// Pick a free port to use as both listen_addr and tcp_forwards key,
	// so the test does not race other tests on a fixed port.
	port := pickFreePortForTest(t)
	addr := net.JoinHostPort("127.0.0.1", port)

	manager := newTestProxybuildManager(t)
	cs := setupProxyStartTestSession(t, manager, nil)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": addr,
		"tcp_forwards": map[string]any{
			port: "127.0.0.1:1",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for self-colliding tcp_forwards/listen_addr")
	}

	// The error message must surface both the colliding port and the
	// listen_addr so an AI agent caller can self-diagnose.
	body := combineCallToolText(result)
	if !contains(body, port) {
		t.Errorf("error %q does not mention colliding port %q", body, port)
	}
	if !contains(body, addr) {
		t.Errorf("error %q does not mention listen_addr %q", body, addr)
	}

	// Critically: no listener must remain registered. The original
	// footgun was a phantom entry blocking recreate-by-same-name.
	if got := manager.ListenerCount(); got != 0 {
		t.Errorf("ListenerCount after rejected proxy_start = %d, want 0 (no phantom listener)", got)
	}
}

// TestProxyStart_TCPForwardExternalBindConflict_RollsBack verifies that when
// a tcp_forwards bind fails because an EXTERNAL holder owns the port, the
// listener is rolled back so the user can recreate under the same name.
// This covers the second arm of USK-861: the missing StopNamed call after
// startTCPForwards failure.
func TestProxyStart_TCPForwardExternalBindConflict_RollsBack(t *testing.T) {
	// Reserve a port from outside to provoke "address in use" inside
	// the proxy's StartTCPForwardsNamed call.
	occupied, release := reserveExternalPort(t)
	defer release()

	manager := newTestProxybuildManager(t)
	cs := setupProxyStartTestSession(t, manager, nil)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
		"tcp_forwards": map[string]any{
			occupied: "127.0.0.1:1",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for tcp_forwards bind conflict")
	}

	// The fix: parent listener must NOT remain registered after the
	// forward bind failure. Without StopNamed in the rollback path,
	// ListenerCount stays at 1 and the user cannot recreate the
	// listener under the same name.
	if got := manager.ListenerCount(); got != 0 {
		t.Errorf("ListenerCount after rolled-back proxy_start = %d, want 0", got)
	}
}

// TestProxyStart_RecreateAfterTCPForwardFailure_Succeeds verifies that
// after a tcp_forwards bind failure, the same listener name is reusable.
// This is the user-visible symptom of the rollback fix: prior to the fix,
// a second proxy_start with the same name returned "listener with this
// name already exists".
func TestProxyStart_RecreateAfterTCPForwardFailure_Succeeds(t *testing.T) {
	occupied, release := reserveExternalPort(t)
	defer release()

	const name = "raw"

	manager := newTestProxybuildManager(t)
	cs := setupProxyStartTestSession(t, manager, nil)

	// First call: forward bind conflict triggers rollback.
	result, err := callProxyStart(t, cs, map[string]any{
		"name":        name,
		"listen_addr": "127.0.0.1:0",
		"tcp_forwards": map[string]any{
			occupied: "127.0.0.1:1",
		},
	})
	if err != nil {
		t.Fatalf("first CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected first proxy_start to fail with bind conflict")
	}

	// Sanity: rollback already cleared the listener.
	if got := manager.ListenerCount(); got != 0 {
		t.Fatalf("ListenerCount after first (failed) proxy_start = %d, want 0", got)
	}

	// Release the externally-held port, then retry with a non-colliding
	// forward port under the same listener name. Without the rollback
	// fix, this returned "listener with this name already exists".
	release()

	result, err = callProxyStart(t, cs, map[string]any{
		"name":        name,
		"listen_addr": "127.0.0.1:0",
		"tcp_forwards": map[string]any{
			"0": "127.0.0.1:1", // ephemeral port; no collision possible
		},
	})
	if err != nil {
		t.Fatalf("second CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected second proxy_start to succeed after rollback: %s", combineCallToolText(result))
	}
	if got := manager.ListenerCount(); got != 1 {
		t.Errorf("ListenerCount after successful recreate = %d, want 1", got)
	}
}

// pickFreePortForTest acquires an ephemeral loopback port, releases it,
// and returns the port string. The brief window between Close and any
// subsequent bind is the same the OS provides to any caller; the test
// uses the freed port as both listen_addr and tcp_forwards key to
// trigger the self-collision check.
func pickFreePortForTest(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("acquire ephemeral port: %v", err)
	}
	_, port, err := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	return port
}

// reserveExternalPort listens on an ephemeral loopback port and returns
// the port string + a closer. The listener stays bound until the closer
// runs, so any in-test bind on that port observes "address already in use".
func reserveExternalPort(t *testing.T) (port string, release func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve external port: %v", err)
	}
	_, p, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		ln.Close()
		t.Fatalf("split host port: %v", err)
	}
	closed := false
	return p, func() {
		if closed {
			return
		}
		closed = true
		ln.Close()
	}
}

// combineCallToolText extracts all text content from a CallToolResult.
// IsError responses surface their error string as the first TextContent;
// joining all entries is robust to multi-content responses.
func combineCallToolText(result *gomcp.CallToolResult) string {
	if result == nil {
		return ""
	}
	out := ""
	for _, c := range result.Content {
		if tc, ok := c.(*gomcp.TextContent); ok {
			if out != "" {
				out += "\n"
			}
			out += tc.Text
		}
	}
	return out
}

// TestProxyStartTool_DescriptionGuidesToConfigure asserts that the
// proxy_start tool description contains the key phrases that steer AI
// agents away from the documented misuse pattern (USK-950): re-calling
// proxy_start to add a single rule, which silently resets every other
// session setting (USK-407 semantics).
//
// Each row asserts on a substring rather than the entire description so
// cosmetic edits do not cascade into test churn. The intent is to fail
// loudly if the reset-semantics warning or the configure-guidance phrase
// is removed.
func TestProxyStartTool_DescriptionGuidesToConfigure(t *testing.T) {
	desc := lookupToolDescription(t, "proxy_start")

	cases := []struct {
		name   string
		phrase string
	}{
		{
			name:   "reset semantics warning",
			phrase: "resets all prior settings",
		},
		{
			name:   "configure tool recommended for partial updates",
			phrase: "configure",
		},
		{
			name:   "misuse pattern named",
			phrase: "Do NOT call proxy_start repeatedly",
		},
		{
			name:   "links to help resource",
			phrase: "yorishiro://help/proxy_start",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(desc, tc.phrase) {
				t.Errorf("proxy_start Description missing key phrase %q\n--- description ---\n%s\n--- end ---",
					tc.phrase, desc)
			}
		})
	}
}

// TestConfigureTool_DescriptionPointsAtProxyStart asserts the reciprocal
// cross-reference (USK-950): the configure tool description names
// proxy_start as the tool whose reset semantics configure replaces for
// in-session partial updates. Substring assertions only — wording may be
// refined without breaking the test as long as the concept survives.
func TestConfigureTool_DescriptionPointsAtProxyStart(t *testing.T) {
	desc := lookupToolDescription(t, "configure")

	cases := []struct {
		name   string
		phrase string
	}{
		{
			name:   "names proxy_start as the alternative to NOT re-call",
			phrase: "proxy_start",
		},
		{
			name:   "describes configure as the partial-update path",
			phrase: "in-session partial updates",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(desc, tc.phrase) {
				t.Errorf("configure Description missing key phrase %q\n--- description ---\n%s\n--- end ---",
					tc.phrase, desc)
			}
		})
	}
}

// lookupToolDescription returns the Description field of the named MCP
// tool by listing tools through a fully-wired client session. Fails the
// test fatally when the tool is not registered.
func lookupToolDescription(t *testing.T, name string) string {
	t.Helper()
	manager := newTestProxybuildManager(t)
	cs := setupProxyStartTestSession(t, manager, nil)
	res, err := cs.ListTools(context.Background(), &gomcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	for _, tool := range res.Tools {
		if tool.Name == name {
			return tool.Description
		}
	}
	t.Fatalf("tool %q not found in ListTools result", name)
	return ""
}
