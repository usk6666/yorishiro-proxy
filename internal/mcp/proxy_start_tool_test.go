package mcp

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/rules"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// setupProxyStartTestSession creates an MCP client flow with Manager, CaptureScope,
// and PassthroughList for testing the proxy_start tool.
func setupProxyStartTestSession(t *testing.T, manager proxyManager, scope *proxy.CaptureScope, pl *proxy.PassthroughList) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	var opts []ServerOption
	if scope != nil {
		opts = append(opts, WithCaptureScope(scope))
	}
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

	cs := setupProxyStartTestSession(t, manager, nil, nil)

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

	cs := setupProxyStartTestSession(t, manager, nil, nil)

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

	cs := setupProxyStartTestSession(t, manager, nil, nil)

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
	cs := setupProxyStartTestSession(t, nil, nil, nil)

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

	cs := setupProxyStartTestSession(t, manager, nil, nil)

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

	cs := setupProxyStartTestSession(t, manager, nil, nil)

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

func TestProxyStart_WithCaptureScope(t *testing.T) {
	manager := newTestProxybuildManager(t)

	scope := proxy.NewCaptureScope()
	cs := setupProxyStartTestSession(t, manager, scope, nil)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
		"capture_scope": map[string]any{
			"includes": []any{
				map[string]any{"hostname": "*.target.com", "url_prefix": "/api/", "method": "POST"},
			},
			"excludes": []any{
				map[string]any{"hostname": "cdn.example.com"},
			},
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

	// Verify scope was applied.
	includes, excludes := scope.Rules()
	if len(includes) != 1 {
		t.Fatalf("scope includes = %d, want 1", len(includes))
	}
	if includes[0].Hostname != "*.target.com" {
		t.Errorf("includes[0].hostname = %q, want %q", includes[0].Hostname, "*.target.com")
	}
	if includes[0].URLPrefix != "/api/" {
		t.Errorf("includes[0].url_prefix = %q, want %q", includes[0].URLPrefix, "/api/")
	}
	if includes[0].Method != "POST" {
		t.Errorf("includes[0].method = %q, want %q", includes[0].Method, "POST")
	}
	if len(excludes) != 1 {
		t.Fatalf("scope excludes = %d, want 1", len(excludes))
	}
	if excludes[0].Hostname != "cdn.example.com" {
		t.Errorf("excludes[0].hostname = %q, want %q", excludes[0].Hostname, "cdn.example.com")
	}
}

func TestProxyStart_WithCaptureScope_IncludesOnly(t *testing.T) {
	manager := newTestProxybuildManager(t)

	scope := proxy.NewCaptureScope()
	cs := setupProxyStartTestSession(t, manager, scope, nil)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
		"capture_scope": map[string]any{
			"includes": []any{
				map[string]any{"hostname": "example.com"},
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	includes, excludes := scope.Rules()
	if len(includes) != 1 {
		t.Fatalf("includes = %d, want 1", len(includes))
	}
	if len(excludes) != 0 {
		t.Errorf("excludes = %d, want 0", len(excludes))
	}
}

func TestProxyStart_WithCaptureScope_ExcludesOnly(t *testing.T) {
	manager := newTestProxybuildManager(t)

	scope := proxy.NewCaptureScope()
	cs := setupProxyStartTestSession(t, manager, scope, nil)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
		"capture_scope": map[string]any{
			"excludes": []any{
				map[string]any{"hostname": "ads.example.com"},
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	includes, excludes := scope.Rules()
	if len(includes) != 0 {
		t.Errorf("includes = %d, want 0", len(includes))
	}
	if len(excludes) != 1 {
		t.Fatalf("excludes = %d, want 1", len(excludes))
	}
}

func TestProxyStart_WithCaptureScope_EmptyRuleError(t *testing.T) {
	manager := newTestProxybuildManager(t)

	scope := proxy.NewCaptureScope()
	cs := setupProxyStartTestSession(t, manager, scope, nil)

	// Include rule with no fields set should error.
	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
		"capture_scope": map[string]any{
			"includes": []any{
				map[string]any{},
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for empty include rule")
	}
}

func TestProxyStart_WithCaptureScope_EmptyExcludeRuleError(t *testing.T) {
	manager := newTestProxybuildManager(t)

	scope := proxy.NewCaptureScope()
	cs := setupProxyStartTestSession(t, manager, scope, nil)

	// Exclude rule with no fields set should error.
	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
		"capture_scope": map[string]any{
			"excludes": []any{
				map[string]any{},
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for empty exclude rule")
	}
}

func TestProxyStart_WithCaptureScope_NilScope(t *testing.T) {
	manager := newTestProxybuildManager(t)

	// No scope configured on server.
	cs := setupProxyStartTestSession(t, manager, nil, nil)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
		"capture_scope": map[string]any{
			"includes": []any{
				map[string]any{"hostname": "example.com"},
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error when scope is not initialized")
	}
}

func TestProxyStart_WithTLSPassthrough(t *testing.T) {
	manager := newTestProxybuildManager(t)

	pl := proxy.NewPassthroughList()
	cs := setupProxyStartTestSession(t, manager, nil, pl)

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

	pl := proxy.NewPassthroughList()
	cs := setupProxyStartTestSession(t, manager, nil, pl)

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
	cs := setupProxyStartTestSession(t, manager, nil, nil)

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

	scope := proxy.NewCaptureScope()
	pl := proxy.NewPassthroughList()
	cs := setupProxyStartTestSession(t, manager, scope, pl)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
		"capture_scope": map[string]any{
			"includes": []any{
				map[string]any{"hostname": "*.target.com", "url_prefix": "/api/", "method": "POST"},
			},
			"excludes": []any{
				map[string]any{"hostname": "cdn.example.com"},
			},
		},
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

	// Verify scope was applied.
	includes, excludes := scope.Rules()
	if len(includes) != 1 {
		t.Errorf("scope includes = %d, want 1", len(includes))
	}
	if len(excludes) != 1 {
		t.Errorf("scope excludes = %d, want 1", len(excludes))
	}

	// Verify passthrough was applied.
	if pl.Len() != 2 {
		t.Errorf("passthrough len = %d, want 2", pl.Len())
	}
}

func TestProxyStart_WithEmptyCaptureScope(t *testing.T) {
	manager := newTestProxybuildManager(t)

	scope := proxy.NewCaptureScope()
	// Pre-set some rules to verify empty scope object does not clear them.
	scope.SetRules(
		[]proxy.ScopeRule{{Hostname: "existing.com"}},
		nil,
	)

	cs := setupProxyStartTestSession(t, manager, scope, nil)

	// Pass capture_scope as an empty object (no includes or excludes).
	// The scope with empty includes/excludes should set empty rules.
	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr":   "127.0.0.1:0",
		"capture_scope": map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	// Empty capture_scope object should set empty rules (clear previous).
	includes, excludes := scope.Rules()
	if len(includes) != 0 {
		t.Errorf("scope includes = %d, want 0 (empty scope should clear)", len(includes))
	}
	if len(excludes) != 0 {
		t.Errorf("scope excludes = %d, want 0 (empty scope should clear)", len(excludes))
	}
}

func TestProxyStart_WithoutCaptureScope(t *testing.T) {
	manager := newTestProxybuildManager(t)

	scope := proxy.NewCaptureScope()
	// Pre-set some rules to verify that proxy_start resets them when
	// capture_scope is omitted (USK-407: proxy_start resets all settings).
	scope.SetRules(
		[]proxy.ScopeRule{{Hostname: "existing.com"}},
		nil,
	)

	cs := setupProxyStartTestSession(t, manager, scope, nil)

	// Omit capture_scope entirely — existing rules should be cleared
	// because proxy_start resets all settings to defaults.
	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	includes, _ := scope.Rules()
	if len(includes) != 0 {
		t.Errorf("scope includes = %d, want 0 (proxy_start should reset scope to default)", len(includes))
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

			cs := setupProxyStartTestSession(t, manager, nil, nil)

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

func TestProxyStart_ScopeAppliedBeforeStart(t *testing.T) {
	// Verify that scope and passthrough are configured before the proxy starts.
	// If scope validation fails, proxy should NOT start.
	manager := newTestProxybuildManager(t)

	scope := proxy.NewCaptureScope()
	cs := setupProxyStartTestSession(t, manager, scope, nil)

	// Invalid scope rule should prevent proxy from starting.
	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
		"capture_scope": map[string]any{
			"includes": []any{
				map[string]any{}, // empty rule — invalid
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for invalid scope rule")
	}

	// Verify proxy did NOT start.
	running, _ := manager.Status()
	if running {
		t.Error("proxy should not be running after scope validation failure")
		manager.Stop(context.Background())
	}
}

func TestProxyStart_PassthroughAppliedBeforeStart(t *testing.T) {
	// If passthrough validation fails, proxy should NOT start.
	manager := newTestProxybuildManager(t)

	pl := proxy.NewPassthroughList()
	cs := setupProxyStartTestSession(t, manager, nil, pl)

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
	t.Skip("proxybuild.Manager returns ErrTCPForwardsNotSupported; TCP forward orchestration is owned by a USK-697 follow-up")
	manager := newTestProxybuildManager(t)

	tcpHandler := &mockTCPHandler{}
	cs := setupProxyStartTestSessionWithTCPHandler(t, manager, nil, nil, tcpHandler)

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
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	out := unmarshalProxyStartResult(t, result)
	if out.Status != "running" {
		t.Errorf("status = %q, want %q", out.Status, "running")
	}
	if len(out.TCPForwards) == 0 {
		t.Error("expected non-empty tcp_forwards in result")
	}

	// Verify forward mappings were set on the handler.
	fc := tcpHandler.forwards["0"]
	if fc == nil || fc.Target != "127.0.0.1:9999" {
		var got string
		if fc != nil {
			got = fc.Target
		}
		t.Errorf("tcpHandler forwards[0].Target = %q, want %q", got, "127.0.0.1:9999")
	}

	// Verify the forward listener is accessible.
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
	manager := newTestProxybuildManager(t)

	// No TCP handler configured.
	cs := setupProxyStartTestSession(t, manager, nil, nil)

	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
		"tcp_forwards": map[string]any{
			"0": "127.0.0.1:9999",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error when TCP handler is not initialized")
	}
}

func TestProxyStart_WithTCPForwards_InvalidTarget(t *testing.T) {
	manager := newTestProxybuildManager(t)

	tcpHandler := &mockTCPHandler{}
	cs := setupProxyStartTestSessionWithTCPHandler(t, manager, nil, nil, tcpHandler)

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
// CaptureScope, PassthroughList, and TCP handler for testing the proxy_start tool.
func setupProxyStartTestSessionWithTCPHandler(t *testing.T, manager proxyManager, scope *proxy.CaptureScope, pl *proxy.PassthroughList, tcpHandler tcpForwardHandler) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	var opts []ServerOption
	if scope != nil {
		opts = append(opts, WithCaptureScope(scope))
	}
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

func TestApplyCaptureScope(t *testing.T) {
	tests := []struct {
		name        string
		scope       *proxy.CaptureScope
		input       *captureScopeInput
		wantErr     bool
		wantInclude int
		wantExclude int
	}{
		{
			name:  "nil scope returns error",
			scope: nil,
			input: &captureScopeInput{
				Includes: []scopeRuleInput{{Hostname: "example.com"}},
			},
			wantErr: true,
		},
		{
			name:  "valid includes and excludes",
			scope: proxy.NewCaptureScope(),
			input: &captureScopeInput{
				Includes: []scopeRuleInput{{Hostname: "*.target.com"}},
				Excludes: []scopeRuleInput{{Hostname: "cdn.target.com"}},
			},
			wantInclude: 1,
			wantExclude: 1,
		},
		{
			name:  "empty include rule returns error",
			scope: proxy.NewCaptureScope(),
			input: &captureScopeInput{
				Includes: []scopeRuleInput{{}},
			},
			wantErr: true,
		},
		{
			name:  "empty exclude rule returns error",
			scope: proxy.NewCaptureScope(),
			input: &captureScopeInput{
				Excludes: []scopeRuleInput{{}},
			},
			wantErr: true,
		},
		{
			name:        "empty input sets empty rules",
			scope:       proxy.NewCaptureScope(),
			input:       &captureScopeInput{},
			wantInclude: 0,
			wantExclude: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mkServerFromLegacyDeps(legacyDeps{scope: tt.scope})
			err := s.applyCaptureScope(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("applyCaptureScope() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.scope != nil {
				includes, excludes := tt.scope.Rules()
				if len(includes) != tt.wantInclude {
					t.Errorf("includes = %d, want %d", len(includes), tt.wantInclude)
				}
				if len(excludes) != tt.wantExclude {
					t.Errorf("excludes = %d, want %d", len(excludes), tt.wantExclude)
				}
			}
		})
	}
}

// --- Tests for max_connections, peek_timeout_ms, request_timeout_ms ---

func TestProxyStart_WithMaxConnections(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupProxyStartTestSession(t, manager, nil, nil)

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

	cs := setupProxyStartTestSession(t, manager, nil, nil)

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
	cs := setupProxyStartTestSessionWithOptions(t, manager, nil, nil,
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

			cs := setupProxyStartTestSession(t, manager, nil, nil)

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

			cs := setupProxyStartTestSession(t, manager, nil, nil)

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
			cs := setupProxyStartTestSessionWithOptions(t, manager, nil, nil,
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
	cs := setupProxyStartTestSessionWithOptions(t, manager, nil, nil,
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

	cs := setupProxyStartTestSession(t, manager, nil, nil)

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
func setupProxyStartTestSessionWithOptions(t *testing.T, manager proxyManager, scope *proxy.CaptureScope, pl *proxy.PassthroughList, extraOpts ...ServerOption) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	var opts []ServerOption
	if scope != nil {
		opts = append(opts, WithCaptureScope(scope))
	}
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
		pl       *proxy.PassthroughList
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
			pl:       proxy.NewPassthroughList(),
			patterns: []string{"example.com", "*.googleapis.com"},
			wantLen:  2,
		},
		{
			name:     "empty pattern returns error",
			pl:       proxy.NewPassthroughList(),
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

func TestApplyProxyDefaults_CaptureScope(t *testing.T) {
	scopeJSON := json.RawMessage(`{
		"includes": [{"hostname": "*.target.com"}],
		"excludes": [{"hostname": "cdn.example.com"}]
	}`)
	s := mkServerFromLegacyDeps(legacyDeps{
		proxyDefaults: &config.ProxyConfig{
			CaptureScope: scopeJSON,
		},
	})

	t.Run("uses default when not specified", func(t *testing.T) {
		input := proxyStartInput{}
		s.applyProxyDefaults(&input)
		if input.CaptureScope == nil {
			t.Fatal("CaptureScope is nil, want non-nil")
		}
		if len(input.CaptureScope.Includes) != 1 {
			t.Errorf("CaptureScope.Includes = %d, want 1", len(input.CaptureScope.Includes))
		}
		if input.CaptureScope.Includes[0].Hostname != "*.target.com" {
			t.Errorf("includes[0].hostname = %q, want %q", input.CaptureScope.Includes[0].Hostname, "*.target.com")
		}
	})

	t.Run("caller value takes precedence", func(t *testing.T) {
		callerScope := &captureScopeInput{
			Includes: []scopeRuleInput{{Hostname: "custom.com"}},
		}
		input := proxyStartInput{CaptureScope: callerScope}
		s.applyProxyDefaults(&input)
		if len(input.CaptureScope.Includes) != 1 || input.CaptureScope.Includes[0].Hostname != "custom.com" {
			t.Errorf("CaptureScope should not be overridden by defaults")
		}
	})
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
			CaptureScope:   json.RawMessage(`{invalid`),
			InterceptRules: json.RawMessage(`[{invalid`),
			AutoTransform:  json.RawMessage(`[{invalid`),
		},
	})

	input := proxyStartInput{}
	s.applyProxyDefaults(&input)

	// All fields should remain at zero values.
	if input.CaptureScope != nil {
		t.Error("CaptureScope should be nil for invalid default JSON")
	}
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

	scope := proxy.NewCaptureScope()
	pl := proxy.NewPassthroughList()

	proxyCfg := &config.ProxyConfig{
		ListenAddr:     "127.0.0.1:0",
		TLSPassthrough: []string{"default-pinned.com"},
	}

	ctx := context.Background()
	s := newServer(ctx, nil, nil, manager,
		WithCaptureScope(scope),
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

	scope := proxy.NewCaptureScope()
	pl := proxy.NewPassthroughList()

	proxyCfg := &config.ProxyConfig{
		ListenAddr:     "127.0.0.1:0",
		TLSPassthrough: []string{"default-pinned.com"},
	}

	ctx := context.Background()
	s := newServer(ctx, nil, nil, manager,
		WithCaptureScope(scope),
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

	scope := proxy.NewCaptureScope()
	pl := proxy.NewPassthroughList()

	cs := setupProxyStartTestSessionWithOptions(t, manager, scope, pl)

	// Step 1: Start proxy with capture_scope and tls_passthrough configured.
	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
		"capture_scope": map[string]any{
			"includes": []any{
				map[string]any{"hostname": "example.com"},
			},
		},
		"tls_passthrough": []any{"pinned.example.com"},
	})
	if err != nil {
		t.Fatalf("CallTool (first start): %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error on first start: %v", result.Content)
	}

	// Verify settings were applied.
	if scope.IsEmpty() {
		t.Fatal("expected capture scope to be non-empty after first start")
	}
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

	// Step 3: Restart proxy without capture_scope or tls_passthrough.
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
	if !scope.IsEmpty() {
		t.Error("capture scope should be empty (reset to default) after restart without capture_scope")
	}
	if pl.Len() != 0 {
		t.Errorf("passthrough list length = %d, want 0 (reset to default) after restart without tls_passthrough", pl.Len())
	}
}

// TestProxyStart_ResetsInterceptAndTransformOnRestart verifies that intercept rules
// and auto-transform rules are cleared on proxy_start.
func TestProxyStart_ResetsInterceptAndTransformOnRestart(t *testing.T) {
	manager := newTestProxybuildManager(t)

	scope := proxy.NewCaptureScope()
	pl := proxy.NewPassthroughList()
	httpInterceptEng := httprules.NewInterceptEngine()
	transformPipe := rules.NewPipeline()

	cs := setupProxyStartTestSessionWithOptions(t, manager, scope, pl,
		WithHTTPInterceptEngine(httpInterceptEng),
		WithTransformPipeline(transformPipe),
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
				"id":        "transform-1",
				"enabled":   true,
				"priority":  1,
				"direction": "request",
				"conditions": map[string]any{
					"url_pattern": ".*\\.example\\.com",
				},
				"action": map[string]any{
					"type":   "add_header",
					"header": "X-Test",
					"value":  "1",
				},
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
	if transformPipe.Len() == 0 {
		t.Fatal("expected transform pipeline to have rules after first start")
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
	if transformPipe.Len() != 0 {
		t.Errorf("transform pipeline rule count = %d, want 0 after restart", transformPipe.Len())
	}
}

// TestProxyStart_ResetsLimitsAndTimeoutsOnRestart verifies that connection limits
// and timeouts are reset to defaults when proxy_start omits them.
func TestProxyStart_ResetsLimitsAndTimeoutsOnRestart(t *testing.T) {
	manager := newTestProxybuildManager(t)

	mockTimeout := &mockRequestTimeoutSetter{}

	cs := setupProxyStartTestSessionWithOptions(t, manager, nil, nil,
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
// is reset to "chrome" (default) when proxy_start omits tls_fingerprint.
func TestProxyStart_ResetsTLSFingerprintOnRestart(t *testing.T) {
	manager := newTestProxybuildManager(t)

	mockFP := &mockTLSFingerprintSetter{}

	cs := setupProxyStartTestSessionWithOptions(t, manager, nil, nil,
		WithTLSFingerprintSetter(mockFP),
	)

	// Step 1: Start proxy with custom fingerprint.
	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr":     "127.0.0.1:0",
		"tls_fingerprint": "firefox",
	})
	if err != nil {
		t.Fatalf("CallTool (first start): %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error on first start: %v", result.Content)
	}
	if mockFP.profile != "firefox" {
		t.Errorf("tls_fingerprint after first start = %q, want %q", mockFP.profile, "firefox")
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
	if mockFP.profile != "chrome" {
		t.Errorf("tls_fingerprint after restart = %q, want %q (default)", mockFP.profile, "chrome")
	}
}

// TestProxyStart_ResetsProtocolsOnRestart verifies that enabled protocols
// are reset to all (nil) when proxy_start omits the protocols parameter.
func TestProxyStart_ResetsProtocolsOnRestart(t *testing.T) {
	manager := newTestProxybuildManager(t)

	// Use a Server directly to inspect deps.
	ctx := context.Background()
	scope := proxy.NewCaptureScope()
	s := newServer(ctx, nil, nil, manager, WithCaptureScope(scope))
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{Name: "test", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	// Step 1: Start proxy with specific protocols.
	result, err := callProxyStart(t, cs, map[string]any{
		"listen_addr": "127.0.0.1:0",
		"protocols":   []any{"HTTP/1.x", "HTTPS"},
	})
	if err != nil {
		t.Fatalf("CallTool (first start): %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error on first start: %v", result.Content)
	}
	if len(s.connector.enabledProtocols) != 2 {
		t.Fatalf("enabled protocols count after first start = %d, want 2", len(s.connector.enabledProtocols))
	}

	// Step 2: Stop and restart without protocols.
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

	// Verify protocols were reset to nil (all protocols).
	if s.connector.enabledProtocols != nil {
		t.Errorf("enabled protocols after restart = %v, want nil (all protocols)", s.connector.enabledProtocols)
	}
}
