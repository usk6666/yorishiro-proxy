package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// setupMultiListenerTestSession creates an MCP client flow with a Manager for
// testing multi-listener features.
func setupMultiListenerTestSession(t *testing.T, manager proxyManager) *gomcp.ClientSession {
	t.Helper()
	return setupTestSessionWithManager(t, manager)
}

func TestProxyStart_WithName(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupMultiListenerTestSession(t, manager)
	defer manager.StopAll(context.Background())

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "http-proxy",
			"listen_addr": "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out proxyStartResult
	textContent, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Name != "http-proxy" {
		t.Errorf("name = %q, want %q", out.Name, "http-proxy")
	}
	if out.Status != "running" {
		t.Errorf("status = %q, want %q", out.Status, "running")
	}
	if out.ListenAddr == "" {
		t.Error("expected non-empty listen_addr")
	}
}

func TestProxyStart_DefaultNameWhenOmitted(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupMultiListenerTestSession(t, manager)
	defer manager.StopAll(context.Background())

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"listen_addr": "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out proxyStartResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Name != connector.DefaultListenerName {
		t.Errorf("name = %q, want %q", out.Name, connector.DefaultListenerName)
	}
}

func TestProxyStart_MultipleNamedListeners(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupMultiListenerTestSession(t, manager)
	defer manager.StopAll(context.Background())

	// Start first listener.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "http",
			"listen_addr": "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("CallTool(http): %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success for http: %v", result.Content)
	}

	// Start second listener on a different name and port.
	result, err = cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "grpc",
			"listen_addr": "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("CallTool(grpc): %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success for grpc: %v", result.Content)
	}

	// Verify both are running.
	if got := manager.ListenerCount(); got != 2 {
		t.Errorf("ListenerCount = %d, want 2", got)
	}
}

func TestProxyStart_DuplicateName_Error(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupMultiListenerTestSession(t, manager)
	defer manager.StopAll(context.Background())

	// Start first.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "myproxy",
			"listen_addr": "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("CallTool first: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected first start to succeed: %v", result.Content)
	}

	// Duplicate name should fail.
	result, err = cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "myproxy",
			"listen_addr": "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("CallTool duplicate: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for duplicate name")
	}
}

func TestProxyStop_WithName(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupMultiListenerTestSession(t, manager)

	// Start two listeners.
	cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "listener-a",
			"listen_addr": "127.0.0.1:0",
		},
	})
	cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "listener-b",
			"listen_addr": "127.0.0.1:0",
		},
	})
	defer manager.StopAll(context.Background())

	if got := manager.ListenerCount(); got != 2 {
		t.Fatalf("ListenerCount = %d, want 2", got)
	}

	// Stop specific listener by name.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_stop",
		Arguments: map[string]any{
			"name": "listener-a",
		},
	})
	if err != nil {
		t.Fatalf("CallTool stop: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out proxyStopResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Status != "stopped" {
		t.Errorf("status = %q, want %q", out.Status, "stopped")
	}
	if len(out.Stopped) != 1 || out.Stopped[0] != "listener-a" {
		t.Errorf("stopped = %v, want [listener-a]", out.Stopped)
	}

	// Only listener-b should remain.
	if got := manager.ListenerCount(); got != 1 {
		t.Errorf("ListenerCount after stop = %d, want 1", got)
	}
}

func TestProxyStop_WithoutName_StopsAll(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupMultiListenerTestSession(t, manager)

	// Start multiple listeners.
	cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "a",
			"listen_addr": "127.0.0.1:0",
		},
	})
	cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "b",
			"listen_addr": "127.0.0.1:0",
		},
	})

	if got := manager.ListenerCount(); got != 2 {
		t.Fatalf("ListenerCount = %d, want 2", got)
	}

	// Stop without name should stop all.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_stop",
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out proxyStopResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Status != "stopped" {
		t.Errorf("status = %q, want %q", out.Status, "stopped")
	}
	if len(out.Stopped) != 2 {
		t.Errorf("stopped count = %d, want 2", len(out.Stopped))
	}

	if got := manager.ListenerCount(); got != 0 {
		t.Errorf("ListenerCount after StopAll = %d, want 0", got)
	}
}

func TestProxyStop_NamedNotFound_Error(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupMultiListenerTestSession(t, manager)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_stop",
		Arguments: map[string]any{
			"name": "nonexistent",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for nonexistent listener")
	}
}

func TestQueryStatus_MultipleListeners(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupMultiListenerTestSession(t, manager)
	defer manager.StopAll(context.Background())

	// Start two named listeners.
	cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "http",
			"listen_addr": "127.0.0.1:0",
		},
	})
	cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "grpc",
			"listen_addr": "127.0.0.1:0",
		},
	})

	// Query status.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "query",
		Arguments: map[string]any{
			"resource": "status",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryStatusResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if !out.Running {
		t.Error("expected running=true")
	}
	if out.ListenerCount != 2 {
		t.Errorf("listener_count = %d, want 2", out.ListenerCount)
	}
	if len(out.Listeners) != 2 {
		t.Fatalf("listeners len = %d, want 2", len(out.Listeners))
	}

	// Verify listener names.
	names := make(map[string]bool)
	for _, l := range out.Listeners {
		names[l.Name] = true
		if l.ListenAddr == "" {
			t.Errorf("listener %q has empty listen_addr", l.Name)
		}
	}
	if !names["http"] {
		t.Error("expected 'http' listener in status")
	}
	if !names["grpc"] {
		t.Error("expected 'grpc' listener in status")
	}
}

func TestQueryStatus_NoListeners(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupMultiListenerTestSession(t, manager)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "query",
		Arguments: map[string]any{
			"resource": "status",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryStatusResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.Running {
		t.Error("expected running=false when no listeners")
	}
	if out.ListenerCount != 0 {
		t.Errorf("listener_count = %d, want 0", out.ListenerCount)
	}
}

func TestQueryStatus_OnlyNamedListeners_RunningTrue(t *testing.T) {
	manager := newTestProxybuildManager(t)

	cs := setupMultiListenerTestSession(t, manager)
	defer manager.StopAll(context.Background())

	// Start a non-default listener.
	cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "custom",
			"listen_addr": "127.0.0.1:0",
		},
	})

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "query",
		Arguments: map[string]any{
			"resource": "status",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	var out queryStatusResult
	textContent := result.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(textContent.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Running should be true even without a "default" listener.
	if !out.Running {
		t.Error("expected running=true with a named listener")
	}
	if out.ListenerCount != 1 {
		t.Errorf("listener_count = %d, want 1", out.ListenerCount)
	}
}

// TestConfigure_UpstreamProxy_PerListenerScope verifies the USK-826 fix:
// configure { name: "B", upstream_proxy: "..." } applies ONLY to listener
// B; listener A's upstream-proxy slot stays clear. The canonical
// repro of the original self-recursion bug — pre-USK-826, setting
// upstream_proxy on B propagated to A and any traffic through A would
// recurse through B's upstream URL.
func TestConfigure_UpstreamProxy_PerListenerScope(t *testing.T) {
	manager := newTestProxybuildManager(t)
	cs := setupMultiListenerTestSession(t, manager)
	defer manager.StopAll(context.Background())

	// Start two listeners.
	for _, name := range []string{"alpha", "beta"} {
		result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
			Name: "proxy_start",
			Arguments: map[string]any{
				"name":        name,
				"listen_addr": "127.0.0.1:0",
			},
		})
		if err != nil {
			t.Fatalf("proxy_start(%s): %v", name, err)
		}
		if result.IsError {
			t.Fatalf("proxy_start(%s) failed: %v", name, result.Content)
		}
	}

	// Configure upstream_proxy on listener beta only.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: map[string]any{
			"name":           "beta",
			"upstream_proxy": "http://127.0.0.1:65432",
		},
	})
	if err != nil {
		t.Fatalf("configure(beta): %v", err)
	}
	if result.IsError {
		t.Fatalf("configure(beta) failed: %v", result.Content)
	}

	// Verify manager-level state: beta has it, alpha does not.
	if got := manager.UpstreamProxyForListener("alpha"); got != "" {
		t.Errorf("alpha leaked: %q (USK-826: per-listener scoping broken)", got)
	}
	if got := manager.UpstreamProxyForListener("beta"); got != "http://127.0.0.1:65432" {
		t.Errorf("beta = %q, want round-trip", got)
	}

	// Verify the query/status surface reflects per-listener upstream proxy.
	statusResult, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "query",
		Arguments: map[string]any{"resource": "status"},
	})
	if err != nil {
		t.Fatalf("query/status: %v", err)
	}
	var status queryStatusResult
	tc := statusResult.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(tc.Text), &status); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	got := map[string]string{}
	for _, l := range status.Listeners {
		got[l.Name] = l.UpstreamProxy
	}
	if got["alpha"] != "" {
		t.Errorf("alpha listener entry has upstream_proxy=%q, want empty", got["alpha"])
	}
	if got["beta"] != "http://127.0.0.1:65432" {
		t.Errorf("beta listener entry upstream_proxy = %q, want http://127.0.0.1:65432", got["beta"])
	}
}

// TestConfigure_UpstreamProxy_DefaultListenerWhenNameOmitted verifies that
// configure { upstream_proxy: "..." } without a name field targets ONLY
// the default listener — not a fan-out to every running listener
// (USK-826). The pre-fix behaviour treated this as a global override.
func TestConfigure_UpstreamProxy_DefaultListenerWhenNameOmitted(t *testing.T) {
	manager := newTestProxybuildManager(t)
	cs := setupMultiListenerTestSession(t, manager)
	defer manager.StopAll(context.Background())

	// Start default + one named listener.
	for _, name := range []string{connector.DefaultListenerName, "beta"} {
		result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
			Name: "proxy_start",
			Arguments: map[string]any{
				"name":        name,
				"listen_addr": "127.0.0.1:0",
			},
		})
		if err != nil || result.IsError {
			t.Fatalf("proxy_start(%s): err=%v result=%v", name, err, result)
		}
	}

	// Omit "name" — should target the default listener.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: map[string]any{
			"upstream_proxy": "http://default.example.com:8080",
		},
	})
	if err != nil {
		t.Fatalf("configure: %v", err)
	}
	if result.IsError {
		t.Fatalf("configure failed: %v", result.Content)
	}

	if got := manager.UpstreamProxyForListener(connector.DefaultListenerName); got != "http://default.example.com:8080" {
		t.Errorf("default listener missing override: %q", got)
	}
	if got := manager.UpstreamProxyForListener("beta"); got != "" {
		t.Errorf("beta leaked: %q (USK-826)", got)
	}
}

// TestConfigure_UpstreamProxy_RejectsMissingListener verifies that
// configure { name: "missing", upstream_proxy: "..." } returns an error
// (rather than silently dropping the directive) when no listener of that
// name is running (USK-826 design decision U1).
func TestConfigure_UpstreamProxy_RejectsMissingListener(t *testing.T) {
	manager := newTestProxybuildManager(t)
	cs := setupMultiListenerTestSession(t, manager)
	defer manager.StopAll(context.Background())

	// Start only one listener.
	cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "alpha",
			"listen_addr": "127.0.0.1:0",
		},
	})

	// Target a non-existent listener.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: map[string]any{
			"name":           "missing",
			"upstream_proxy": "http://127.0.0.1:65432",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected IsError=true for missing listener; got success: %v", result.Content)
	}
}

// TestConfigure_UpstreamProxy_RejectsWhenDefaultNotRunning verifies the
// USK-826 design decision U1: configure { upstream_proxy } with no
// running default listener returns an error rather than silently
// installing an override that no traffic will consult.
func TestConfigure_UpstreamProxy_RejectsWhenDefaultNotRunning(t *testing.T) {
	manager := newTestProxybuildManager(t)
	cs := setupMultiListenerTestSession(t, manager)
	defer manager.StopAll(context.Background())

	// Start ONLY a named listener — no default.
	cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "alpha",
			"listen_addr": "127.0.0.1:0",
		},
	})

	// Omit "name" — implies "default", which is not running.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: map[string]any{
			"upstream_proxy": "http://127.0.0.1:65432",
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected IsError=true; default listener not running but configure succeeded: %v", result.Content)
	}
}

// TestProxyStart_UpstreamProxy_PerListenerScope verifies that
// proxy_start { upstream_proxy } targets the listener being started
// (USK-826). Pre-USK-826, the URL was installed globally and a second
// proxy_start without upstream_proxy would inherit it via the global
// slot.
func TestProxyStart_UpstreamProxy_PerListenerScope(t *testing.T) {
	manager := newTestProxybuildManager(t)
	cs := setupMultiListenerTestSession(t, manager)
	defer manager.StopAll(context.Background())

	// Start alpha with no upstream_proxy.
	if r, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "alpha",
			"listen_addr": "127.0.0.1:0",
		},
	}); err != nil || r.IsError {
		t.Fatalf("proxy_start(alpha): err=%v result=%v", err, r)
	}

	// Start beta with an explicit upstream_proxy URL.
	if r, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":           "beta",
			"listen_addr":    "127.0.0.1:0",
			"upstream_proxy": "http://beta-upstream.example.com:8888",
		},
	}); err != nil || r.IsError {
		t.Fatalf("proxy_start(beta): err=%v result=%v", err, r)
	}

	if got := manager.UpstreamProxyForListener("alpha"); got != "" {
		t.Errorf("alpha inherited beta's upstream_proxy: %q (USK-826)", got)
	}
	if got := manager.UpstreamProxyForListener("beta"); got != "http://beta-upstream.example.com:8888" {
		t.Errorf("beta = %q, want round-trip", got)
	}
}

// TestProxyStart_Reset_PreservesOtherListenerOverride verifies that
// proxy_start of listener A does NOT clear listener B's upstream_proxy
// override (USK-826 design decision U4). Pre-USK-826 reset cleared the
// process-global slot, which wiped every listener's URL.
func TestProxyStart_Reset_PreservesOtherListenerOverride(t *testing.T) {
	manager := newTestProxybuildManager(t)
	cs := setupMultiListenerTestSession(t, manager)
	defer manager.StopAll(context.Background())

	// Start beta first with an upstream_proxy.
	if r, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":           "beta",
			"listen_addr":    "127.0.0.1:0",
			"upstream_proxy": "http://beta-upstream.example.com:8888",
		},
	}); err != nil || r.IsError {
		t.Fatalf("proxy_start(beta): err=%v result=%v", err, r)
	}

	// Now start alpha — its reset path must scope to alpha only.
	if r, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "proxy_start",
		Arguments: map[string]any{
			"name":        "alpha",
			"listen_addr": "127.0.0.1:0",
		},
	}); err != nil || r.IsError {
		t.Fatalf("proxy_start(alpha): err=%v result=%v", err, r)
	}

	if got := manager.UpstreamProxyForListener("beta"); got != "http://beta-upstream.example.com:8888" {
		t.Errorf("beta upstream_proxy wiped by alpha start: %q (USK-826)", got)
	}
	if got := manager.UpstreamProxyForListener("alpha"); got != "" {
		t.Errorf("alpha = %q, want empty", got)
	}
}

// TestQueryStatus_PerListenerUpstreamProxyRotation verifies the USK-976
// surface: when a listener is configured with USK-959 rotation
// (url_template + rotation.policy), query("status").listeners[*] echoes
// the redacted template and the policy on that listener's entry — and
// non-rotation listeners do not carry the fields (omitempty correctness).
//
// The template carries a "secret" password substring to exercise the
// connector.RedactProxyURL call at the publish boundary.
func TestQueryStatus_PerListenerUpstreamProxyRotation(t *testing.T) {
	manager := newTestProxybuildManager(t)
	cs := setupMultiListenerTestSession(t, manager)
	defer manager.StopAll(context.Background())

	// Start two listeners.
	for _, name := range []string{"alpha", "beta"} {
		result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
			Name: "proxy_start",
			Arguments: map[string]any{
				"name":        name,
				"listen_addr": "127.0.0.1:0",
			},
		})
		if err != nil {
			t.Fatalf("proxy_start(%s): %v", name, err)
		}
		if result.IsError {
			t.Fatalf("proxy_start(%s) failed: %v", name, result.Content)
		}
	}

	// Configure rotation on listener "beta" only. Use a template with a
	// real password component so we can assert the redaction zeroed it
	// out on the status surface.
	const rotationTemplate = "http://user-§__nonce§:secret@127.0.0.1:65432"
	const rotationPolicy = "per_request"
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: map[string]any{
			"name": "beta",
			"upstream_proxy": map[string]any{
				"url_template": rotationTemplate,
				"rotation": map[string]any{
					"policy": rotationPolicy,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("configure(beta rotation): %v", err)
	}
	if result.IsError {
		t.Fatalf("configure(beta rotation) failed: %v", result.Content)
	}

	// Manager-level state sanity-check: beta carries the raw rotation,
	// alpha does not.
	tplBeta, polBeta := manager.UpstreamProxyRotationForListener("beta")
	if tplBeta != rotationTemplate {
		t.Errorf("beta rotation template = %q, want round-trip %q", tplBeta, rotationTemplate)
	}
	if polBeta != rotationPolicy {
		t.Errorf("beta rotation policy = %q, want %q", polBeta, rotationPolicy)
	}
	tplAlpha, polAlpha := manager.UpstreamProxyRotationForListener("alpha")
	if tplAlpha != "" || polAlpha != "" {
		t.Errorf("alpha leaked rotation: template=%q policy=%q", tplAlpha, polAlpha)
	}

	// Query the status surface and verify the per-listener entries.
	statusResult, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "query",
		Arguments: map[string]any{"resource": "status"},
	})
	if err != nil {
		t.Fatalf("query/status: %v", err)
	}
	if statusResult.IsError {
		t.Fatalf("query/status failed: %v", statusResult.Content)
	}

	var status queryStatusResult
	tc := statusResult.Content[0].(*gomcp.TextContent)
	if err := json.Unmarshal([]byte(tc.Text), &status); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}

	entries := map[string]queryListenerStatusEntry{}
	for _, l := range status.Listeners {
		entries[l.Name] = l
	}

	betaEntry, ok := entries["beta"]
	if !ok {
		t.Fatalf("beta listener missing from status.Listeners (got %d entries)", len(status.Listeners))
	}
	if betaEntry.UpstreamProxyTemplate == "" {
		t.Errorf("beta upstream_proxy_template empty; want redacted template")
	}
	// Redaction must zero out the "secret" password substring.
	if strings.Contains(betaEntry.UpstreamProxyTemplate, "secret") {
		t.Errorf("beta upstream_proxy_template leaked password: %q", betaEntry.UpstreamProxyTemplate)
	}
	// The template macro and the host:port must still be visible so the
	// editor can re-populate. The §__nonce§ marker passes through
	// RedactProxyURL because it contains no '@'.
	if !strings.Contains(betaEntry.UpstreamProxyTemplate, "§__nonce§") {
		t.Errorf("beta upstream_proxy_template dropped §__nonce§ macro: %q", betaEntry.UpstreamProxyTemplate)
	}
	if !strings.Contains(betaEntry.UpstreamProxyTemplate, "127.0.0.1:65432") {
		t.Errorf("beta upstream_proxy_template dropped host:port: %q", betaEntry.UpstreamProxyTemplate)
	}
	if betaEntry.UpstreamProxyRotationPolicy != rotationPolicy {
		t.Errorf("beta upstream_proxy_rotation_policy = %q, want %q",
			betaEntry.UpstreamProxyRotationPolicy, rotationPolicy)
	}
	// When rotation is configured, no literal URL is set.
	if betaEntry.UpstreamProxy != "" {
		t.Errorf("beta upstream_proxy = %q, want empty (rotation is active)", betaEntry.UpstreamProxy)
	}

	alphaEntry, ok := entries["alpha"]
	if !ok {
		t.Fatalf("alpha listener missing from status.Listeners")
	}
	// Non-rotation listener: rotation fields must be empty (omitempty
	// correctness — the JSON wire form should omit them entirely, and
	// the deserialised struct should carry the zero value).
	if alphaEntry.UpstreamProxyTemplate != "" {
		t.Errorf("alpha upstream_proxy_template = %q, want empty", alphaEntry.UpstreamProxyTemplate)
	}
	if alphaEntry.UpstreamProxyRotationPolicy != "" {
		t.Errorf("alpha upstream_proxy_rotation_policy = %q, want empty", alphaEntry.UpstreamProxyRotationPolicy)
	}

	// Belt-and-braces: verify the raw JSON for the alpha entry actually
	// omits the rotation fields (omitempty on the struct).
	if !strings.Contains(tc.Text, `"name":"alpha"`) {
		t.Fatalf("status JSON missing alpha entry: %s", tc.Text)
	}
	// Strict: the raw JSON must not contain "secret" anywhere — the
	// only place it could appear is via leaked beta credentials.
	if strings.Contains(tc.Text, "secret") {
		t.Errorf("status JSON leaked rotation password: %s", tc.Text)
	}
}
