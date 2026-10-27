//go:build e2e && !e2e_smoke

package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// tempPluginScript writes content to a fresh .star file in t.TempDir() and
// returns the absolute path. The file name is unique so the engine's
// pluginName helper produces a distinct identifier per script.
func tempPluginScript(t *testing.T, name, content string) string {
	t.Helper()
	if name == "" {
		name = "plugin"
	}
	if filepath.Ext(name) == "" {
		name += ".star"
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// setupIntrospectSession constructs an MCP server with the supplied
// pluginv2 engine, returning a connected client session.
func setupIntrospectSession(t *testing.T, eng *pluginv2.Engine) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	ca := newTestCA(t)
	srv := newServer(ctx, ca, nil, nil, WithPluginv2Engine(eng))
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := srv.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })
	client := gomcp.NewClient(&gomcp.Implementation{Name: "introspect-test", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// callPluginIntrospect calls the plugin_introspect tool and unmarshals the
// JSON content into the result struct.
func callPluginIntrospect(t *testing.T, cs *gomcp.ClientSession) pluginIntrospectResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "plugin_introspect",
	})
	if err != nil {
		t.Fatalf("CallTool plugin_introspect: %v", err)
	}
	if res.IsError {
		t.Fatalf("plugin_introspect returned error: %v", res.Content)
	}
	if len(res.Content) == 0 {
		t.Fatal("empty Content")
	}
	tc, ok := res.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("Content[0] type = %T, want *TextContent", res.Content[0])
	}
	var out pluginIntrospectResult
	if err := json.Unmarshal([]byte(tc.Text), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

// TestPluginIntrospect_NoPlugins verifies the tool returns an empty
// plugin list when the engine has no loaded plugins.
func TestPluginIntrospect_NoPlugins(t *testing.T) {
	eng := pluginv2.NewEngine(nil)
	cs := setupIntrospectSession(t, eng)
	got := callPluginIntrospect(t, cs)
	if len(got.Plugins) != 0 {
		t.Errorf("Plugins len = %d, want 0", len(got.Plugins))
	}
}

// TestPluginIntrospect_NilEngine verifies the tool returns an empty list
// when the pluginv2 engine is unset (e.g. proxy not configured for v2).
func TestPluginIntrospect_NilEngine(t *testing.T) {
	cs := setupIntrospectSession(t, nil)
	got := callPluginIntrospect(t, cs)
	if len(got.Plugins) != 0 {
		t.Errorf("Plugins len = %d, want 0", len(got.Plugins))
	}
}

// TestPluginIntrospect_MultiplePlugins verifies multiple loaded plugins
// surface with their registrations grouped per plugin.
func TestPluginIntrospect_MultiplePlugins(t *testing.T) {
	a := tempPluginScript(t, "alpha", `
def h(ctx, m):
    return None
register_hook("http", "on_request", h, phase="pre_pipeline")
register_hook("http", "on_response", h, phase="post_pipeline")
`)
	b := tempPluginScript(t, "beta", `
def h(ctx, m):
    return None
register_hook("ws", "on_message", h)
register_hook("connection", "on_connect", h)
`)
	eng := pluginv2.NewEngine(nil)
	if err := eng.LoadPlugins(context.Background(), []pluginv2.PluginConfig{
		{Name: "alpha", Path: a, OnError: string(pluginv2.OnErrorAbort)},
		{Name: "beta", Path: b, OnError: string(pluginv2.OnErrorAbort)},
	}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	cs := setupIntrospectSession(t, eng)

	got := callPluginIntrospect(t, cs)
	if len(got.Plugins) != 2 {
		t.Fatalf("Plugins len = %d, want 2", len(got.Plugins))
	}
	if got.Plugins[0].Name != "alpha" || got.Plugins[1].Name != "beta" {
		t.Errorf("plugin order = [%q, %q], want [alpha, beta]", got.Plugins[0].Name, got.Plugins[1].Name)
	}
	if !got.Plugins[0].Enabled || !got.Plugins[1].Enabled {
		t.Error("Enabled = false on a loaded plugin")
	}
	// Two registrations on each.
	if len(got.Plugins[0].Registrations) != 2 {
		t.Errorf("alpha Registrations len = %d, want 2", len(got.Plugins[0].Registrations))
	}
	if len(got.Plugins[1].Registrations) != 2 {
		t.Errorf("beta Registrations len = %d, want 2", len(got.Plugins[1].Registrations))
	}
	// Spot-check the first registration of each plugin.
	r := got.Plugins[0].Registrations[0]
	if r.Protocol != "http" || r.Event != "on_request" || r.Phase != "pre_pipeline" {
		t.Errorf("alpha[0] = %+v, want {http, on_request, pre_pipeline}", r)
	}
	r2 := got.Plugins[1].Registrations[1]
	if r2.Protocol != "connection" || r2.Event != "on_connect" || r2.Phase != "none" {
		t.Errorf("beta[1] = %+v, want {connection, on_connect, none}", r2)
	}
}

// TestPluginIntrospect_RedactKeys verifies that PluginConfig.RedactKeys
// is honoured at the introspect boundary: the listed keys are returned
// as the literal "<redacted>" while siblings pass through.
func TestPluginIntrospect_RedactKeys(t *testing.T) {
	path := tempPluginScript(t, "secrets", `
def h(ctx, m):
    return None
register_hook("http", "on_request", h)
`)
	eng := pluginv2.NewEngine(nil)
	if err := eng.LoadPlugins(context.Background(), []pluginv2.PluginConfig{
		{
			Name:       "secrets",
			Path:       path,
			OnError:    string(pluginv2.OnErrorAbort),
			Vars:       map[string]any{"hmac_key": "supersecret", "log_level": "debug"},
			RedactKeys: []string{"hmac_key"},
		},
	}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	cs := setupIntrospectSession(t, eng)

	got := callPluginIntrospect(t, cs)
	if len(got.Plugins) != 1 {
		t.Fatalf("Plugins len = %d, want 1", len(got.Plugins))
	}
	v := got.Plugins[0].Vars
	if v["hmac_key"] != "<redacted>" {
		t.Errorf("hmac_key = %v, want \"<redacted>\"", v["hmac_key"])
	}
	if v["log_level"] != "debug" {
		t.Errorf("log_level = %v, want \"debug\"", v["log_level"])
	}
}

// TestPluginIntrospect_FailOpen verifies the tool's JSON carries
// fail_open_count (present and 0 before any refusal) and last_fail_open
// after a plugin's RESPOND was refused and treated as CONTINUE.
func TestPluginIntrospect_FailOpen(t *testing.T) {
	path := tempPluginScript(t, "shape", `
def h(msg, ctx):
    return action.RESPOND_GRPC(status=16, message="denied")
register_hook("http", "on_request", h)
`)
	eng := pluginv2.NewEngine(nil)
	if err := eng.LoadPlugins(context.Background(), []pluginv2.PluginConfig{
		{Path: path, OnError: string(pluginv2.OnErrorAbort)},
	}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	cs := setupIntrospectSession(t, eng)

	raw := callPluginIntrospectRaw(t, cs)
	if !strings.Contains(raw, `"fail_open_count":0`) {
		t.Errorf("plugin_introspect before any refusal = %s, want fail_open_count:0 present", raw)
	}
	if strings.Contains(raw, "last_fail_open") {
		t.Errorf("plugin_introspect before any refusal = %s, want no last_fail_open", raw)
	}

	hooks := eng.Registry().Lookup("http", "on_request", pluginv2.PhasePrePipeline)
	if len(hooks) != 1 {
		t.Fatalf("hooks = %d, want 1", len(hooks))
	}
	env := &envelope.Envelope{
		StreamID: "s", FlowID: "f", Direction: envelope.Send, Protocol: envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{Method: "GET", Path: "/", Authority: "example.com"},
	}
	if _, err := eng.Dispatch(context.Background(), hooks[0], env); err == nil {
		t.Fatal("Dispatch err = nil, want the RESPOND_GRPC refused")
	}

	got := callPluginIntrospect(t, cs)
	if len(got.Plugins) != 1 {
		t.Fatalf("Plugins len = %d, want 1", len(got.Plugins))
	}
	p := got.Plugins[0]
	if p.FailOpenCount != 1 {
		t.Errorf("fail_open_count = %d, want 1", p.FailOpenCount)
	}
	if p.LastFailOpen == nil || p.LastFailOpen.Kind != "respond_shape_mismatch" ||
		p.LastFailOpen.Protocol != "http" || p.LastFailOpen.Event != "on_request" ||
		p.LastFailOpen.Phase != "pre_pipeline" || p.LastFailOpen.Action != "RESPOND" {
		t.Errorf("last_fail_open = %+v, want respond_shape_mismatch RESPOND (http, on_request, pre_pipeline)", p.LastFailOpen)
	}
}

// callPluginIntrospectRaw returns the plugin_introspect JSON text verbatim
// so presence of zero-valued fields can be asserted.
func callPluginIntrospectRaw(t *testing.T, cs *gomcp.ClientSession) string {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{Name: "plugin_introspect"})
	if err != nil {
		t.Fatalf("CallTool plugin_introspect: %v", err)
	}
	if res.IsError || len(res.Content) == 0 {
		t.Fatalf("plugin_introspect: isError=%v content=%v", res.IsError, res.Content)
	}
	tc, ok := res.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("Content[0] type = %T, want *TextContent", res.Content[0])
	}
	return tc.Text
}
