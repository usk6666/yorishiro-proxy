//go:build e2e

// Package mcptest_test holds USK-754's smoke coverage for pluginv2 hook
// dispatch — proof that a loaded Starlark plugin actually fires on a
// proxied request, not merely that the engine accepted the script.
//
// internal/mcpserver/livewire_pluginv2_integration_test.go covers
// pluginv2 dispatch but is gated as `e2e && !e2e_smoke`. A regression
// in PluginStepPre / PluginStepPost wiring (the same class of bug
// USK-685 caught at boot but USK-671 caught at runtime) would not
// surface in the per-PR merge gate. This file boots the production
// server with a one-line plugin and confirms both:
//
//  1. plugin_introspect surfaces the loaded plugin and its registered
//     ("http","on_request") hook.
//  2. The hook's mutation reaches the upstream — i.e. the dispatch
//     path actually invoked the Starlark callable.
package mcptest_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// pluginScriptHeaderInjector is a one-hook Starlark plugin that
// appends a sentinel header to every HTTP request sent to the
// upstream. It uses the v2 register_hook() API and the
// msg["headers"].append(...) mutation path documented in
// internal/pluginv2/headers.go.
//
// The header value is a fixed sentinel rather than a counter because
// the test only needs proof-of-dispatch, not a ranked frequency
// signal — the upstream observed-server records the header verbatim
// and the test asserts presence.
const pluginScriptHeaderInjector = `
def on_request(msg, ctx):
    msg["headers"].append("X-Plugin-Smoke-Hit", "1")

register_hook("http", "on_request", on_request, phase="pre_pipeline")
`

// TestE2E_PluginDispatch_HeaderInjection proves the production
// pipeline fires (http, on_request) hooks. Without this, a silent
// dispatch failure (e.g. PluginStepPre dropped from the pipeline
// builder) would only surface nightly via livewire_pluginv2.
func TestE2E_PluginDispatch_HeaderInjection(t *testing.T) {
	scriptPath := writePluginScript(t, "smoke_header_injector.star", pluginScriptHeaderInjector)
	cfg := pluginsConfigJSON(t, scriptPath)

	upstreamAddr, upstreamObs := startObservedUpstream(t)

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON: cfg,
	})

	// Sanity-check: the plugin loaded and registered a hook. This
	// catches "config file parsed but engine rejected the script"
	// before the request-side assertion fires.
	assertPluginLoaded(t, h, scriptPath)

	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}

	client := proxyHTTPClient(t, proxyAddr)
	resp := proxiedGet(t, client, fmt.Sprintf("http://%s/plugin-smoke", upstreamAddr))
	if resp.statusCode != http.StatusOK {
		t.Fatalf("proxied GET status = %d, want 200", resp.statusCode)
	}

	if got := upstreamObs.lastHeaderValue("X-Plugin-Smoke-Hit"); got != "1" {
		t.Errorf("upstream X-Plugin-Smoke-Hit = %q, want %q (plugin on_request hook did not fire on the send-direction)", got, "1")
	}
}

// writePluginScript writes the Starlark source to a per-test temp
// directory and returns the absolute path. The file is automatically
// cleaned up by t.TempDir().
func writePluginScript(t *testing.T, name, script string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatalf("write plugin script %s: %v", path, err)
	}
	return path
}

// pluginsConfigJSON builds a minimal harness config that loads a
// single pluginv2 plugin from absolutePath. We marshal via the JSON
// encoder so any path-escaping concerns (Windows backslashes,
// embedded quotes) are handled correctly.
func pluginsConfigJSON(t *testing.T, absolutePath string) string {
	t.Helper()
	cfg := map[string]any{
		"plugins": []map[string]any{
			{
				"name": "smoke_header_injector",
				"path": absolutePath,
			},
		},
	}
	buf, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal plugins config: %v", err)
	}
	return string(buf)
}

// assertPluginLoaded calls plugin_introspect and asserts that exactly
// one plugin is loaded, that its path matches the script we wrote,
// and that it registered the (http, on_request) hook. The intent is
// to fail fast with a clear "plugin never loaded" message before
// downstream dispatch assertions surface a more confusing failure.
func assertPluginLoaded(t *testing.T, h *mcptest.Harness, expectPath string) {
	t.Helper()
	res := h.MustOK(t, "plugin_introspect", map[string]any{})

	pluginsAny, _ := res.Decoded["plugins"].([]any)
	if len(pluginsAny) != 1 {
		t.Fatalf("plugin_introspect: %d plugins loaded, want 1; result=%s", len(pluginsAny), res.Text)
	}
	plugin, _ := pluginsAny[0].(map[string]any)
	if plugin == nil {
		t.Fatalf("plugin_introspect: plugins[0] is not an object: %v", pluginsAny[0])
	}
	if path, _ := plugin["path"].(string); path != expectPath {
		t.Errorf("plugin_introspect: plugins[0].path = %q, want %q", path, expectPath)
	}

	regsAny, _ := plugin["registrations"].([]any)
	if len(regsAny) == 0 {
		t.Fatalf("plugin_introspect: plugins[0].registrations is empty; register_hook did not run")
	}
	found := false
	for _, raw := range regsAny {
		reg, _ := raw.(map[string]any)
		if reg == nil {
			continue
		}
		proto, _ := reg["protocol"].(string)
		event, _ := reg["event"].(string)
		if proto == "http" && event == "on_request" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("plugin_introspect: no (http, on_request) registration found in %v", regsAny)
	}
}
