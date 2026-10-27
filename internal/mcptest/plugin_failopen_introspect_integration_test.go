//go:build e2e && !e2e_smoke

// USK-1395: a plugin RESPOND whose shape does not match its hook (here
// action.RESPOND_GRPC from http.on_request) is refused and treated as
// CONTINUE — the request reaches the upstream. Driven through the
// production wiring (mcpserver.Run + proxybuild): plugin_introspect over
// JSON-RPC must report the fail-open outcome so an agent can notice that a
// "blocking" plugin let the request through.
package mcptest_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

const pluginScriptRespondGRPCOnHTTP = `
def on_request(msg, ctx):
    return action.RESPOND_GRPC(status=7, message="blocked")

register_hook("http", "on_request", on_request, phase="pre_pipeline")
`

func TestE2E_PluginRespondShapeMismatch_ReportedByIntrospect(t *testing.T) {
	scriptPath := writePluginScript(t, "respond_grpc_on_http.star", pluginScriptRespondGRPCOnHTTP)
	upstreamAddr, upstreamObs := startObservedUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: pluginsConfigJSON(t, scriptPath)})
	assertPluginLoaded(t, h, scriptPath)

	if got := introspectFailOpen(t, h); got["fail_open_count"] != float64(0) {
		t.Fatalf("fail_open_count before traffic = %v, want 0 (present)", got["fail_open_count"])
	}

	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}

	client := proxyHTTPClient(t, proxyAddr)
	resp := proxiedGet(t, client, fmt.Sprintf("http://%s/failopen", upstreamAddr))
	if resp.statusCode != http.StatusOK {
		t.Fatalf("proxied GET status = %d, want 200 (the refused RESPOND must fall back to CONTINUE)", resp.statusCode)
	}
	if got := upstreamObs.hitCount(); got != 1 {
		t.Fatalf("upstream hits = %d, want 1 (the request must be forwarded)", got)
	}

	// The hook ran before the request was forwarded, but poll briefly so
	// the assertion does not depend on that ordering.
	var plugin map[string]any
	deadline := time.Now().Add(5 * time.Second)
	for {
		plugin = introspectFailOpen(t, h)
		if plugin["fail_open_count"] == float64(1) || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if plugin["fail_open_count"] != float64(1) {
		t.Fatalf("fail_open_count = %v, want 1; plugin=%v", plugin["fail_open_count"], plugin)
	}
	last, _ := plugin["last_fail_open"].(map[string]any)
	if last == nil {
		t.Fatalf("last_fail_open missing; plugin=%v", plugin)
	}
	want := map[string]string{
		"kind": "respond_shape_mismatch", "action": "RESPOND",
		"protocol": "http", "event": "on_request", "phase": "pre_pipeline",
	}
	for k, v := range want {
		if got, _ := last[k].(string); got != v {
			t.Errorf("last_fail_open.%s = %q, want %q", k, got, v)
		}
	}
	if reason, _ := last["reason"].(string); !strings.Contains(reason, "RESPOND_GRPC") {
		t.Errorf("last_fail_open.reason = %q, want it to name RESPOND_GRPC", reason)
	}
	if at, _ := last["at"].(string); at == "" {
		t.Error("last_fail_open.at is empty")
	}
}

// introspectFailOpen returns the single loaded plugin's plugin_introspect
// object.
func introspectFailOpen(t *testing.T, h *mcptest.Harness) map[string]any {
	t.Helper()
	res := h.MustOK(t, "plugin_introspect", map[string]any{})
	plugins, _ := res.Decoded["plugins"].([]any)
	if len(plugins) != 1 {
		t.Fatalf("plugin_introspect: %d plugins, want 1; result=%s", len(plugins), res.Text)
	}
	p, _ := plugins[0].(map[string]any)
	if p == nil {
		t.Fatalf("plugin_introspect: plugins[0] is not an object: %v", plugins[0])
	}
	return p
}
