//go:build e2e && !e2e_smoke

// USK-1408: plugin_max_body_size replaces the fixed 1 MiB plugin body cap.
// Driven through the production wiring (config JSON → mcpserver init →
// pluginv2.Engine): a response body above the configured cap is never
// handed to an http.on_response hook, one within it still is.
package mcptest_test

import (
	"fmt"
	"net/http"
	"strconv"
	"testing"
)

// pluginScriptResponseStamp stamps every HTTP response it sees with the
// body length it observed, so the client can tell whether the hook ran.
const pluginScriptResponseStamp = `
def on_response(msg, ctx):
    msg["headers"].append("X-Plugin-Saw", str(len(msg["body"])))

register_hook("http", "on_response", on_response, phase="pre_pipeline")
`

func TestE2E_PluginMaxBodySize_GatesHook(t *testing.T) {
	const pluginCap = 2048
	scriptPath := writePluginScript(t, "response_stamp.star", pluginScriptResponseStamp)
	upstream := startSizedUpstream(t)
	h, proxyAddr := startBodyLimitProxy(t, bodyLimitConfigJSON(t, map[string]any{
		"plugin_max_body_size": pluginCap,
		"plugins": []map[string]any{
			{"name": "response_stamp", "path": scriptPath},
		},
	}))

	cfgRes := h.MustOK(t, "query", map[string]any{"resource": "config"})
	if got, _ := cfgRes.Decoded["plugin_max_body_size"].(float64); int64(got) != pluginCap {
		t.Errorf("query config plugin_max_body_size = %v, want %d", cfgRes.Decoded["plugin_max_body_size"], pluginCap)
	}

	client := proxyHTTPClient(t, proxyAddr)
	cases := []struct {
		bodyLen int
		want    string // X-Plugin-Saw; "" = hook not called
	}{
		{bodyLen: 4096, want: ""},
		{bodyLen: 1024, want: strconv.Itoa(1024)},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("body_%d", tc.bodyLen), func(t *testing.T) {
			resp := proxiedGet(t, client, fmt.Sprintf("http://%s/size/%d", upstream, tc.bodyLen))
			if resp.err != nil {
				t.Fatalf("proxied GET: %v", resp.err)
			}
			if resp.statusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.statusCode)
			}
			if len(resp.body) != tc.bodyLen {
				t.Errorf("client received %d bytes, want %d", len(resp.body), tc.bodyLen)
			}
			if got := resp.headers.Get("X-Plugin-Saw"); got != tc.want {
				t.Errorf("X-Plugin-Saw = %q, want %q (plugin cap %d, body %d)", got, tc.want, pluginCap, tc.bodyLen)
			}
		})
	}
}
