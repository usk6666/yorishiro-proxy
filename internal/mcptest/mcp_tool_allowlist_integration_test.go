//go:build e2e && !e2e_smoke

// USK-1120: the -mcp-tools allowlist, exercised over the HTTP MCP transport
// of the production mcpserver.Run wiring.
package mcptest_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

func TestE2E_MCPToolAllowlist_HTTP(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ExtraArgs: []string{"-mcp-tools", "resend_http,fuzz_http,query"},
	})

	got := h.Client.ListTools(t)
	slices.Sort(got)
	if want := []string{"fuzz_http", "query", "resend_http"}; !slices.Equal(got, want) {
		t.Errorf("tools/list = %v, want %v", got, want)
	}

	before := h.MustOK(t, "query", map[string]any{"resource": "status"})
	beforeTimeout, ok := before.Decoded["request_timeout_ms"].(float64)
	if !ok {
		t.Fatalf("query status: request_timeout_ms missing: %s", before.Text)
	}
	newTimeout := beforeTimeout + 4321

	res := h.CallTool(t, "configure", map[string]any{"request_timeout_ms": newTimeout})
	if res.Err == nil || !strings.Contains(res.Err.Error(), `unknown tool "configure"`) {
		t.Errorf("tools/call configure: err = %v isError = %v text = %q, want unknown tool \"configure\"", res.Err, res.IsError, res.Text)
	}

	after := h.MustOK(t, "query", map[string]any{"resource": "status"})
	if got := after.Decoded["request_timeout_ms"]; got != beforeTimeout {
		t.Errorf("request_timeout_ms after the refused configure = %v, want %v unchanged", got, beforeTimeout)
	}
}
