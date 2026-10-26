//go:build e2e && !e2e_smoke

// USK-1185: client-side timeouts set by configure survive a proxy_start
// that omits them, and query reports the disabled state as 0.
package mcptest_test

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

func clientTimeoutFields(t *testing.T, h *mcptest.Harness, resource string) (req, idle float64) {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{"resource": resource})
	r, ok := res.Decoded["request_timeout_ms"].(float64)
	if !ok {
		t.Fatalf("query %s: request_timeout_ms missing: %s", resource, res.Text)
	}
	i, ok := res.Decoded["client_idle_timeout_ms"].(float64)
	if !ok {
		t.Fatalf("query %s: client_idle_timeout_ms missing: %s", resource, res.Text)
	}
	return r, i
}

func TestE2E_ClientTimeouts_ConfigureSurvivesProxyStart(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

	h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	for _, resource := range []string{"status", "config"} {
		if req, idle := clientTimeoutFields(t, h, resource); req != 60000 || idle != 120000 {
			t.Errorf("default %s request_timeout_ms=%v client_idle_timeout_ms=%v, want 60000 / 120000", resource, req, idle)
		}
	}

	h.MustOK(t, "configure", map[string]any{"request_timeout_ms": 0, "client_idle_timeout_ms": 5000})
	h.MustOK(t, "proxy_stop", map[string]any{})
	h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})

	for _, resource := range []string{"status", "config"} {
		if req, idle := clientTimeoutFields(t, h, resource); req != 0 || idle != 5000 {
			t.Errorf("%s after configure + restart: request_timeout_ms=%v client_idle_timeout_ms=%v, want 0 / 5000", resource, req, idle)
		}
	}

	h.MustOK(t, "configure", map[string]any{"client_idle_timeout_ms": 0, "request_timeout_ms": 30000})
	for _, resource := range []string{"status", "config"} {
		if req, idle := clientTimeoutFields(t, h, resource); req != 30000 || idle != 0 {
			t.Errorf("%s after re-enable: request_timeout_ms=%v client_idle_timeout_ms=%v, want 30000 / 0", resource, req, idle)
		}
	}
}

// TestE2E_ClientTimeouts_ConfigFileSeedsThenMCPWins is USK-1186 T9: the
// -config file seeds the boot value; an explicit configure / proxy_start
// replaces it and a later proxy_start without the key does not re-apply
// the file.
func TestE2E_ClientTimeouts_ConfigFileSeedsThenMCPWins(t *testing.T) {
	t.Run("configure 0 survives restart", func(t *testing.T) {
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: `{"request_timeout_ms": 300, "client_idle_timeout_ms": 400}`})
		if req, idle := clientTimeoutFields(t, h, "status"); req != 300 || idle != 400 {
			t.Fatalf("status after boot: request_timeout_ms=%v client_idle_timeout_ms=%v, want 300 / 400 (config file)", req, idle)
		}
		h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
		h.MustOK(t, "configure", map[string]any{"request_timeout_ms": 0})
		h.MustOK(t, "proxy_stop", map[string]any{})
		h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
		for _, resource := range []string{"status", "config"} {
			if req, idle := clientTimeoutFields(t, h, resource); req != 0 || idle != 400 {
				t.Errorf("%s after configure 0 + restart: request_timeout_ms=%v client_idle_timeout_ms=%v, want 0 / 400", resource, req, idle)
			}
		}
	})
	t.Run("proxy_start value replaces the file value", func(t *testing.T) {
		h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: `{"request_timeout_ms": 300}`})
		if req, _ := clientTimeoutFields(t, h, "status"); req != 300 {
			t.Fatalf("status after boot: request_timeout_ms=%v, want 300 (config file)", req)
		}
		h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0", "request_timeout_ms": 5000})
		if req, _ := clientTimeoutFields(t, h, "status"); req != 5000 {
			t.Errorf("status after proxy_start 5000: request_timeout_ms=%v, want 5000", req)
		}
	})
}
