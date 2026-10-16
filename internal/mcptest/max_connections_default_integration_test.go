//go:build e2e && !e2e_smoke

package mcptest_test

import (
	"encoding/json"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// USK-1141: the default concurrent-connection cap must be the same value
// whether the operator looks before any listener exists (boot seeds the
// manager from config.Default()) or after a proxy_start that omits
// max_connections (USK-407 reset path). Both paths previously carried their
// own copy of the literal; this test drives the real server boot through the
// JSON-RPC harness so a drift in either copy surfaces here.

// maxConnectionsSnapshot is the subset of query(status) / query(config) read
// by this test. Defined locally because the query tool's result structs are
// unexported.
type maxConnectionsSnapshot struct {
	MaxConnections int `json:"max_connections"`
}

func queryMaxConnections(t *testing.T, h *mcptest.Harness, resource string) int {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{"resource": resource})
	var snap maxConnectionsSnapshot
	if err := json.Unmarshal([]byte(res.Text), &snap); err != nil {
		t.Fatalf("decode query(%s): %v (text=%q)", resource, err, res.Text)
	}
	return snap.MaxConnections
}

func TestE2E_MaxConnections_DefaultBeforeAndAfterProxyStart(t *testing.T) {
	// Literal on purpose: this is the operator-visible default the Issue
	// promises, not a mirror of whatever the constant happens to hold.
	const want = 512

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})

	// Before any listener exists the manager reports the boot-time seed
	// (config.Default().MaxConnections).
	for _, resource := range []string{"status", "config"} {
		if got := queryMaxConnections(t, h, resource); got != want {
			t.Errorf("before proxy_start: query(%s).max_connections = %d, want %d", resource, got, want)
		}
	}

	// proxy_start without max_connections resets to the compile-time default
	// (USK-407) and the running listener reports it.
	h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})

	for _, resource := range []string{"status", "config"} {
		if got := queryMaxConnections(t, h, resource); got != want {
			t.Errorf("after proxy_start: query(%s).max_connections = %d, want %d", resource, got, want)
		}
	}
}
