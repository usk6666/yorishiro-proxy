//go:build e2e

package mcptest_test

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_Harness_BasicProxyStartAndQuery exercises the harness end to
// end against the production MCP server assembly: boot the server,
// connect a JSON-RPC-over-HTTP client, fire proxy_start, then
// query for status. This is the smoke test specified in USK-724 — if
// it passes, the harness foundation is wired correctly and downstream
// scenario Issues (USK-725/726/727) can build on top.
func TestE2E_Harness_BasicProxyStartAndQuery(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		UpstreamProto: "http/1.1",
	})
	defer h.Cleanup()

	h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	h.MustOK(t, "query", map[string]any{"resource": "status"})
}

// TestE2E_Harness_ExpectError_RejectsUnknownAction asserts that
// ExpectError correctly surfaces a tool-reported error. The intercept
// tool requires an "action" field, so an empty argument map should
// trip the schema-validation path on the server.
func TestE2E_Harness_ExpectError_RejectsUnknownAction(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	defer h.Cleanup()

	// Calling intercept with no params should fail with an error
	// referencing a missing required field. We assert on the generic
	// substring "action" so the test does not over-couple to the
	// tool's error wording.
	h.ExpectError(t, "intercept", map[string]any{}, "action")
}

// TestE2E_Harness_PreStartTools_Fires verifies the PreStartTools hook:
// each tool in the slice runs before StartHarness returns. We assert
// indirectly via query("status") afterwards — the harness must still
// be usable.
func TestE2E_Harness_PreStartTools_Fires(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		PreStartTools: []mcptest.ToolCall{
			{Name: "query", Args: map[string]any{"resource": "status"}},
		},
	})
	defer h.Cleanup()

	// Server must remain healthy after PreStartTools ran.
	h.MustOK(t, "query", map[string]any{"resource": "status"})
}
