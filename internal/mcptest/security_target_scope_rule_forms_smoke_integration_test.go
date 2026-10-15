//go:build e2e

// USK-1129 T9: an Agent allow inside a Policy allow that has no hostname
// (any host) must be accepted. Pre-fix, matchTargetRule treated the empty
// hostname as "any host" while the Policy-covers-Agent check treated it as
// covering nothing, so under a Policy allow {"ports":[443]} every
// `security set_target_scope` allow was refused as "outside policy allow
// boundary". Driven end to end: the Policy comes from the production config
// loader (-config), the Agent rule from the MCP wire.
package mcptest_test

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

func TestE2E_USK1129_AgentAllowUnderEmptyHostnamePolicyAllow(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON: `{"target_scope_policy":{"allows":[{"ports":[443]}]}}`,
	})

	h.MustOK(t, "security", map[string]any{
		"action": "set_target_scope",
		"params": map[string]any{
			"allows": []map[string]any{
				{"hostname": "example.com", "ports": []int{443}},
			},
		},
	})

	// The ports subset check still binds: an allow wider than the policy's
	// ports, or on another port, stays refused.
	h.ExpectError(t, "security", map[string]any{
		"action": "set_target_scope",
		"params": map[string]any{
			"allows": []map[string]any{{"hostname": "example.com"}},
		},
	}, "outside policy allow boundary")
	h.ExpectError(t, "security", map[string]any{
		"action": "set_target_scope",
		"params": map[string]any{
			"allows": []map[string]any{{"hostname": "example.com", "ports": []int{80}}},
		},
	}, "outside policy allow boundary")
}
