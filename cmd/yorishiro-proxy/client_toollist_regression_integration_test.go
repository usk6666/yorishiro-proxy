//go:build e2e

package main

// client_toollist_regression_integration_test.go — USK-751 regression test.
//
// USK-693 (PR #688) split the legacy `resend` / `fuzz` MCP tools into
// protocol-typed siblings (resend_http/ws/grpc/raw, fuzz_http/ws/grpc/raw)
// and PR #664 renamed `plugin` to `plugin_introspect`. The CLI client's
// hardcoded clientToolList / clientToolHelp / clientToolDescriptions
// drifted out of sync, leaving stale legacy names that the server no
// longer accepts.
//
// This regression test boots a real MCP server via the production
// mcpserver.Run path, drives tools/list over Streamable HTTP (the wire
// format real CLI clients use), and asserts set equality both
// directions:
//
//   - every server-registered tool must appear in clientToolList
//     (catches "added a new MCP tool but forgot to update the CLI")
//   - every clientToolList entry must be registered on the server
//     (catches "kept a legacy name in clientToolList after server-side
//     removal" — the failure mode this Issue fixed)
//
// Set equality on both directions is the contract the Issue's acceptance
// criterion #4 demands: adding a server tool without updating the
// CLI list — or vice versa — must trip this test.

import (
	"sort"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestRegression_ClientToolList_MatchesServer asserts that the CLI's
// hardcoded clientToolList stays in lockstep with the MCP server's
// registerTools() output. The test boots the production server stack
// via mcptest.StartHarness (mcpserver.Run + Streamable HTTP) and calls
// tools/list, then compares to clientToolList on both directions.
//
// Failure messages name the offending tool(s) so the cause is obvious
// — either a server-side addition without a CLI update, or a stale
// CLI entry after server-side removal.
func TestRegression_ClientToolList_MatchesServer(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	defer h.Cleanup()

	serverNames := h.Client.ListTools(t)

	serverSet := make(map[string]bool, len(serverNames))
	for _, name := range serverNames {
		serverSet[name] = true
	}

	clientSet := make(map[string]bool, len(clientToolList))
	for _, name := range clientToolList {
		clientSet[name] = true
	}

	// Direction 1: server has a tool the client list omits.
	var missingFromClient []string
	for _, name := range serverNames {
		if !clientSet[name] {
			missingFromClient = append(missingFromClient, name)
		}
	}
	sort.Strings(missingFromClient)
	if len(missingFromClient) > 0 {
		t.Errorf("MCP tools registered on server but missing from clientToolList: %v\n"+
			"  Update cmd/yorishiro-proxy/client.go (clientToolList, clientToolDescriptions, clientToolHelp) "+
			"and cmd/yorishiro-proxy/client_params.go (positionalArgMapping) to add the new tool(s).",
			missingFromClient)
	}

	// Direction 2: client list has a tool the server doesn't register.
	var missingFromServer []string
	for _, name := range clientToolList {
		if !serverSet[name] {
			missingFromServer = append(missingFromServer, name)
		}
	}
	sort.Strings(missingFromServer)
	if len(missingFromServer) > 0 {
		t.Errorf("clientToolList contains tools not registered on the server: %v\n"+
			"  Remove the stale entries from cmd/yorishiro-proxy/client.go "+
			"(clientToolList, clientToolDescriptions, clientToolHelp) and "+
			"cmd/yorishiro-proxy/client_params.go (positionalArgMapping).",
			missingFromServer)
	}

	// Sanity: clientToolDescriptions and clientToolHelp must cover every
	// entry in clientToolList. A mismatch here means a partial update —
	// e.g. the list got the new name but the description / help map did
	// not. Catching this locally avoids needing a separate unit test.
	for _, name := range clientToolList {
		if _, ok := clientToolDescriptions[name]; !ok {
			t.Errorf("clientToolList entry %q has no clientToolDescriptions entry", name)
		}
		if _, ok := clientToolHelp[name]; !ok {
			t.Errorf("clientToolList entry %q has no clientToolHelp entry", name)
		}
	}
}
