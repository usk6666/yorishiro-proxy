package mcp

import (
	"strings"
	"testing"
)

// TestDocsTool_ProxyStartListenAddrDocumentsNonLoopback verifies the
// proxy_start help no longer documents listen_addr as loopback-only and
// tells the agent how to bind every interface (explicit wildcard host) and
// what that implies (no client authentication, one Warn at start).
func TestDocsTool_ProxyStartListenAddrDocumentsNonLoopback(t *testing.T) {
	cs := setupResourceTestSession(t)
	body := callDocsOK(t, cs, map[string]any{"topic": "proxy_start"})

	for _, stale := range []string{
		"Must be a loopback address",
		"Only loopback addresses",
	} {
		if strings.Contains(body, stale) {
			t.Errorf("proxy_start docs still contain loopback-only text %q", stale)
		}
	}
	for _, want := range []string{
		"0.0.0.0",
		"[::]",
		"no client authentication",
		"Warn",
		"inherit",
		"binds IPv4 only",
		"dual-stack",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("proxy_start docs missing %q", want)
		}
	}
}

// TestDocsTool_SecurityDocumentsListenerExposure verifies the security help
// carries the listener-exposure note: access control for a non-loopback
// listener is the network side plus the TargetScope Policy.
func TestDocsTool_SecurityDocumentsListenerExposure(t *testing.T) {
	cs := setupResourceTestSession(t)
	body := callDocsOK(t, cs, map[string]any{"topic": "security"})
	if !strings.Contains(body, "## Listener Exposure") {
		t.Fatal("security docs missing the \"## Listener Exposure\" section")
	}
	for _, want := range []string{"binds IPv4 only", "dual-stack"} {
		if !strings.Contains(body, want) {
			t.Errorf("security docs missing %q", want)
		}
	}
}
