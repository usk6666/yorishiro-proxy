package mcp

import (
	"net/url"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// TestCheckTargetScopeHelpers_HostAliases is USK-1250 test-plan 6: the MCP
// control-plane gates (resend / fuzz / macro / hooks / grpc_schema
// discover) end in the same TargetScope comparison as the data path, so a
// host alias of a denied host is blocked there too.
func TestCheckTargetScopeHelpers_HostAliases(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: "127.0.0.1"}, {Hostname: "localhost"}})

	for _, raw := range []string{
		"http://[::ffff:127.0.0.1]/",
		"http://[::ffff:7f00:1]:8080/x",
		"http://localhost.:80/",
		"http://2130706433/",
		"http://0x7f.0.0.1/",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", raw, err)
		}
		if err := checkTargetScopeURLHelper(scope, u); err == nil {
			t.Errorf("checkTargetScopeURLHelper(%q) = nil, want blocked", raw)
		}
	}

	for _, addr := range []string{
		"localhost.:80",
		"[::ffff:127.0.0.1]:443",
		"localhost.",
		"[::ffff:127.0.0.1]",
		"127.1:80",
	} {
		if err := checkTargetScopeAddrPathHelper(scope, "http", addr, "/"); err == nil {
			t.Errorf("checkTargetScopeAddrPathHelper(%q) = nil, want blocked", addr)
		}
	}

	// Control: an unrelated host is still admitted.
	if err := checkTargetScopeAddrPathHelper(scope, "http", "example.com:80", "/"); err != nil {
		t.Errorf("checkTargetScopeAddrPathHelper(example.com:80) = %v, want nil", err)
	}
}
