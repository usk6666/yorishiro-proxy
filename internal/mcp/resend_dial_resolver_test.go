package mcp

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-1264 (U3): the MCP dial resolvers share the forward target's
// default-port join (connector.JoinDefaultPort). An authority whose host
// has colons but is not an IPv6 literal, or whose bracket holds a non-IPv6
// value, is an error before any dial — it was wrapped as
// "[db.internal:5432]:80" and the scope check read the host as
// "db.internal:5432", missing a db.internal deny.
func TestResendDialResolvers_MultiColonAuthority(t *testing.T) {
	bad := []string{"db.internal:5432:80", "db.internal:5432:x", "[db.internal:5432]:80", "[db.internal]:80", "[db.internal]"}
	good := []struct{ in, want string }{
		{"example.com", "example.com:80"},
		{"example.com:8080", "example.com:8080"},
		{"::1", "[::1]:80"},
		{"[::1]", "[::1]:80"},
		{"[::1]:8080", "[::1]:8080"},
	}

	resolvers := map[string]func(string) (string, error){
		"resend_http": func(a string) (string, error) {
			addr, _, _, err := resolveResendHTTPDial(&envelope.HTTPMessage{Scheme: "http", Authority: a}, "")
			return addr, err
		},
		"resend_ws": func(a string) (string, error) {
			addr, _, err := resolveResendWSDialTarget(a, false)
			return addr, err
		},
		"resend_grpc": func(a string) (string, error) {
			addr, _, err := resolveResendGRPCDialTarget(a, false)
			return addr, err
		},
	}
	for name, resolve := range resolvers {
		t.Run(name, func(t *testing.T) {
			for _, a := range bad {
				if addr, err := resolve(a); err == nil {
					t.Errorf("resolve(%q) = %q, nil; want error before dial", a, addr)
				}
			}
			for _, g := range good {
				if addr, err := resolve(g.in); err != nil || addr != g.want {
					t.Errorf("resolve(%q) = %q, %v; want %q", g.in, addr, err, g.want)
				}
			}
		})
	}
}

// override_host must not carry a non-IPv6 bracket either: the override
// leg's scope check would read "db.internal:5432" as the host.
func TestValidateOverrideHost_NonIPv6Bracket(t *testing.T) {
	for _, h := range []string{"[db.internal:5432]:80", "[db.internal]:80"} {
		if err := validateOverrideHost(h); err == nil {
			t.Errorf("validateOverrideHost(%q) = nil, want error", h)
		}
	}
	for _, h := range []string{"[::1]:80", "example.com:8080"} {
		if err := validateOverrideHost(h); err != nil {
			t.Errorf("validateOverrideHost(%q) = %v, want nil", h, err)
		}
	}
}
